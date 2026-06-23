"""
Telegram alert module for RA137.

Sends vulnerability notifications to a Telegram chat.  Findings are batched
into a single message (or a small number of messages) to respect Telegram's
rate limits (~30 messages/sec to the same chat).
"""

import json
import time
from pathlib import Path
from typing import List

from utils.config import get_config
from utils.http_session import get_session
from utils.logger import get_logger

_log = get_logger("TELEGRAM")

# Telegram allows ~30 messages/second per chat.  We stay well under.
_BATCH_SIZE = 20          # findings per message
_INTER_BATCH_DELAY = 1.5  # seconds between batch sends


def _get_telegram_credentials():
    """Load Telegram credentials from config."""
    config = get_config()
    return (
        config.api_keys.telegram_bot_token or "",
        config.api_keys.telegram_chat_id or "",
    )


def _format_vuln(vuln_info: dict) -> str:
    """Format a single vulnerability into a readable text block."""
    severity = vuln_info.get("info", {}).get("severity", "unknown")
    name = vuln_info.get("info", {}).get("name", "unknown")
    template_id = vuln_info.get("template-id", "unknown")
    matched_at = vuln_info.get("matched-at", "N/A")
    curl_command = vuln_info.get("curl-command", "N/A")
    ip = vuln_info.get("ip", "unknown")
    target = vuln_info.get("host", ip)

    return (
        f"IP: {ip} | Target: {target}\n"
        f"Severity: {severity} | {name}\n"
        f"Template: {template_id}\n"
        f"URL: {matched_at}\n"
        f"Curl: {curl_command}"
    )


def _send_message(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a single message to Telegram."""
    sess = get_session()
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = sess.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
        if resp.status_code == 200:
            return True
        _log.warning(f"Telegram API returned {resp.status_code}: {resp.text[:200]}")
    except Exception as exc:
        _log.error(f"Telegram send failed: {exc}")
    return False


def send_nuclei_results_to_telegram(output_dir: Path) -> None:
    """
    Read nuclei JSON results and send batched Telegram alerts.

    Groups findings into batches of ``_BATCH_SIZE`` to stay well within
    Telegram's rate limits.

    Parameters
    ----------
    output_dir : Path
        Directory containing ``nuclei_results.json``.
    """
    json_file = Path(output_dir) / "nuclei_results.json"
    if not json_file.exists():
        _log.info("nuclei_results.json not found – skipping Telegram alerts")
        return

    bot_token, chat_id = _get_telegram_credentials()
    if not bot_token or not chat_id:
        _log.info("Telegram credentials not configured – skipping alerts")
        return

    # Parse all findings
    findings: List[dict] = []
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
        if not content:
            _log.info("nuclei_results.json is empty – nothing to alert")
            return
        # nuclei -json-export produces a JSON array (pretty-printed)
        try:
            data = json.loads(content)
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict):
                # Some nuclei versions wrap results in {"results": [...]}
                findings = data.get("results", [data])
        except json.JSONDecodeError:
            # Fallback: try JSON Lines format (one JSON object per line)
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        _log.error(f"Failed to read nuclei results: {exc}")
        return

    if not findings:
        _log.info("No vulnerability findings to alert")
        return

    # Build batches
    batches = []
    for i in range(0, len(findings), _BATCH_SIZE):
        batch = findings[i:i + _BATCH_SIZE]
        header = (
            f"\U0001f6a8 VULNERABILITY ALERT "
            f"({i + 1}-{min(i + _BATCH_SIZE, len(findings))}/{len(findings)}) "
            f"\U0001f6a8\n"
        )
        body = "\n---\n".join(_format_vuln(v) for v in batch)
        batches.append(header + body)

    _log.info(f"Sending {len(batches)} Telegram alert batch(es) for {len(findings)} findings")

    for idx, message in enumerate(batches):
        if _send_message(bot_token, chat_id, message):
            _log.info(f"  Batch {idx + 1}/{len(batches)} sent")
        if idx < len(batches) - 1:
            time.sleep(_INTER_BATCH_DELAY)

    _log.success(f"Telegram alerts complete: {len(findings)} findings in {len(batches)} message(s)")
