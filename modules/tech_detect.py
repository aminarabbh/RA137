"""
Technology detection module for RA137.

Runs technology fingerprinting against ``final_ips.json`` using:
    * **httpx** – HTTP probing with tech-detect, title, server headers
    * **gow** (gowitness) – full-page screenshots

All results are stored in a single unified output file.

Outputs
-------
* ``tech_results.json``  – structured results with metadata
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.command import run_command
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ai_report import generate_ai_report, ai_validate
from utils.ip_utils import load_ips_from_json
from utils.paths import build_metadata

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
WAF_KEYWORDS = [
    "cloudflare", "akamai", "imperva", "incapsula",
    "sucuri", "f5", "fastly", "aws", "edge",
]

IIS_DEFAULT_KEYWORDS = [
    "iis windows server",
    "welcome to iis",
    "internet information services",
]

OTHER_DEFAULT_KEYWORDS = [
    "apache2 ubuntu default page",
    "nginx welcome",
    "test page",
    "default page",
    "placeholder page",
    "it works",
    "welcome page",
]

PORTS = "80,443,4443,7443,8443,9443,10443"


# ---------------------------------------------------------------------------
# httpx runner
# ---------------------------------------------------------------------------

def _run_httpx(ip_file: Path, output_file: Path, logger: Logger) -> None:
    """Run httpx tech detection against the given IP file."""
    logger.info(f"Running httpx tech detection on {ip_file}")

    cmd = [
        "httpxx",
        "-l", str(ip_file),
        "-ports", PORTS,
        "-title",
        "-server",
        "-tech-detect",
        "-silent",
        "-o", str(output_file),
    ]

    result = run_command(cmd)
    if not result.success:
        logger.warning(f"httpx exited with code {result.returncode}: {result.stderr[:200]}")
    else:
        logger.info("httpx tech detection completed")


# ---------------------------------------------------------------------------
# Result parser (unified – no category splitting)
# ---------------------------------------------------------------------------

def _parse_httpx_results(
    httpx_file: Path,
    logger: Logger,
) -> List[dict]:
    """
    Parse httpx output into a unified list of result dicts.

    Each entry contains the raw line plus any detected tags (WAF, IIS default, etc.).
    """
    results: List[dict] = []

    if not httpx_file.exists():
        logger.warning(f"httpx output not found: {httpx_file}")
        return results

    with open(httpx_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue

            tags: List[str] = []
            lower = line.lower()

            # Detect WAF
            for waf in WAF_KEYWORDS:
                if waf in lower:
                    tags.append(f"waf:{waf}")

            # Detect IIS default pages
            for kw in IIS_DEFAULT_KEYWORDS:
                if kw in lower:
                    tags.append("default:iis")
                    break

            # Detect other default pages
            for kw in OTHER_DEFAULT_KEYWORDS:
                if kw in lower:
                    tags.append("default:other")
                    break

            # Extract URL (first field before brackets)
            url = line.split(" [")[0].split(" ")[0].strip()

            results.append({
                "raw": line,
                "url": url,
                "tags": tags,
            })

    logger.info(f"Parsed {len(results)} httpx results")
    waf_count = sum(1 for r in results if any(t.startswith("waf:") for t in r["tags"]))
    default_count = sum(1 for r in results if any(t.startswith("default:") for t in r["tags"]))
    logger.info(f"  WAF detections: {waf_count}, Default pages: {default_count}")

    return results


# ---------------------------------------------------------------------------
# Technology extraction
# ---------------------------------------------------------------------------

# Regex to extract tech name + optional version from httpx tech-detect output
# Matches patterns like: Nginx:1.18.0, Apache HTTP Server:2.4.58, IIS:10.0, PHP, Ubuntu
_TECH_VERSION_RE = re.compile(
    r"\[([^\]]+)\]\s*$"  # last bracketed group = technology list
)


def _extract_unique_technologies(results: List[dict]) -> List[str]:
    """
    Extract a deduplicated list of technology:version strings from httpx results.

    The last bracketed group in each httpx line contains comma-separated
    technologies, e.g. ``[Nginx:1.18.0,Ubuntu]``.
    """
    techs: Set[str] = set()
    for entry in results:
        raw = entry.get("raw", "")
        m = _TECH_VERSION_RE.search(raw)
        if not m:
            continue
        for part in m.group(1).split(","):
            part = part.strip()
            if part:
                techs.add(part)
    return sorted(techs)


# ---------------------------------------------------------------------------
# AI CVE analysis
# ---------------------------------------------------------------------------

_CVE_PROMPT = """You are a cybersecurity expert. Given the following list of detected web technologies (with versions where available), identify known CVEs and security risks.

For each technology with a known vulnerability:
- Provide the CVE ID (e.g. CVE-2021-23017)
- Severity: critical / high / medium / low
- A one-line description of the vulnerability
- Affected version range

If a technology has no known CVEs, skip it.

Respond ONLY with a valid JSON array. Each element:
{{"technology": "nginx 1.18.0", "cve_id": "CVE-2021-23017", "severity": "high", "description": "Off-by-one in ngx_mp4_module allows DoS", "affected_versions": "< 1.20.1"}}

If no CVEs are found for any technology, respond with an empty JSON array: []

Technologies detected:
{tech_list}"""


def _ai_cve_analysis(
    technologies: List[str],
    logger: Logger,
) -> Optional[List[dict]]:
    """
    Send detected technologies to AI and return known CVEs.

    Returns a list of CVE dicts, or ``None`` if AI is unavailable / fails.
    """
    if not technologies:
        return None

    tech_list_str = "\n".join(f"- {t}" for t in technologies)
    prompt = _CVE_PROMPT.format(tech_list=tech_list_str)

    logger.info(f"Sending {len(technologies)} technologies to AI for CVE analysis")
    response = ai_validate(prompt, temperature=0.2)
    if not response:
        logger.info("AI CVE analysis: no response (AI not configured or failed)")
        return None

    # Parse JSON from AI response (handle markdown code-block wrapping)
    text = response.strip()
    if text.startswith("```"):
        # Strip ```json ... ``` wrapper
        lines = text.splitlines()
        text = "\n".join(
            ln for ln in lines
            if not ln.strip().startswith("```")
        ).strip()

    try:
        cves = json.loads(text)
        if isinstance(cves, list):
            logger.success(f"AI CVE analysis: found {len(cves)} potential vulnerabilities")
            return cves
        else:
            logger.warning("AI CVE analysis: response is not a JSON array")
            return None
    except json.JSONDecodeError as exc:
        logger.warning(f"AI CVE analysis: failed to parse JSON response – {exc}")
        # Store raw response as fallback
        return [{"raw_response": response[:2000]}]


# ---------------------------------------------------------------------------
# gow (gowitness) runner
# ---------------------------------------------------------------------------

def _run_gow(url_file: Path, output_dir: Path, logger: Logger) -> None:
    """Run gowitness screenshot scan on URLs."""
    if not url_file.exists():
        logger.warning("URL file not found for gow – skipping screenshots")
        return

    # Compute relative path from output_dir (gow runs with cwd=output_dir)
    rel_path = url_file.relative_to(output_dir)

    screenshot_dir = Path(output_dir) / "screenshots"
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Running gow screenshot scan on {rel_path}")
    cmd = [
        "gow", "scan", "file",
        "-f", str(rel_path),
        "--screenshot-fullpage",
        "--screenshot-path", str(screenshot_dir),
        "--write-jsonl",
    ]
    result = run_command(cmd, cwd=output_dir)
    if not result.success:
        logger.warning(f"gow exited with code {result.returncode}")
    else:
        logger.info("gow screenshot scan completed")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def tech_detection(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[dict]:
    """
    Run technology detection against final_ips.json.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional
        Module logger.

    Returns
    -------
    list[dict]
        Unified tech detection results.
    """
    if logger is None:
        logger = get_logger("TECH")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting tech detection")

    # --- determine IP file to scan ---------------------------------------
    final_ips_json = Path(output_dir) / "final_ips.json"
    if not final_ips_json.exists():
        logger.warning("final_ips.json not found – skipping tech detection")
        return []

    # httpx needs a plain-text file; create a temp one from the JSON
    ips = load_ips_from_json(final_ips_json)
    if not ips:
        logger.warning("No IPs in final_ips.json – skipping tech detection")
        return []

    temp_ip_file = output_dir / ".tech_ips.tmp"
    with open(temp_ip_file, "w", encoding="utf-8") as fh:
        for ip in sorted(ips):
            fh.write(ip + "\n")

    httpx_raw = output_dir / ".httpx_raw.tmp"

    # --- run httpx --------------------------------------------------------
    _run_httpx(temp_ip_file, httpx_raw, logger)

    # Clean up temp IP file
    if temp_ip_file.exists():
        temp_ip_file.unlink()

    # --- parse results (unified) -----------------------------------------
    results = _parse_httpx_results(httpx_raw, logger)

    # --- run gow screenshots on httpx output (discovered URLs with ports) ---
    gow_url_file = output_dir / ".gow_urls.tmp"
    if results:
        with open(gow_url_file, "w", encoding="utf-8") as fh:
            for r in results:
                url = r.get("url", "")
                if url:
                    fh.write(url + "\n")
        logger.info(f"Generated {len(results)} URLs for gowitness from httpx output")
        _run_gow(gow_url_file, output_dir, logger)
        # Clean up temp gow URL file
        if gow_url_file.exists():
            gow_url_file.unlink()

    # Clean up httpx raw output
    if httpx_raw.exists():
        httpx_raw.unlink()

    # --- AI CVE analysis on detected technologies --------------------------
    cve_results = None
    config = get_config()
    if config.ai.ai_validation:
        unique_techs = _extract_unique_technologies(results)
        if unique_techs:
            logger.info(f"Unique technologies detected: {', '.join(unique_techs[:20])}")
            cve_results = _ai_cve_analysis(unique_techs, logger)
        else:
            logger.info("No technologies detected – skipping AI CVE analysis")
    else:
        logger.info("AI validation disabled – skipping CVE analysis")

    # --- save structured JSON output (flat, at scan root) ---------------
    json_file = output_dir / "tech_results.json"
    payload = {
        "metadata": build_metadata("Tech Detection", target),
        "total_results": len(results),
        "results": results,
    }
    if cve_results is not None:
        payload["unique_technologies"] = unique_techs
        payload["cve_analysis"] = cve_results
        payload["total_cves"] = len(cve_results)
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    # --- AI report -------------------------------------------------------
    report_lines = [r["raw"] for r in results]
    if cve_results:
        report_lines.append("\n--- CVE Analysis ---")
        for cve in cve_results:
            if "cve_id" in cve:
                report_lines.append(
                    f"{cve.get('cve_id', '?')} [{cve.get('severity', '?')}] "
                    f"{cve.get('technology', '?')}: {cve.get('description', '')}"
                )
    generate_ai_report(
        module_name="Tech Detection",
        data="\n".join(report_lines) if report_lines else "No tech detection results.",
        target=target,
    )

    cve_msg = f", {len(cve_results)} CVEs" if cve_results else ""
    logger.success(f"Tech detection: {len(results)} results{cve_msg} → {json_file}")
    return results
