"""
Vulnerability checking module for RA137.

Runs **nuclei** against the aggregated IP list (``final_ips.json``).

Improvements over the original:
    * Uses ``final_ips.json`` as the primary IP source
    * Gracefully skips invalid IPs
    * Structured JSON output with metadata
    * Improved logging and error handling
    * Retry / timeout support via ``run_command``

Outputs
-------
* ``vuln_results.json``   – structured results (scan root)
* ``nuclei_results.json`` – nuclei's own JSON export (scan root)
"""

import ipaddress
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from utils.command import run_command
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ai_report import generate_ai_report
from utils.telegram_alert import send_nuclei_results_to_telegram
from utils.paths import build_metadata
from utils.ip_utils import is_valid_ip, load_ips_from_json, sorted_ip_list

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Fallback ports used when network_discovery results are not available
DEFAULT_PORTS = [80, 443, 4443, 7443, 8443, 9443, 10443]


# ---------------------------------------------------------------------------
# IP loading
# ---------------------------------------------------------------------------


def collect_all_ips(output_dir: Path, logger: Logger) -> List[str]:
    """
    Collect IPs from ``final_ips.json`` in the scan directory.

    Returns a sorted list of unique, valid IPs.
    """
    final_ips_file = output_dir / "final_ips.json"

    all_ips: Set[str] = set()

    if final_ips_file.exists():
        final_ips = load_ips_from_json(final_ips_file)
        logger.info(f"Loaded {len(final_ips)} IPs from final_ips.json")
        all_ips.update(final_ips)
    else:
        logger.warning("final_ips.json not found – no IPs available for vulnerability scan")

    return sorted_ip_list(all_ips)


def load_open_ports(output_dir: Path, logger: Logger) -> Dict[str, Set[int]]:
    """
    Load IP-to-open-ports mapping from network_discovery results.

    Reads ``network_results.json`` from the scan root and extracts open ports
    from nmap, Shodan, FOFA, and Censys sources.

    Returns
    -------
    dict[str, set[int]]
        Mapping of IP address -> set of open port numbers.
        Empty dict if no results are available.
    """
    net_json = Path(output_dir) / "network_results.json"
    ip_ports: Dict[str, Set[int]] = {}

    if not net_json.exists():
        logger.info("network_results.json not found – no open port data available")
        return ip_ports

    try:
        with open(net_json, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        logger.warning(f"Failed to read network_results.json: {exc}")
        return ip_ports

    results = data.get("results", {})

    # --- nmap: parse host + port from findings ---
    for entry in results.get("nmap", []):
        host = entry.get("host", "").strip("()")
        port_info = entry.get("port_info", "")
        if not host or not is_valid_ip(host):
            continue
        # Extract port number from lines like "443/tcp  open  ssl/https"
        port_match = re.match(r"(\d+)/(?:tcp|udp)", port_info)
        if port_match:
            port = int(port_match.group(1))
            ip_ports.setdefault(host, set()).add(port)

    # --- Shodan: ports list per IP ---
    for entry in results.get("shodan", []):
        ip = entry.get("ip", "")
        if ip and is_valid_ip(ip):
            ports = entry.get("ports", [])
            if ports:
                ip_ports.setdefault(ip, set()).update(
                    p for p in ports if isinstance(p, int)
                )

    # --- FOFA: ports list per IP ---
    for entry in results.get("fofa", []):
        ip = entry.get("ip", "")
        if ip and is_valid_ip(ip):
            ports = entry.get("ports", [])
            if ports:
                ip_ports.setdefault(ip, set()).update(
                    int(p) for p in ports
                    if isinstance(p, (int, str)) and str(p).isdigit()
                )

    # --- Censys: services with port numbers ---
    for entry in results.get("censys", []):
        ip = entry.get("ip", "")
        if ip and is_valid_ip(ip):
            for svc in entry.get("services", []):
                port = svc.get("port")
                if isinstance(port, int):
                    ip_ports.setdefault(ip, set()).add(port)

    # Summary
    total_ports = sum(len(p) for p in ip_ports.values())
    if ip_ports:
        logger.info(
            f"Loaded {total_ports} open ports across {len(ip_ports)} IPs "
            f"from network discovery"
        )
    else:
        logger.info("No open ports found in network_results.json")

    return ip_ports


# ---------------------------------------------------------------------------
# Target building
# ---------------------------------------------------------------------------

def build_targets(
    ips: List[str],
    ip_ports: Optional[Dict[str, Set[int]]] = None,
) -> Tuple[List[str], str]:
    """Build URL targets from IPs and their open ports.

    If *ip_ports* is provided, each IP is scanned only on its discovered
    open ports.  IPs without discovered ports are skipped.

    If *ip_ports* is ``None`` or empty, falls back to ``DEFAULT_PORTS``.

    Returns
    -------
    (targets, mode) : tuple[list[str], str]
        ``mode`` is ``"discovered"`` or ``"fallback"``.
    """
    targets: Set[str] = set()

    if ip_ports:
        for ip in ips:
            ports = ip_ports.get(ip)
            if not ports:
                continue  # skip IPs with no discovered open ports
            for port in sorted(ports):
                if port == 80:
                    targets.add(f"http://{ip}")
                elif port == 443:
                    targets.add(f"https://{ip}")
                else:
                    targets.add(f"https://{ip}:{port}")
        if targets:
            return sorted(targets), "discovered"

    # Fallback to default ports
    for ip in ips:
        for port in DEFAULT_PORTS:
            if port == 80:
                targets.add(f"http://{ip}")
            elif port == 443:
                targets.add(f"https://{ip}")
            else:
                targets.add(f"https://{ip}:{port}")
    return sorted(targets), "fallback"


def save_targets(targets: List[str], output_dir: Path) -> Path:
    """Write targets to a temp file and return its path."""
    input_file = output_dir / ".nuclei_targets.tmp"
    with open(input_file, "w", encoding="utf-8") as fh:
        for target in targets:
            fh.write(target + "\n")
    return input_file


# ---------------------------------------------------------------------------
# Nuclei runner
# ---------------------------------------------------------------------------

def run_nuclei(input_file: Path, output_dir: Path, logger: Logger) -> Path:
    """Run nuclei scan and return the path to the text output file."""
    output_file = output_dir / ".nuclei_raw.tmp"
    json_file = output_dir / "nuclei_results.json"

    cmd = [
        "nuclei",
        "-l", str(input_file),
        "-silent",
        "-o", str(output_file),
        "-json-export", str(json_file),
    ]

    logger.info("Running nuclei scan")
    config = get_config()
    result = run_command(cmd, timeout=config.timeouts.command_execution)

    if not result.success:
        logger.warning(f"nuclei exited with code {result.returncode}: {result.stderr[:200]}")
    else:
        logger.info("Nuclei scan completed")

    return output_file


# ---------------------------------------------------------------------------
# Result parser
# ---------------------------------------------------------------------------

def parse_nuclei_results(output_file: Path, logger: Logger) -> List[dict]:
    """Parse nuclei text output into structured findings."""
    findings: List[dict] = []
    if not output_file.exists():
        logger.warning(f"Nuclei output not found: {output_file}")
        return findings

    try:
        with open(output_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    findings.append({
                        "raw": line,
                        "template": _extract_template_id(line),
                    })
    except Exception as exc:
        logger.error(f"Failed to parse nuclei results: {exc}")

    return findings


def _extract_template_id(line: str) -> str:
    """Try to extract the nuclei template ID from a result line."""
    # Typical format: [template-id] [severity] [type] matched-at
    match = re.match(r"\[([^\]]+)\]", line)
    return match.group(1) if match else "unknown"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def nuclei_scan(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[dict]:
    """
    Run nuclei vulnerability scan against final_ips.json.

    Parameters
    ----------
    output_dir : Path
        Per-target scan directory (flat structure).
    logger : Logger, optional
        Module logger.
    target : str
        Target domain name.

    Returns
    -------
    list[dict]
        Structured vulnerability findings.
    """
    if logger is None:
        logger = get_logger("VULN")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting vulnerability check")

    # --- collect IPs -----------------------------------------------------
    ips = collect_all_ips(output_dir, logger)
    if not ips:
        logger.warning("No IPs found – skipping vulnerability scan")
        return []

    logger.info(f"Scanning {len(ips)} IPs for vulnerabilities")

    # --- load open ports from network_discovery --------------------------
    ip_ports = load_open_ports(output_dir, logger)

    # --- build targets ---------------------------------------------------
    targets, mode = build_targets(ips, ip_ports if ip_ports else None)
    if mode == "discovered":
        ips_with_ports = sum(1 for ip in ips if ip in ip_ports)
        logger.info(
            f"Built {len(targets)} targets from discovered open ports "
            f"({ips_with_ports}/{len(ips)} IPs have open ports)"
        )
    else:
        logger.info(
            f"Built {len(targets)} targets using fallback port list "
            f"(no open ports from network_discovery)"
        )

    input_file = save_targets(targets, output_dir)

    # --- run nuclei (outputs go to scan root) ----------------------------
    raw_output = run_nuclei(input_file, output_dir, logger)

    # --- parse results ---------------------------------------------------
    findings = parse_nuclei_results(raw_output, logger)

    # --- save structured JSON output with metadata -----------------------
    json_file = output_dir / "vuln_results.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump({
            "metadata": build_metadata("Vulnerability Check", target),
            "total_ips_scanned": len(ips),
            "total_targets": len(targets),
            "total_findings": len(findings),
            "findings": findings,
        }, fh, indent=2)

    # --- cleanup temp files ----------------------------------------------
    for tmp_name in [".nuclei_targets.tmp", ".nuclei_raw.tmp"]:
        tmp_file = output_dir / tmp_name
        if tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass

    # --- AI report -------------------------------------------------------
    report_data = "\n".join(f["raw"] for f in findings)
    generate_ai_report(
        module_name="Nuclei Scan",
        data=report_data,
        target=target,
    )

    # --- Telegram alerts -------------------------------------------------
    nuclei_json = output_dir / "nuclei_results.json"
    if nuclei_json.exists():
        try:
            send_nuclei_results_to_telegram(output_dir)
        except Exception as exc:
            logger.warning(f"Telegram alert failed: {exc}")

    logger.success(
        f"Vulnerability scan: {len(findings)} findings from {len(ips)} IPs → {json_file}"
    )

    return findings
