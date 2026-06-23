"""
Network discovery module for RA137.

Performs additional network intelligence gathering on ``final_ips.json``:
    * nmap port scanning and service detection
    * Shodan host lookups
    * FOFA queries
    * Censys host enrichment
    * SecurityTrails reverse DNS

Integrations are automatically skipped when API keys or binaries are missing.
Results are merged, deduplicated, and saved as structured JSON.

Outputs
-------
* ``network_results.json`` – structured results with metadata
"""

import ipaddress
import json
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.command import run_command
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.http_session import get_session
from utils.ip_utils import is_valid_ip, sorted_ip_list, load_ips_from_json
from utils.ai_report import generate_ai_report
from utils.paths import build_metadata

_log = get_logger("NETWORK")


# ---------------------------------------------------------------------------
# nmap scanning
# ---------------------------------------------------------------------------

def _run_nmap(ip_file: Path, output_dir: Path, logger: Logger) -> List[dict]:
    """Run nmap scan on IPs from final_ips.json."""
    if not shutil.which("nmap"):
        logger.warning("nmap not found – skipping port scan")
        return []

    nmap_output = output_dir / ".nmap_output.tmp"
    nmap_xml = output_dir / ".nmap_results.xml"

    config = get_config()
    cmd = [
        "nmap",
        "-iL", str(ip_file),
        "-sT", "-Pn", "--open",
        "-sV", "--version-intensity", "3",
        "-oN", str(nmap_output),
        "-oX", str(nmap_xml),
        "--max-retries", "2",
        "-T4",
        f"--host-timeout", f"{config.timeouts.nmap_scan}s",
    ]

    logger.info(f"Running nmap on {ip_file}")
    result = run_command(cmd, timeout=config.timeouts.nmap_scan + 60)

    if not result.success:
        logger.warning(f"nmap exited with code {result.returncode}: {result.stderr[:200]}")

    # Parse basic results from the text output
    findings: List[dict] = []
    if nmap_output.exists():
        try:
            with open(nmap_output, "r", encoding="utf-8") as fh:
                current_host = None
                for line in fh:
                    line = line.strip()
                    if line.startswith("Nmap scan report for"):
                        parts = line.split()
                        current_host = parts[-1]
                    elif line and current_host and ("/tcp" in line or "/udp" in line):
                        findings.append({
                            "host": current_host,
                            "port_info": line,
                            "source": "nmap",
                        })
        except Exception as exc:
            logger.error(f"Failed to parse nmap output: {exc}")

    # Clean up temp nmap files
    for tmp in (nmap_output, nmap_xml):
        if tmp.exists():
            tmp.unlink()

    logger.info(f"nmap found {len(findings)} port/service entries")
    return findings


# ---------------------------------------------------------------------------
# Shodan host lookup
# ---------------------------------------------------------------------------

def _shodan_host(ip: str, logger: Logger) -> Optional[dict]:
    """Look up a single IP on Shodan."""
    config = get_config()
    key = config.api_keys.shodan_api_key
    if not key:
        return None
    try:
        sess = get_session()
        resp = sess.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            timeout=config.timeouts.api_call,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip": ip,
                "ports": data.get("ports", []),
                "os": data.get("os", ""),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "vulns": list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else [],
                "source": "shodan",
            }
    except Exception as exc:
        logger.debug(f"Shodan lookup failed for {ip}: {exc}")
    return None


def _shodan_scan(ips: List[str], logger: Logger) -> List[dict]:
    """Batch Shodan lookups with rate limiting."""
    config = get_config()
    if not config.api_keys.shodan_api_key:
        logger.info("Shodan API key not set – skipping")
        return []

    results: List[dict] = []
    logger.info(f"Querying Shodan for {len(ips)} IPs")

    def _lookup(ip: str) -> Optional[dict]:
        time.sleep(0.3)  # gentle rate limit
        return _shodan_host(ip, logger)

    with ThreadPoolExecutor(max_workers=config.concurrency.max_api_workers) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                info = future.result()
                if info:
                    results.append(info)
            except Exception as exc:
                logger.debug(f"Shodan error: {exc}")

    logger.info(f"Shodan returned data for {len(results)}/{len(ips)} IPs")
    return results


# ---------------------------------------------------------------------------
# FOFA lookup
# ---------------------------------------------------------------------------

def _fofa_query(ip: str, logger: Logger) -> Optional[dict]:
    """Query FOFA for a single IP."""
    config = get_config()
    email = config.api_keys.fofa_email
    key = config.api_keys.fofa_api_key
    if not email or not key:
        return None
    try:
        import base64
        sess = get_session()
        q64 = base64.b64encode(f'ip="{ip}"'.encode()).decode()
        resp = sess.get(
            f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={q64}&size=5&fields=ip,port",
            timeout=config.timeouts.api_call,
        )
        if resp.status_code == 200:
            data = resp.json()
            items = data.get("results", [])
            if items:
                return {
                    "ip": ip,
                    "results_count": len(items),
                    "domains": list({r[0] for r in items if isinstance(r, (list, tuple)) and len(r) > 0}),
                    "ports": list({r[1] for r in items if isinstance(r, (list, tuple)) and len(r) > 1}),
                    "source": "fofa",
                }
    except Exception as exc:
        logger.debug(f"FOFA lookup failed for {ip}: {exc}")
    return None


def _fofa_scan(ips: List[str], logger: Logger) -> List[dict]:
    """Batch FOFA lookups."""
    config = get_config()
    if not config.api_keys.fofa_email or not config.api_keys.fofa_api_key:
        logger.info("FOFA credentials not set – skipping")
        return []

    results: List[dict] = []
    logger.info(f"Querying FOFA for {len(ips)} IPs")

    def _lookup(ip: str) -> Optional[dict]:
        time.sleep(0.5)  # gentle rate limit
        return _fofa_query(ip, logger)

    with ThreadPoolExecutor(max_workers=config.concurrency.max_api_workers) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                info = future.result()
                if info:
                    results.append(info)
            except Exception as exc:
                logger.debug(f"FOFA error: {exc}")

    logger.info(f"FOFA returned data for {len(results)}/{len(ips)} IPs")
    return results


# ---------------------------------------------------------------------------
# Censys host lookup
# ---------------------------------------------------------------------------

def _censys_host(ip: str, logger: Logger) -> Optional[dict]:
    """Look up a single IP on Censys."""
    config = get_config()
    cid_ = config.api_keys.censys_api_id
    csec = config.api_keys.censys_api_secret
    if not cid_ or not csec:
        return None
    try:
        sess = get_session()
        resp = sess.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(cid_, csec),
            timeout=config.timeouts.api_call,
        )
        if resp.status_code == 200:
            data = resp.json().get("result", {})
            services = data.get("services", [])
            return {
                "ip": ip,
                "services": [
                    {
                        "port": s.get("port"),
                        "service": s.get("service_name", ""),
                        "transport": s.get("transport_protocol", ""),
                    }
                    for s in services
                ],
                "os": data.get("operating_system", ""),
                "source": "censys",
            }
    except Exception as exc:
        logger.debug(f"Censys lookup failed for {ip}: {exc}")
    return None


def _censys_scan(ips: List[str], logger: Logger) -> List[dict]:
    """Batch Censys lookups."""
    config = get_config()
    if not config.api_keys.censys_api_id or not config.api_keys.censys_api_secret:
        logger.info("Censys credentials not set – skipping")
        return []

    results: List[dict] = []
    logger.info(f"Querying Censys for {len(ips)} IPs")

    def _lookup(ip: str) -> Optional[dict]:
        time.sleep(0.3)  # gentle rate limit
        return _censys_host(ip, logger)

    with ThreadPoolExecutor(max_workers=config.concurrency.max_api_workers) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        for future in as_completed(futures):
            try:
                info = future.result()
                if info:
                    results.append(info)
            except Exception as exc:
                logger.debug(f"Censys error: {exc}")

    logger.info(f"Censys returned data for {len(results)}/{len(ips)} IPs")
    return results


# ---------------------------------------------------------------------------
# SecurityTrails reverse DNS
# ---------------------------------------------------------------------------

def _securitytrails_reverse(ip: str, logger: Logger) -> Optional[dict]:
    """Reverse DNS lookup via SecurityTrails."""
    config = get_config()
    key = config.api_keys.securitytrails_api_key
    if not key:
        return None
    try:
        sess = get_session()
        resp = sess.get(
            "https://api.securitytrails.com/v1/domain/list",
            params={"filter": f"ipv4={ip}"},
            headers={"APIKEY": key, "Accept": "application/json"},
            timeout=config.timeouts.api_call,
        )
        if resp.status_code == 200:
            data = resp.json()
            records = data.get("records", [])
            if records:
                return {
                    "ip": ip,
                    "domains": [r.get("hostname", "") for r in records if r.get("hostname")],
                    "source": "securitytrails",
                }
    except Exception as exc:
        logger.debug(f"SecurityTrails reverse failed for {ip}: {exc}")
    return None


def _securitytrails_scan(ips: List[str], logger: Logger) -> List[dict]:
    """Batch SecurityTrails reverse lookups."""
    config = get_config()
    if not config.api_keys.securitytrails_api_key:
        logger.info("SecurityTrails API key not set – skipping")
        return []

    results: List[dict] = []
    logger.info(f"Querying SecurityTrails for {len(ips)} IPs")

    # Limit to first 50 IPs to avoid excessive API usage
    limited = ips[:50]
    if len(ips) > 50:
        logger.warning(f"SecurityTrails: limiting to first 50 of {len(ips)} IPs")

    def _lookup(ip: str) -> Optional[dict]:
        time.sleep(0.5)  # gentle rate limit
        return _securitytrails_reverse(ip, logger)

    with ThreadPoolExecutor(max_workers=config.concurrency.max_api_workers) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in limited}
        for future in as_completed(futures):
            try:
                info = future.result()
                if info:
                    results.append(info)
            except Exception as exc:
                logger.debug(f"SecurityTrails error: {exc}")

    logger.info(f"SecurityTrails returned data for {len(results)}/{len(limited)} IPs")
    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def network_discovery(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> Dict:
    """
    Run network intelligence gathering on final_ips.json.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional
        Module logger.

    Returns
    -------
    dict
        Merged and structured network discovery results.
    """
    if logger is None:
        logger = get_logger("NETWORK")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting network discovery")

    # --- load final IPs --------------------------------------------------
    final_ips_json = Path(output_dir) / "final_ips.json"
    if not final_ips_json.exists():
        logger.warning("final_ips.json not found – skipping network discovery")
        return {}

    all_ips = load_ips_from_json(final_ips_json)
    valid_ips = [ip for ip in sorted(all_ips) if is_valid_ip(ip)]

    if not valid_ips:
        logger.warning("No valid IPs found – skipping network discovery")
        return {}

    logger.info(f"Network discovery on {len(valid_ips)} IPs")

    # --- create temp IP file for nmap ------------------------------------
    temp_ip_file = output_dir / ".nmap_ips.tmp"
    with open(temp_ip_file, "w", encoding="utf-8") as fh:
        for ip in valid_ips:
            fh.write(ip + "\n")

    # --- run all integrations --------------------------------------------
    merged: Dict[str, list] = {
        "nmap": [],
        "shodan": [],
        "fofa": [],
        "censys": [],
        "securitytrails": [],
    }

    # nmap
    try:
        merged["nmap"] = _run_nmap(temp_ip_file, output_dir, logger)
    except Exception as exc:
        logger.error(f"nmap integration failed: {exc}")

    # Clean up temp IP file
    if temp_ip_file.exists():
        temp_ip_file.unlink()

    # Shodan
    try:
        merged["shodan"] = _shodan_scan(valid_ips, logger)
    except Exception as exc:
        logger.error(f"Shodan integration failed: {exc}")

    # FOFA
    try:
        merged["fofa"] = _fofa_scan(valid_ips, logger)
    except Exception as exc:
        logger.error(f"FOFA integration failed: {exc}")

    # Censys
    try:
        merged["censys"] = _censys_scan(valid_ips, logger)
    except Exception as exc:
        logger.error(f"Censys integration failed: {exc}")

    # SecurityTrails
    try:
        merged["securitytrails"] = _securitytrails_scan(valid_ips, logger)
    except Exception as exc:
        logger.error(f"SecurityTrails integration failed: {exc}")

    # --- save structured output (flat, at scan root) ----------------------
    summary = {
        "metadata": build_metadata("Network Discovery", target),
        "total_ips_scanned": len(valid_ips),
        "sources": {k: len(v) for k, v in merged.items()},
        "results": merged,
    }

    json_file = output_dir / "network_results.json"
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    # --- log summary -----------------------------------------------------
    total_findings = sum(len(v) for v in merged.values())
    logger.success(f"Network discovery complete: {total_findings} findings → {json_file}")
    for source, count in summary["sources"].items():
        logger.info(f"  {source}: {count} results")

    # --- AI report -------------------------------------------------------
    report_lines = []
    for source_name, source_results in merged.items():
        if source_results:
            report_lines.append(f"## {source_name.upper()}")
            for entry in source_results[:50]:
                if isinstance(entry, dict):
                    if "host" in entry:
                        report_lines.append(f"Host: {entry['host']} - {entry.get('port_info', '')}")
                    elif "ip" in entry:
                        report_lines.append(f"IP: {entry['ip']} - ports: {entry.get('ports', entry.get('services', []))}")
    generate_ai_report(
        module_name="Network Discovery",
        data="\n".join(report_lines) if report_lines else "No network discovery findings.",
        target=target,
    )

    return summary
