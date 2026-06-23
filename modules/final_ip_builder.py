"""
Final IP aggregation module for RA137.

Collects ALL discovered IPs from every upstream discovery module,
deduplicates, validates, and writes ``final_ips.json``.

Sources consumed:
    * ``cdn_analysis.json``      – direct (non-CDN) IPs
    * ``realip_results.json``    – origin-IP discovery
    * ``asn_results.json``       – ASN/IP-range recon
    * ``cert_discovery.json``    – certificate-based discovery
    * ``pure_ip.json``           – fallback baseline

Outputs
-------
* ``final_ips.json``  – structured final IP list with metadata
"""

import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ip_utils import (
    is_valid_ip,
    extract_ips_from_text,
    load_ips_from_json,
    sorted_ip_list,
)
from utils.ai_report import generate_ai_report
from utils.paths import build_metadata
from utils.cdn_utils import load_cdn_networks, check_ip_cdn

# Re-export for use within this module
_is_valid_ip = is_valid_ip
_extract_ips_from_text = extract_ips_from_text


# ---------------------------------------------------------------------------
# Source loaders
# ---------------------------------------------------------------------------

def _load_cdn_direct_ips(output_dir: Path, logger: Logger) -> Set[str]:
    """Load direct (non-CDN) IPs from cdn_analysis.json."""
    cdn_json = Path(output_dir) / "cdn_analysis.json"
    ips: Set[str] = set()
    if not cdn_json.exists():
        logger.info("CDN analysis not found – skipping direct IPs")
        return ips
    try:
        with open(cdn_json, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for ip in data.get("direct_ips", []):
            if _is_valid_ip(ip):
                ips.add(ip)
        logger.info(f"CDN direct IPs: {len(ips)}")
    except Exception as exc:
        logger.warning(f"Failed to load CDN analysis: {exc}")
    return ips


def _load_realip_results(output_dir: Path, logger: Logger) -> Set[str]:
    """Load IPs from realip_results.json."""
    json_file = Path(output_dir) / "realip_results.json"
    ips: Set[str] = set()
    if not json_file.exists():
        logger.info("Real IP results not found – skipping")
        return ips
    try:
        with open(json_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Handle both new format (with metadata) and plain list
        results = data.get("results", data) if isinstance(data, dict) else data
        for entry in results:
            if isinstance(entry, dict):
                ip = entry.get("ip", "")
                if _is_valid_ip(ip):
                    ips.add(ip)
        logger.info(f"Real IP discovery IPs: {len(ips)}")
    except Exception as exc:
        logger.warning(f"Failed to load realip results: {exc}")
    return ips


def _load_asn_results(output_dir: Path, logger: Logger) -> tuple:
    """Load matched IPs and CIDR ranges from asn_results.json.

    Returns
    -------
    (ips, cidr_ranges) : tuple[Set[str], Set[str]]
    """
    json_file = Path(output_dir) / "asn_results.json"
    ips: Set[str] = set()
    cidr_ranges: Set[str] = set()
    if not json_file.exists():
        logger.info("ASN results not found – skipping")
        return ips, cidr_ranges
    try:
        with open(json_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for entry in data.get("matches", []):
            value = entry.get("ip", "")
            # CIDR range
            if "/" in value:
                try:
                    net = ipaddress.ip_network(value, strict=False)
                    cidr_ranges.add(str(net))
                except ValueError:
                    pass
            # Individual IP
            elif _is_valid_ip(value):
                ips.add(value)

        # Also load prefixes from asns[] section
        for asn_entry in data.get("asns", []):
            for prefix_str in asn_entry.get("prefixes", []):
                try:
                    net = ipaddress.ip_network(prefix_str, strict=False)
                    cidr_ranges.add(str(net))
                except ValueError:
                    pass

        logger.info(f"ASN recon IPs: {len(ips)}, CIDR ranges: {len(cidr_ranges)}")
    except Exception as exc:
        logger.warning(f"Failed to load ASN results: {exc}")
    return ips, cidr_ranges


def _load_cert_discovery_ips(output_dir: Path, logger: Logger) -> Set[str]:
    """Load IPs from cert_discovery.json."""
    cert_file = Path(output_dir) / "cert_discovery.json"
    ips: Set[str] = set()
    if not cert_file.exists():
        logger.info("cert_discovery.json not found – skipping")
        return ips
    try:
        with open(cert_file, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for match in data.get("matches", []):
            ip = match.get("ip", "")
            if _is_valid_ip(ip):
                ips.add(ip)
        logger.info(f"Certificate discovery IPs: {len(ips)}")
    except Exception as exc:
        logger.warning(f"Failed to load cert discovery: {exc}")
    return ips


def _load_pure_ips(output_dir: Path, logger: Logger) -> Set[str]:
    """Load baseline IPs from pure_ip.json."""
    pure_file = Path(output_dir) / "pure_ip.json"
    ips = load_ips_from_json(pure_file)
    if ips:
        logger.info(f"Baseline pure IPs: {len(ips)}")
    else:
        logger.info("pure_ip.json not found or empty – skipping baseline")
    return ips


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_final_ips(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[str]:
    """
    Aggregate all discovered IPs from every discovery module.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional
        Module logger.

    Returns
    -------
    list[str]
        Sorted, deduplicated list of validated IPs.
    """
    if logger is None:
        logger = get_logger("FINAL-IP")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting final IP aggregation")

    # --- collect from all sources ----------------------------------------
    source_counts: Dict[str, int] = {}

    cdn_ips = _load_cdn_direct_ips(output_dir, logger)
    source_counts["cdn_direct"] = len(cdn_ips)

    realip_ips = _load_realip_results(output_dir, logger)
    source_counts["realip_discovery"] = len(realip_ips)

    asn_ips, asn_cidr_ranges = _load_asn_results(output_dir, logger)
    source_counts["asn_recon"] = len(asn_ips)
    source_counts["asn_recon_cidr"] = len(asn_cidr_ranges)

    cert_ips = _load_cert_discovery_ips(output_dir, logger)
    source_counts["cert_discovery"] = len(cert_ips)

    pure_ips = _load_pure_ips(output_dir, logger)
    source_counts["pure_ip"] = len(pure_ips)

    # --- merge all -------------------------------------------------------
    all_ips = cdn_ips | realip_ips | asn_ips | cert_ips | pure_ips
    all_cidr_ranges = sorted(asn_cidr_ranges)

    logger.info(f"Total unique IPs before validation: {len(all_ips)}")

    # --- fallback: if absolutely nothing, use pure_ip.json ----------------
    if not all_ips:
        logger.warning("No IPs from any discovery module")
        fallback_ips = load_ips_from_json(output_dir / "pure_ip.json")
        if fallback_ips:
            logger.info("Falling back to pure_ip.json")
            all_ips = fallback_ips
            source_counts["fallback_pure_ip"] = len(all_ips)

    if not all_ips:
        logger.warning("No IPs found from any source – final_ips.json will be empty")

    # --- filter out CDN / Cloud / Hosting IPs ----------------------------
    # load_cdn_networks() loads ALL providers (CDN + cloud + hosting from all_cdn.txt)
    cdn_nets = load_cdn_networks(config.paths.cdn_file, logger, auto_update=False)
    if cdn_nets:
        before = len(all_ips)
        all_ips = {ip for ip in all_ips if not check_ip_cdn(ip, cdn_nets)}
        removed = before - len(all_ips)
        if removed:
            logger.info(f"CDN/cloud/hosting filter: removed {removed} IPs from final set")
    else:
        logger.warning("CDN/cloud/hosting networks not loaded – skipping filter")

    # --- validate and sort -----------------------------------------------
    valid_ips: List[str] = []
    for ip in all_ips:
        if _is_valid_ip(ip):
            valid_ips.append(ip)
    
    valid_ips = sorted_ip_list(valid_ips)
    
    # --- expand CIDR ranges into individual IPs --------------------------
    MAX_CIDR_HOSTS = 1024  # /22 = 1022 hosts; skip larger ranges
    expanded_ips: Set[str] = set(valid_ips)

    # If no CIDR ranges found from ASN recon, generate /24 from direct (non-CDN) IPs only
    if not all_cidr_ranges and valid_ips:
        generated_cidrs: Set[str] = set()
        for ip_str in valid_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                # Build /24 network for this IP
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                generated_cidrs.add(str(network))
            except ValueError:
                pass
        if generated_cidrs:
            all_cidr_ranges = sorted(generated_cidrs)
            source_counts["generated_/24"] = len(all_cidr_ranges)
            logger.info(f"No ASN prefixes found – generated {len(all_cidr_ranges)} /24 ranges from direct IPs")

    # --- filter CDN/cloud/hosting CIDR ranges ----------------------------
    if cdn_nets:
        filtered_cidrs = []
        for cidr in all_cidr_ranges:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                # Remove CIDR if network OR broadcast address falls inside a known CDN/cloud/hosting range
                net_ip = str(net.network_address)
                bcast_ip = str(net.broadcast_address)
                if check_ip_cdn(net_ip, cdn_nets) or check_ip_cdn(bcast_ip, cdn_nets):
                    continue
                filtered_cidrs.append(cidr)
            except ValueError:
                filtered_cidrs.append(cidr)
        removed_cidrs = len(all_cidr_ranges) - len(filtered_cidrs)
        if removed_cidrs:
            logger.info(f"CDN/cloud/hosting CIDR filter: removed {removed_cidrs} ranges")
        all_cidr_ranges = filtered_cidrs

    for cidr in all_cidr_ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > MAX_CIDR_HOSTS:
                logger.warning(
                    f"CIDR {cidr} too large ({len(hosts)} hosts) – skipping expansion"
                )
                continue
            for host in hosts:
                expanded_ips.add(str(host))
            logger.info(f"Expanded {cidr} → {len(hosts)} IPs")
        except ValueError:
            logger.warning(f"Invalid CIDR range: {cidr}")
    
    # Re-sort after expansion
    final_ips = sorted_ip_list(list(expanded_ips))

    # --- post-expansion CDN/cloud/hosting filter -------------------------
    if cdn_nets:
        before = len(final_ips)
        final_ips = [ip for ip in final_ips if not check_ip_cdn(ip, cdn_nets)]
        removed = before - len(final_ips)
        if removed:
            logger.info(f"Post-expansion CDN/cloud/hosting filter: removed {removed} IPs")

    logger.info(f"Total IPs after CDN filtering: {len(final_ips)}")
    
    # --- save JSON output (flat, at scan root) ----------------------------
    json_file = Path(output_dir) / "final_ips.json"
    payload = {
        "metadata": build_metadata("Final IP Aggregation", target),
        "total_ips": len(final_ips),
        "total_cidr_ranges": len(all_cidr_ranges),
        "source_counts": source_counts,
        "ips": final_ips,
        "cidr_ranges": all_cidr_ranges,
    }
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        
    logger.success(
        f"Final IP aggregation: {len(final_ips)} unique IPs "
        f"(from {len(all_ips)} direct + {len(all_cidr_ranges)} CIDR ranges expanded) "
        f"→ {json_file}"
    )
    for src, count in source_counts.items():
        if count:
            logger.info(f"  {src}: {count} IPs")

    # --- AI report -------------------------------------------------------
    report_lines = [f"Total IPs: {len(final_ips)}", f"CIDR ranges expanded: {len(all_cidr_ranges)}"]
    for src, count in source_counts.items():
        if count:
            report_lines.append(f"Source {src}: {count}")
    report_lines.append("---")
    report_lines.extend(f"IP: {ip}" for ip in final_ips[:100])
    if len(final_ips) > 100:
        report_lines.append(f"... and {len(final_ips) - 100} more IPs")
    generate_ai_report(
        module_name="Final IP Aggregation",
        data="\n".join(report_lines),
        target=target,
    )

    return final_ips
