"""
CDN / Cloud / Hosting detection module for RA137.

Reads the IP list produced by ``ip_extractor`` (``pure_ip.json``), checks
each IP against the auto-maintained CDN range list, categorises them as
CDN / Cloud / Hosting / Direct, and writes structured JSON output.

Outputs
-------
* ``cdn_analysis.json``  – full structured CDN analysis
* ``direct_ips.json``    – non-CDN (direct) IPs for downstream modules
"""

import ipaddress
import json
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.cdn_utils import (
    build_provider_cidr_map,
    check_ip_cdn,
    load_cdn_networks,
    update_cdn_ranges,
)
from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.ai_report import generate_ai_report
from utils.ip_utils import load_ips_from_json
from utils.paths import build_metadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Lazy-init reverse lookup: CIDR-string -> provider name + category
_PROVIDER_MAP: Optional[Dict[str, dict]] = None


def _get_provider_map() -> Dict[str, dict]:
    """Return the global provider map, building it on first use."""
    global _PROVIDER_MAP
    if _PROVIDER_MAP is None:
        _PROVIDER_MAP = build_provider_cidr_map()
    return _PROVIDER_MAP


def _identify_provider(
    matched_cidr: str,
) -> dict:
    """Return ``{provider, category}`` for a matched CIDR."""
    provider_map = _get_provider_map()
    # Exact match first
    if matched_cidr in provider_map:
        return provider_map[matched_cidr]
    # Fuzzy: try to match by normalised network address
    try:
        net = ipaddress.ip_network(matched_cidr, strict=False)
        net_str = str(net)
        if net_str in provider_map:
            return provider_map[net_str]
    except (ValueError, TypeError):
        pass
    return {"provider": "unknown", "category": "unknown"}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def filter_non_cdn_ips(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> Dict[str, list]:
    """
    Analyse IPs against CDN / Cloud / Hosting ranges.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory (contains ``pure_ip.json``).
    logger : Logger, optional
        Module logger (created automatically if omitted).

    Returns
    -------
    dict
        ``{cdn_ips, cloud_ips, hosting_ips, direct_ips}``
    """
    if logger is None:
        logger = get_logger("CDN")

    config = get_config()
    logger.info("Starting CDN / Cloud / Hosting detection")

    # ------------------------------------------------------------------
    # 1. Ensure CDN ranges are available
    # ------------------------------------------------------------------
    cdn_file = config.paths.cdn_file
    if not cdn_file.exists():
        logger.info("CDN file missing – downloading fresh ranges")
        update_cdn_ranges(cdn_file, logger, max_workers=config.concurrency.max_cdn_workers)

    networks = load_cdn_networks(cdn_file, logger, auto_update=True)

    # ------------------------------------------------------------------
    # 2. Load IPs from pure_ip.json
    # ------------------------------------------------------------------
    pure_ip_file = Path(output_dir) / "pure_ip.json"
    if not pure_ip_file.exists():
        logger.warning(f"pure_ip.json not found in {output_dir} – skipping")
        return {"cdn_ips": [], "cloud_ips": [], "hosting_ips": [], "direct_ips": []}

    ips: List[str] = sorted(load_ips_from_json(pure_ip_file))

    if not ips:
        logger.warning("No IPs found in pure_ip.json")
        return {"cdn_ips": [], "cloud_ips": [], "hosting_ips": [], "direct_ips": []}

    logger.info(f"Checking {len(ips)} IPs against {len(networks)} networks")

    # ------------------------------------------------------------------
    # 3. Classify each IP
    # ------------------------------------------------------------------
    results: Dict[str, list] = {
        "cdn_ips": [],
        "cloud_ips": [],
        "hosting_ips": [],
        "direct_ips": [],
    }

    for idx, ip in enumerate(ips, 1):
        logger.progress(idx, len(ips), "CDN check ")

        matched_cidr = check_ip_cdn(ip, networks)

        if matched_cidr:
            info = _identify_provider(matched_cidr)
            entry = {
                "ip": ip,
                "cidr": matched_cidr,
                "provider": info["provider"],
            }
            category = info["category"]
            if category == "cdn":
                results["cdn_ips"].append(entry)
            elif category == "cloud":
                results["cloud_ips"].append(entry)
            else:
                results["hosting_ips"].append(entry)
        else:
            results["direct_ips"].append(ip)

    # ------------------------------------------------------------------
    # 4. Save structured JSON outputs (flat, at scan root)
    # ------------------------------------------------------------------
    metadata = build_metadata("CDN Analysis", target)

    # cdn_analysis.json – full analysis
    cdn_json_file = Path(output_dir) / "cdn_analysis.json"
    cdn_payload = {
        "metadata": metadata,
        "summary": {
            "direct": len(results["direct_ips"]),
            "cdn": len(results["cdn_ips"]),
            "cloud": len(results["cloud_ips"]),
            "hosting": len(results["hosting_ips"]),
        },
        **results,
    }
    with open(cdn_json_file, "w", encoding="utf-8") as fh:
        json.dump(cdn_payload, fh, indent=2)

    # direct_ips.json – non-CDN IPs for downstream modules
    direct_json_file = Path(output_dir) / "direct_ips.json"
    direct_payload = {
        "metadata": metadata,
        "total": len(results["direct_ips"]),
        "ips": sorted(results["direct_ips"]),
    }
    with open(direct_json_file, "w", encoding="utf-8") as fh:
        json.dump(direct_payload, fh, indent=2)

    # ------------------------------------------------------------------
    # 5. Summary
    # ------------------------------------------------------------------
    logger.success(
        f"CDN analysis complete: "
        f"{len(results['direct_ips'])} direct, "
        f"{len(results['cdn_ips'])} CDN, "
        f"{len(results['cloud_ips'])} cloud, "
        f"{len(results['hosting_ips'])} hosting"
    )
    logger.info(f"Structured output → {cdn_json_file}")

    # --- AI report -------------------------------------------------------
    report_lines = []
    for category in ["cdn_ips", "cloud_ips", "hosting_ips"]:
        for entry in results[category]:
            report_lines.append(
                f"{entry['ip']} | {category[:-1]} | {entry['provider']} | {entry['cidr']}"
            )
    for ip in results["direct_ips"]:
        report_lines.append(f"{ip} | direct | - | -")
    generate_ai_report(
        module_name="CDN Analysis",
        data="\n".join(report_lines) if report_lines else "No IPs analyzed.",
        target=target,
    )

    return results
