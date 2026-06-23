"""
Centralized path and output-folder management for RA137.

Provides helpers to create the standard output directory tree and
per-target scan directories.  Each scan gets a timestamp-based folder
so that interval scheduling never overwrites previous results.
"""

from datetime import datetime
from pathlib import Path
from typing import Dict


def generate_scan_id() -> str:
    """Return a timestamp-based scan identifier (e.g. ``20260618_143000``)."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def create_target_output(
    target: str,
    base_dir: Path = Path("outputs"),
    scan_id: str = "",
) -> Path:
    """
    Create (and return) a per-target, per-scan output directory.

    Strips protocol prefixes and replaces ``/`` with ``_`` so the name
    is safe to use as a directory name.

    Structure::

        outputs/<target>/<scan_id>/
        └── logs/

    If *scan_id* is empty, falls back to a flat per-target directory
    (backward compatibility for single-run mode without scheduling).
    """
    clean = (
        target
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
    )
    target_dir = base_dir / clean
    if scan_id:
        target_dir = target_dir / scan_id
    target_dir.mkdir(parents=True, exist_ok=True)

    # Create logs sub-folder inside the scan directory
    (target_dir / "logs").mkdir(parents=True, exist_ok=True)

    return target_dir


def get_output_paths(target_dir: Path) -> Dict[str, Path]:
    """Return standard output *file* paths for a per-target scan directory."""
    return {
        "subdomains":       target_dir / "subdomains.json",
        "pure_ip":          target_dir / "pure_ip.json",
        "cdn_analysis":     target_dir / "cdn_analysis.json",
        "direct_ips":       target_dir / "direct_ips.json",
        "cert_discovery":   target_dir / "cert_discovery.json",
        "realip_results":   target_dir / "realip_results.json",
        "asn_results":      target_dir / "asn_results.json",
        "final_ips":        target_dir / "final_ips.json",
        "tech_results":     target_dir / "tech_results.json",
        "network_results":  target_dir / "network_results.json",
        "vuln_results":     target_dir / "vuln_results.json",
    }


def build_metadata(module: str, target: str) -> dict:
    """Build a standard metadata block for JSON output files."""
    return {
        "module": module,
        "target": target,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
    }
