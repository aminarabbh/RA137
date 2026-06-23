"""
Subdomain enumeration module for RA137.

Uses ``subfinder`` and ``gobuster`` to discover subdomains, then merges
and deduplicates results.
"""

import json
from pathlib import Path
from typing import Set

from utils.command import run_command
from utils.logger import get_logger
from utils.ai_report import generate_ai_report
from utils.paths import build_metadata
from utils.validate import is_safe_command_arg

_log = get_logger("SUBDOMAIN")


def run_subfinder(domain: str, output_dir: Path) -> Set[str]:
    """Run subfinder for passive subdomain enumeration."""
    _log.info(f"Running subfinder on {domain}")

    if not is_safe_command_arg(domain):
        _log.error(f"Unsafe domain rejected: {domain!r}")
        return set()

    temp_file = output_dir / ".subfinder.tmp"

    cmd = ["subfinder", "-silent", "-d", domain]
    run_command(cmd, output_file=temp_file)

    subdomains: Set[str] = set()
    if temp_file.exists():
        with open(temp_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    subdomains.add(line)
        temp_file.unlink()

    _log.info(f"Subfinder found {len(subdomains)} subdomains")
    return subdomains


def run_gobuster(domain: str, wordlist_path: str, output_dir: Path) -> Set[str]:
    """Run gobuster for brute-force DNS enumeration."""
    _log.info(f"Running gobuster on {domain}")

    if not is_safe_command_arg(domain) or not is_safe_command_arg(wordlist_path):
        _log.error(f"Unsafe argument rejected for gobuster")
        return set()

    temp_file = output_dir / ".gobuster.tmp"

    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "--resolver", "8.8.8.8",
        "-w", wordlist_path,
        "-t", "50",
        "--delay", "1s",
        "--quiet",
    ]
    run_command(cmd, output_file=temp_file)

    subdomains: Set[str] = set()
    if temp_file.exists():
        with open(temp_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Skip non-domain lines (e.g. "Found:", banners)
                parts = line.split()
                sub = None
                for part in parts:
                    if "." in part:
                        sub = part
                        break
                if sub:
                    subdomains.add(sub)
        temp_file.unlink()

    _log.info(f"Gobuster found {len(subdomains)} subdomains")
    return subdomains


def save_subdomains(subdomains: Set[str], output_dir: Path, target: str = "") -> None:
    """Write deduplicated, sorted subdomain list to JSON."""
    unique_subdomains = sorted(set(subdomains))
    subdomain_file = output_dir / "subdomains.json"

    payload = {
        "metadata": build_metadata("Subdomain Enumeration", target),
        "total": len(unique_subdomains),
        "subdomains": unique_subdomains,
    }
    with open(subdomain_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    _log.info(f"Saved {len(unique_subdomains)} unique subdomains")


def collect_subdomains(domain: str, wordlist_path: str, output_dir: Path, target: str = "") -> Set[str]:
    """
    Run all subdomain enumeration tools and merge results.

    Parameters
    ----------
    domain : str
        Target domain to enumerate.
    wordlist_path : str
        Path to the gobuster wordlist.
    output_dir : Path
        Per-target output directory.
    target : str
        Original target string (for AI report scoping).
    """
    _log.info("Starting subdomain collection")

    all_subdomains: Set[str] = set()

    subfinder_results = run_subfinder(domain, output_dir)
    all_subdomains.update(subfinder_results)

    gobuster_results = run_gobuster(domain, wordlist_path, output_dir)
    all_subdomains.update(gobuster_results)

    save_subdomains(all_subdomains, output_dir, target=target or domain)

    report_data = "\n".join(sorted(all_subdomains))
    generate_ai_report(
        module_name="Subdomain Enumeration",
        data=report_data,
        target=target or domain,
    )

    _log.info("Subdomain collection completed")
    return all_subdomains
