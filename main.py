"""
RA137 Reconnaissance Framework – Main execution entry point.

Execution flow:
    1. Subdomain enumeration        (subdomain_enum)
    2. IP extraction                (ip_extractor)
    3. CDN / Cloud / Hosting detect (check_cdn)
    4. Certificate discovery        (cert_discovery)
    5. Real IP discovery            (realip_discovery)
    6. ASN / IP-range recon       (asn_recon)
    7. Final IP aggregation         (final_ip_builder)
    8. Technology detection         (tech_detect)
    9. Network discovery            (network_discovery)
   10. Vulnerability checking       (vuln_check)
"""

import argparse
import json
import os
import re
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Optional, Set

from utils.logger import Logger, get_logger, set_default_log_file
from utils.database import init_db
from utils.paths import create_target_output, generate_scan_id
from utils.config import get_config
from utils.ai_report import generate_pdf_report
from utils.validate import validate_domain

from modules.subdomain_enum import collect_subdomains
from modules.ip_extractor import collect_ips
from modules.cert_discovery import cert_discovery
from modules.check_cdn import filter_non_cdn_ips
from modules.realip_discovery import real_ip_discovery
from modules.asn_recon import asn_recon
from modules.final_ip_builder import build_final_ips
from modules.tech_detect import tech_detection
from modules.network_discovery import network_discovery
from modules.vuln_check import nuclei_scan


# ---------------------------------------------------------------------------
# Execution steps – ordered
# ---------------------------------------------------------------------------
STEPS = [
    "subdomain_enum",
    "ip_extractor",
    "check_cdn",
    "cert_discovery",
    "realip_discovery",
    "asn_recon",
    "final_ip_builder",
    "tech_detection",
    "network_discovery",
    "vuln_check",
]


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event = threading.Event()


def _signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    _shutdown_event.set()
    logger = get_logger("MAIN")
    logger.warning("Shutdown signal received – finishing current step and exiting...")


signal.signal(signal.SIGINT, _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="RA137 Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--interval",
        type=str,
        default=None,
        help="Scan interval (e.g. 6h, 30m, 1d). Omit for single run.",
    )
    parser.add_argument(
        "--agent",
        type=str,
        default=None,
        metavar="TARGET",
        help="Run as AI agent for a single target (e.g. --agent example.com).",
    )
    return parser.parse_args()


def _parse_interval(value: str) -> int:
    """Parse a human-friendly interval string into seconds.

    Supported suffixes: ``s`` (seconds), ``m`` (minutes), ``h`` (hours),
    ``d`` (days).  Bare integers are treated as seconds.

    Raises ``ValueError`` on invalid input.
    """
    value = value.strip().lower()
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([smhd]?)$", value)
    if not match:
        raise ValueError(f"Invalid interval format: {value!r} (expected e.g. 6h, 30m, 1d)")
    amount = float(match.group(1))
    suffix = match.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return int(amount * multipliers[suffix])


# ---------------------------------------------------------------------------
# JSON-based step state tracker (per-scan directory)
# ---------------------------------------------------------------------------

def _state_file_path(target: str, scan_id: str) -> Path:
    """Return the path to the step-completion state file for a scan."""
    config = get_config()
    return config.paths.output_base / target / scan_id / ".step_state.json"


def _load_state(state_path: Path) -> Dict[str, Dict[str, str]]:
    """
    Load step-completion state from JSON file.

    Structure: ``{step: status}`` where status is "done" or "failed".
    """
    if state_path.exists():
        try:
            with open(state_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_state(state: Dict, state_path: Path) -> None:
    """Persist step-completion state to JSON file."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)


def _step_completed(state: Dict, step: str, scan_dir: Path) -> bool:
    """Check whether a step has been successfully completed.

    Also validates that the scan output directory still exists.
    If the output was deleted, the cached state is invalidated.
    """
    if state.get(step) != "done":
        return False

    # Verify the scan output directory still exists
    if not scan_dir.exists():
        state.clear()
        return False

    return True


def _mark_step(state: Dict, step: str, status: str, state_path: Path) -> None:
    """Mark a step's status ('done' or 'failed')."""
    state[step] = status
    _save_state(state, state_path)


# ---------------------------------------------------------------------------
# Target loading
# ---------------------------------------------------------------------------

def load_targets(logger: Logger) -> list:
    """Load and validate targets from the configured targets file."""
    config = get_config()
    targets_file = config.paths.targets_file

    if not targets_file.exists():
        logger.error(f"Targets file not found: {targets_file}")
        return []

    with open(targets_file, "r", encoding="utf-8") as fh:
        raw_targets = [line.strip() for line in fh if line.strip()]

    # Validate each target
    valid_targets = []
    for raw in raw_targets:
        domain = validate_domain(raw)
        if domain:
            valid_targets.append(domain)
        else:
            logger.error(f"Invalid target rejected: {raw!r}")

    return valid_targets


# ---------------------------------------------------------------------------
# Per-step runners
# ---------------------------------------------------------------------------

def _run_subdomain_enum(target: str, target_output: Path, logger: Logger) -> None:
    collect_subdomains(domain=target, wordlist_path="wordlists/subdomains.txt", output_dir=target_output, target=target)


def _run_ip_extractor(target: str, target_output: Path, logger: Logger) -> None:
    collect_ips(output_dir=target_output, target=target)


def _run_check_cdn(target: str, target_output: Path, logger: Logger) -> None:
    filter_non_cdn_ips(output_dir=target_output, logger=logger, target=target)


def _run_cert_discovery(target: str, target_output: Path, logger: Logger) -> None:
    cert_discovery(target=target, output_dir=target_output)


def _run_realip_discovery(target: str, target_output: Path, logger: Logger) -> None:
    real_ip_discovery(output_dir=target_output, logger=logger, target=target)


def _run_asn_recon(target: str, target_output: Path, logger: Logger) -> None:
    asn_recon(output_dir=target_output, target=target, logger=logger)


def _run_final_ip_builder(target: str, target_output: Path, logger: Logger) -> None:
    build_final_ips(output_dir=target_output, logger=logger, target=target)


def _run_tech_detection(target: str, target_output: Path, logger: Logger) -> None:
    tech_detection(output_dir=target_output, logger=logger, target=target)


def _run_network_discovery(target: str, target_output: Path, logger: Logger) -> None:
    network_discovery(output_dir=target_output, logger=logger, target=target)


def _run_vuln_check(target: str, target_output: Path, logger: Logger) -> None:
    nuclei_scan(output_dir=target_output, logger=logger, target=target)


# ---------------------------------------------------------------------------
# Step dispatcher
# ---------------------------------------------------------------------------

_STEP_RUNNERS = {
    "subdomain_enum":    _run_subdomain_enum,
    "ip_extractor":      _run_ip_extractor,
    "check_cdn":         _run_check_cdn,
    "cert_discovery":    _run_cert_discovery,
    "realip_discovery":  _run_realip_discovery,
    "asn_recon":         _run_asn_recon,
    "final_ip_builder":  _run_final_ip_builder,
    "tech_detection":    _run_tech_detection,
    "network_discovery": _run_network_discovery,
    "vuln_check":        _run_vuln_check,
}


# ---------------------------------------------------------------------------
# Per-target processor
# ---------------------------------------------------------------------------

def _process_target(
    idx: int,
    target: str,
    total: int,
    config,
    scan_id: str,
) -> bool:
    """Process a single target through the full pipeline.

    Creates a per-scan directory and manages step state independently.
    """
    target_output = create_target_output(target, config.paths.output_base, scan_id)

    # Per-scan step state
    state_path = _state_file_path(target, scan_id)
    state = _load_state(state_path)

    # Create per-target log file and switch the global default
    target_log_dir = target_output / "logs"
    target_log_dir.mkdir(parents=True, exist_ok=True)
    target_log_file = target_log_dir / "target.log"

    # Each thread gets its own logger pointing to the per-target log file
    target_logger = get_logger("MAIN", log_file=target_log_file)
    # Also set the global default for modules that create loggers internally
    set_default_log_file(target_log_file)

    target_logger.info(f"\n{'#' * 60}")
    target_logger.info(f"Target {idx}/{total}: {target}  [scan: {scan_id}]")
    target_logger.info(f"{'#' * 60}")

    for step in STEPS:
        if _shutdown_event.is_set():
            target_logger.warning("Shutdown requested – stopping step execution")
            break

        completed = _step_completed(state, step, target_output)

        if completed:
            target_logger.info(f"Skipping {step} (already done)")
            continue

        runner = _STEP_RUNNERS.get(step)
        if runner is None:
            target_logger.error(f"Unknown step: {step}")
            continue

        target_logger.info(f"{'=' * 60}")
        target_logger.info(f"Running step: {step}")
        target_logger.info(f"{'=' * 60}")

        try:
            runner(target, target_output, target_logger)
            _mark_step(state, step, "done", state_path)
            target_logger.success(f"Step '{step}' completed")
        except Exception as exc:
            target_logger.error(f"Step '{step}' failed: {exc}")
            _mark_step(state, step, "failed", state_path)
            target_logger.warning(f"Continuing despite failure in {step}")

    # --- generate PDF report from AI reports --------------------------
    if not _shutdown_event.is_set():
        try:
            generate_pdf_report(target, target_output)
        except Exception as exc:
            target_logger.warning(f"PDF report generation skipped: {exc}")

    target_logger.success(f"Finished target: {target}")
    return True


# ---------------------------------------------------------------------------
# Scan cycle (processes all targets in one scan_id)
# ---------------------------------------------------------------------------

def _run_scan_cycle(targets: list, config, scan_id: str, logger: Logger) -> None:
    """Run one complete scan cycle across all targets."""
    logger.info(f"Scan cycle [{scan_id}] – processing {len(targets)} target(s)")

    # --- parallelism setting (env: PARALLEL_TARGETS, default=1) ---------
    parallel_targets = int(os.environ.get("PARALLEL_TARGETS", "1"))
    if parallel_targets < 1:
        parallel_targets = 1

    logger.info(f"Processing {len(targets)} target(s) with {parallel_targets} worker(s)")

    # --- process targets -------------------------------------------------
    if parallel_targets == 1:
        # Sequential mode (default)
        for idx, target in enumerate(targets, 1):
            if _shutdown_event.is_set():
                logger.warning("Shutdown requested – skipping remaining targets")
                break
            _process_target(idx, target, len(targets), config, scan_id)
    else:
        # Parallel mode
        with ThreadPoolExecutor(max_workers=parallel_targets) as pool:
            futures = {
                pool.submit(
                    _process_target, idx, target, len(targets), config, scan_id
                ): target
                for idx, target in enumerate(targets, 1)
            }
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    logger.error(f"Target '{target}' failed: {exc}")

    # Reset global log file back to default after all targets
    set_default_log_file(config.paths.log_file)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run the full reconnaissance pipeline for all targets."""
    args = parse_args()

    config = get_config()

    # --- AI Agent mode ---------------------------------------------------
    if args.agent:
        from agent import run_agent
        from utils.database import init_db as _init_db
        _init_db()
        config.paths.output_base.mkdir(parents=True, exist_ok=True)
        run_agent(args.agent)
        return

    logger = get_logger("MAIN")

    logger.info("=" * 60)
    logger.info("RA137 Reconnaissance Framework – Starting")
    logger.info("=" * 60)

    # --- initialise database and output base directory ---------------------
    init_db()
    logger.info("Database initialized")

    config.paths.output_base.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output base ready: {config.paths.output_base}")

    # --- load targets -----------------------------------------------------
    targets = load_targets(logger)
    if not targets:
        logger.error("No valid targets found – exiting")
        return

    logger.info(f"{len(targets)} target(s) loaded: {', '.join(targets)}")

    # --- parse interval (if any) -----------------------------------------
    interval_secs: Optional[int] = None
    if args.interval:
        try:
            interval_secs = _parse_interval(args.interval)
            logger.info(f"Interval mode: scanning every {interval_secs}s ({args.interval})")
        except ValueError as exc:
            logger.error(f"Invalid --interval: {exc}")
            return

    # --- scan loop -------------------------------------------------------
    cycle = 0
    while True:
        if _shutdown_event.is_set():
            break

        cycle += 1
        scan_id = generate_scan_id()
        config.scan_id = scan_id
        logger.info(f"{'=' * 60}")
        logger.info(f"Scan cycle #{cycle}  [scan_id: {scan_id}]")
        logger.info(f"{'=' * 60}")

        _run_scan_cycle(targets, config, scan_id, logger)

        # --- final summary for this cycle ---------------------------------
        logger.info("=" * 60)
        if _shutdown_event.is_set():
            logger.warning("Framework exited early due to shutdown signal")
        else:
            logger.success(f"Scan cycle #{cycle} completed")
        logger.summary()
        logger.info("=" * 60)

        # --- interval handling -------------------------------------------
        if interval_secs is None:
            # Single-run mode – exit after one cycle
            break

        if _shutdown_event.is_set():
            break

        logger.info(f"Sleeping {interval_secs}s until next scan cycle...")
        # Sleep in small chunks so we can respond to shutdown quickly
        elapsed = 0
        while elapsed < interval_secs and not _shutdown_event.is_set():
            time.sleep(min(5, interval_secs - elapsed))
            elapsed += 5


if __name__ == "__main__":
    main()
