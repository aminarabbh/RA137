"""
Centralized logging for RA137 Reconnaissance Framework.

Features:
- Colored console output (ANSI)
- Per-module log prefixes
- Progress bar reporting
- Error / warning counters
- File + console logging
- Backward-compatible ``log()`` function
"""

import re
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------
class _Colors:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for clean file output."""
    return _ANSI_RE.sub("", text)


# ---------------------------------------------------------------------------
# Logger class
# ---------------------------------------------------------------------------
class Logger:
    """Module-aware logger with colored console output and file logging."""

    def __init__(self, module_name: str = "MAIN", log_file: Optional[Path] = None):
        self.module = module_name.upper()
        self.log_file = log_file or Path("outputs") / "recon.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.error_count: int = 0
        self.warning_count: int = 0

    # -- internal helpers ---------------------------------------------------

    def _fmt(self, level: str, msg: str, color: str) -> str:
        ts = datetime.now().strftime("%H:%M:%S")
        return f"{color}[{ts}] [{self.module}] [{level}] {msg}{_Colors.RESET}"

    def _write(self, formatted: str):
        """Append the message (ANSI stripped) to the log file."""
        try:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(_strip_ansi(formatted) + "\n")
        except OSError:
            pass  # never let logging crash the framework

    def _emit(self, formatted: str):
        """Print to console and write to file."""
        print(formatted)
        self._write(formatted)

    # -- public API ---------------------------------------------------------

    def info(self, message: str):
        """Informational message (cyan)."""
        self._emit(self._fmt("INFO", message, _Colors.CYAN))

    def success(self, message: str):
        """Success message (green)."""
        self._emit(self._fmt("OK", message, _Colors.GREEN))

    def warning(self, message: str):
        """Warning message (yellow). Increments warning counter."""
        self.warning_count += 1
        self._emit(self._fmt("WARN", message, _Colors.YELLOW))

    def error(self, message: str):
        """Error message (red). Increments error counter."""
        self.error_count += 1
        self._emit(self._fmt("ERROR", message, _Colors.RED))

    def debug(self, message: str):
        """Debug message (magenta) – only shown when DEBUG env is set."""
        import os
        if os.getenv("DEBUG"):
            self._emit(self._fmt("DEBUG", message, _Colors.MAGENTA))

    def progress(self, current: int, total: int, prefix: str = ""):
        """Render a progress bar to the console."""
        if total <= 0:
            return
        pct = (current / total) * 100
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = "█" * filled + "-" * (bar_len - filled)
        msg = f"{prefix}[{bar}] {pct:.0f}% ({current}/{total})"
        formatted = self._fmt("PROG", msg, _Colors.BLUE)
        end = "\n" if current >= total else "\r"
        print(formatted, end=end, flush=True)
        if current >= total:
            self._write(formatted)

    def summary(self):
        """Print a short error/warning summary."""
        if self.error_count or self.warning_count:
            self.warning(
                f"Module finished with {self.error_count} error(s), "
                f"{self.warning_count} warning(s)"
            )


# ---------------------------------------------------------------------------
# Module-level convenience helpers
# ---------------------------------------------------------------------------

# Default logger (backward compatible)
_default_logger = Logger("MAIN")

# Global default log file – when set, all new loggers use this file
# instead of the hardcoded outputs/recon.log. Used by main.py to route
# log output to per-target log files.
_global_log_file: Optional[Path] = None
_global_log_file_lock = threading.Lock()


def set_default_log_file(log_file: Path) -> None:
    """Set the global default log file for all subsequently created loggers."""
    global _global_log_file
    with _global_log_file_lock:
        _global_log_file = Path(log_file)


def log(message: str):
    """
    Legacy ``log()`` function – backward compatible wrapper.

    All existing code that calls ``from utils.logger import log`` keeps
    working without changes.
    """
    _default_logger.info(message)


def get_logger(module_name: str, log_file: Optional[Path] = None) -> Logger:
    """Factory: create a ``Logger`` with a module prefix.

    If *log_file* is ``None``, uses the global default log file (set by
    ``set_default_log_file``), falling back to ``outputs/recon.log``.
    """
    with _global_log_file_lock:
        effective_log_file = log_file or _global_log_file
    return Logger(module_name, effective_log_file)