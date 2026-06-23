"""
Safe shell-command execution with retries, timeouts, and structured results.

Supports two calling conventions:
- **list** of arguments → ``shell=False`` (safe; no injection possible)
- **string** command    → ``shell=True`` (legacy; caller must sanitise inputs)

All new code should pass a *list* to avoid shell injection.
"""

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

from utils.logger import get_logger

_log = get_logger("CMD")

# Type alias: callers may pass either a list (preferred) or a string (legacy)
CmdArg = Union[List[str], str]


@dataclass
class CommandResult:
    """Structured result of a shell command execution."""
    success: bool = False
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    timed_out: bool = False

    def __bool__(self) -> bool:
        return self.success


def run_command(
    cmd: CmdArg,
    output_file: Optional[Path] = None,
    timeout: int = 10000,
    retries: int = 2,
    backoff_factor: float = 2.0,
    silent: bool = True,
    cwd: Optional[Path] = None,
) -> CommandResult:
    """
    Run a shell command with retry logic and timeout handling.

    Parameters
    ----------
    cmd :
        A **list** of arguments (preferred – uses ``shell=False``) or a
        plain **string** (legacy – uses ``shell=True``; inputs MUST be
        sanitised by the caller).
    output_file :
        If given, stdout is redirected to this file.
    timeout :
        Per-attempt timeout in seconds.
    retries :
        Number of retry attempts after a failure.
    backoff_factor :
        Multiplier for exponential-backoff between retries.
    silent :
        Suppress stderr on stdout redirect.
    cwd :
        Working directory for the child process.

    Returns
    -------
    ``CommandResult`` with execution details.
    """
    if output_file is not None:
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)

    # Determine shell mode from argument type
    use_shell = isinstance(cmd, str)

    # Build a display string for logging (truncated)
    display = cmd if use_shell else " ".join(cmd)

    last_error = ""
    last_rc = -1

    for attempt in range(retries + 1):
        try:
            # --- run the command -------------------------------------------
            if output_file is not None:
                with open(output_file, "w", encoding="utf-8") as fh:
                    proc = subprocess.run(
                        cmd,
                        shell=use_shell,
                        stdout=fh,
                        stderr=subprocess.PIPE if not silent else subprocess.DEVNULL,
                        text=True,
                        timeout=timeout,
                        cwd=cwd,
                    )
                stdout_text = ""
                stderr_text = (proc.stderr or "").strip() if not silent else ""
            else:
                proc = subprocess.run(
                    cmd,
                    shell=use_shell,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                )
                stdout_text = proc.stdout or ""
                stderr_text = (proc.stderr or "").strip()

            last_rc = proc.returncode

            if proc.returncode == 0:
                return CommandResult(
                    success=True,
                    stdout=stdout_text,
                    stderr=stderr_text,
                    returncode=0,
                    timed_out=False,
                )

            # Non-zero exit – log and maybe retry
            last_error = stderr_text or f"exit code {proc.returncode}"
            _log.warning(f"Command exited {proc.returncode}: {display[:120]}")
            if stderr_text:
                _log.warning(f"  stderr: {stderr_text[:300]}")

        except subprocess.TimeoutExpired:
            last_error = f"timeout after {timeout}s"
            _log.warning(f"Timeout: {display[:120]}")
            if attempt == retries:
                return CommandResult(
                    success=False,
                    stdout="",
                    stderr=last_error,
                    returncode=-1,
                    timed_out=True,
                )

        except FileNotFoundError as exc:
            # Binary not found – no point retrying
            last_error = str(exc)
            _log.error(f"Binary not found: {exc}")
            return CommandResult(
                success=False,
                stdout="",
                stderr=last_error,
                returncode=127,
                timed_out=False,
            )

        except Exception as exc:
            last_error = str(exc)
            _log.error(f"Exception: {exc}")

        # --- backoff before retry ------------------------------------------
        if attempt < retries:
            wait = backoff_factor ** (attempt + 1)
            _log.info(f"Retry: waiting {wait:.1f}s before attempt {attempt + 2}/{retries + 1}")
            time.sleep(wait)

    return CommandResult(
        success=False,
        stdout="",
        stderr=last_error,
        returncode=last_rc,
        timed_out=("timeout" in last_error.lower()),
    )
