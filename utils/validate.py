"""
Target domain validation utilities for RA137.

Ensures that target strings from ``targets.txt`` are legitimate domain names
before they are passed to shell commands or API calls.
"""

import re
from typing import Optional


# RFC-1035 compliant domain regex (labels separated by dots, max 253 chars total)
_DOMAIN_RE = re.compile(
    r"^(?!-)"                        # must not start with hyphen
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"  # subdomains
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"          # last label
    r"\.?"                           # optional trailing dot (FQDN)
    r"$"
)

# Characters that are dangerous in shell contexts
_SHELL_META = re.compile(r"[;|&$`\"'\\(){}<>\n\r]")


def validate_domain(domain: str) -> Optional[str]:
    """
    Validate and sanitise a domain string.

    Returns the cleaned domain on success, or ``None`` if the input is
    invalid or contains shell-unsafe characters.
    """
    if not domain or not isinstance(domain, str):
        return None

    domain = domain.strip().lower()

    # Strip protocol prefixes (common mistake in targets.txt)
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]

    # Strip trailing path components
    domain = domain.split("/")[0]

    # Reject shell meta-characters outright
    if _SHELL_META.search(domain):
        return None

    # Reject excessively long domains (DoS protection)
    if len(domain) > 253:
        return None

    # Must match RFC-1035 structure
    if not _DOMAIN_RE.match(domain):
        return None

    # Strip trailing dot for consistency
    return domain.rstrip(".")


def is_safe_command_arg(value: str) -> bool:
    """
    Return ``True`` if *value* contains no shell meta-characters and is
    safe to interpolate into a command.

    This is a **defence-in-depth** check – prefer passing arguments as a
    list (``shell=False``) whenever possible.
    """
    return bool(value) and not _SHELL_META.search(value) and len(value) <= 512
