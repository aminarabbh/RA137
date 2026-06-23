"""
Shared IP address utilities for RA137.

Consolidates IP validation, regex extraction, and IPv6 support
into a single canonical module used by all discovery modules.
"""

import ipaddress
import json
import re
from pathlib import Path
from typing import List, Set


# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------

# IPv4: matches dotted-quad notation (digits only – validation done separately)
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# IPv6: common full and compressed forms
IPV6_REGEX = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"      # full form
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                     # trailing ::
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"    # ::x
    r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"   # ::x:y:...
    r"|[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4}"
    r")\b"
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_ip(ip: str) -> bool:
    """
    Return ``True`` if *ip* is a valid IPv4 or IPv6 address.

    Uses the stdlib ``ipaddress`` module for authoritative validation,
    which also rejects leading-zero ambiguities (e.g. ``192.168.01.1``).
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_ipv4(ip: str) -> bool:
    """Return ``True`` only for valid IPv4 addresses."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_network(cidr: str) -> bool:
    """Return ``True`` if *cidr* is a valid IPv4/IPv6 network prefix."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def extract_ipv4_from_text(text: str) -> Set[str]:
    """
    Extract all valid IPv4 addresses from arbitrary text.

    Returns a deduplicated set of validated IP strings.
    """
    found: Set[str] = set()
    for match in IPV4_REGEX.findall(text):
        if is_valid_ip(match):
            found.add(match)
    return found


def extract_ipv6_from_text(text: str) -> Set[str]:
    """
    Extract all valid IPv6 addresses from arbitrary text.

    Returns a deduplicated set of validated IP strings.
    """
    found: Set[str] = set()
    for match in IPV6_REGEX.findall(text):
        if is_valid_ip(match):
            found.add(match)
    return found


def extract_ips_from_text(text: str) -> Set[str]:
    """
    Extract all valid IPv4 and IPv6 addresses from arbitrary text.

    Convenience wrapper combining both v4 and v6 extraction.
    """
    return extract_ipv4_from_text(text) | extract_ipv6_from_text(text)


# ---------------------------------------------------------------------------
# IP file I/O
# ---------------------------------------------------------------------------

def load_ips_from_file(file_path, *, json_lines: bool = False, json_ip_key: str = "ip") -> Set[str]:
    """
    Load validated IPs from a file.

    Supports plain-text (one IP per line) and legacy JSON-Lines formats.
    For the new structured JSON output files, use ``load_ips_from_json()``.

    Parameters
    ----------
    file_path : Path
        Path to the file.
    json_lines : bool
        If ``True``, treat each line as a JSON object and extract the IP
        from the key specified by *json_ip_key*.
    json_ip_key : str
        JSON key to read when *json_lines* is ``True``.

    Returns
    -------
    set[str]
        Deduplicated set of valid IP address strings.
    """
    ips: Set[str] = set()
    file_path = Path(file_path)

    if not file_path.exists():
        return ips

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                if json_lines:
                    try:
                        data = json.loads(line)
                        ip = data.get(json_ip_key, "")
                        if is_valid_ip(ip):
                            ips.add(ip)
                        continue
                    except (json.JSONDecodeError, AttributeError):
                        pass

                # Fallback: regex extraction
                ips |= extract_ips_from_text(line)
    except OSError:
        pass

    return ips


def load_ips_from_json(
    file_path,
    *,
    results_key: str = "results",
    ip_key: str = "ip",
) -> Set[str]:
    """
    Load validated IPs from a structured JSON output file.

    Handles the standard RA137 JSON schema::

        {"metadata": {...}, "results": [{"ip": "...", ...}, ...]}

    Also supports top-level list arrays and ``"ips"`` flat-list keys::

        {"metadata": {...}, "ips": ["1.2.3.4", ...]}

    Parameters
    ----------
    file_path : Path
        Path to the JSON file.
    results_key : str
        Key holding the list of result objects (default ``"results"``).
    ip_key : str
        Key within each result object holding the IP (default ``"ip"``).

    Returns
    -------
    set[str]
        Deduplicated set of valid IP address strings.
    """
    ips: Set[str] = set()
    file_path = Path(file_path)

    if not file_path.exists():
        return ips

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return ips

    # Top-level list (e.g. realip_results.json)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                ip = item.get(ip_key, "")
                if is_valid_ip(ip):
                    ips.add(ip)
            elif isinstance(item, str) and is_valid_ip(item):
                ips.add(item)
        return ips

    if not isinstance(data, dict):
        return ips

    # results_key -> list of objects with ip_key
    results = data.get(results_key)
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict):
                ip = item.get(ip_key, "")
                if is_valid_ip(ip):
                    ips.add(ip)
            elif isinstance(item, str) and is_valid_ip(item):
                ips.add(item)
        return ips

    # Flat "ips" key -> list of IP strings
    flat = data.get("ips")
    if isinstance(flat, list):
        for ip in flat:
            if isinstance(ip, str) and is_valid_ip(ip):
                ips.add(ip)
        return ips

    # "direct_ips" key -> list of plain IP strings (cdn_analysis)
    direct = data.get("direct_ips")
    if isinstance(direct, list):
        for ip in direct:
            if isinstance(ip, str) and is_valid_ip(ip):
                ips.add(ip)

    return ips


def load_subdomains_from_json(file_path) -> List[str]:
    """
    Load subdomain list from the JSON output of subdomain_enum.

    Returns
    -------
    list[str]
        List of subdomain strings.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    if isinstance(data, dict):
        return [s for s in data.get("subdomains", []) if isinstance(s, str) and s.strip()]
    return []


def sorted_ip_list(ips) -> list:
    """
    Return a list of IPs sorted by their packed binary representation.

    Handles mixed IPv4/IPv6 by sorting within each family separately
    then concatenating (v4 first).
    """
    v4 = []
    v6 = []
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 4:
                v4.append(ip)
            else:
                v6.append(ip)
        except (ValueError, TypeError):
            continue

    v4.sort(key=lambda x: ipaddress.ip_address(x).packed)
    v6.sort(key=lambda x: ipaddress.ip_address(x).packed)
    return v4 + v6
