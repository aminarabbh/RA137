"""
CDN / Cloud / Hosting IP-range updater and checker for RA137.

Downloads CIDR ranges from official provider sources, validates them,
merges / deduplicates, and saves to ``all_cdn.txt``.

Supported providers (20):
    AWS, GCP, Azure, Cloudflare, Oracle, Fastly, GitHub, Akamai,
    Fly.io, Hetzner, OVH, Vultr, Linode, Scaleway, Tencent Cloud,
    Alibaba, Huawei, IBM Cloud, Leaseweb, Contabo

Also provides helpers to *load* the saved ranges and *check* individual
IPs against them.
"""

import bisect
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from utils.logger import Logger, get_logger
from utils.ip_utils import is_valid_network

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
ParserFn = Callable[[str], List[str]]

# ---------------------------------------------------------------------------
# Provider source definitions
# ---------------------------------------------------------------------------

def _parse_lines(content: str) -> List[str]:
    """Parse plain-text (one CIDR per line)."""
    return [
        ln.strip()
        for ln in content.splitlines()
        if ln.strip() and not ln.startswith("#")
    ]


def _parse_aws(content: str) -> List[str]:
    data = json.loads(content)
    out: List[str] = []
    for p in data.get("prefixes", []):
        if "ip_prefix" in p:
            out.append(p["ip_prefix"])
    for p in data.get("ipv6_prefixes", []):
        if "ipv6_prefix" in p:
            out.append(p["ipv6_prefix"])
    return out


def _parse_gcp(content: str) -> List[str]:
    data = json.loads(content)
    out: List[str] = []
    for p in data.get("prefixes", []):
        v4 = p.get("ipv4Prefix")
        v6 = p.get("ipv6Prefix")
        if v4:
            out.append(v4)
        if v6:
            out.append(v6)
    return out


def _parse_azure(content: str) -> List[str]:
    data = json.loads(content)
    out: List[str] = []
    for val in data.get("values", []):
        props = val.get("properties", {})
        for prefix in props.get("addressPrefixes", []):
            out.append(prefix)
    return out


def _parse_oracle(content: str) -> List[str]:
    data = json.loads(content)
    out: List[str] = []
    for region in data.get("regions", []):
        for cidr in region.get("cidrs", []):
            ip = cidr.get("cidr")
            if ip:
                out.append(ip)
    return out


def _parse_hetzner(content: str) -> List[str]:
    """Hetzner provides a JSON with server networks."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _parse_lines(content)
    out: List[str] = []
    if isinstance(data, list):
        for entry in data:
            for net in entry.get("networks", []):
                if "ipv4" in net:
                    out.append(net["ipv4"])
                if "ipv6" in net:
                    out.append(net["ipv6"])
    return out or _parse_lines(content)


# Provider definitions: name -> {urls, parser, category}
CDN_SOURCES: Dict[str, dict] = {
    # --- CDN ---
    "cloudflare": {
        "urls": [
            "https://www.cloudflare.com/ips-v4/",
            "https://www.cloudflare.com/ips-v6/",
        ],
        "parser": _parse_lines,
        "category": "cdn",
    },
    "fastly": {
        "urls": [
            "https://api.fastly.com/public-ip-list",
        ],
        "parser": _parse_lines,
        "category": "cdn",
    },
    "akamai": {
        # Akamai does not publish an official list; use Cloudflare as proxy
        # (Akamai CIDRs are often covered by other sources)
        "urls": [],
        "parser": _parse_lines,
        "category": "cdn",
    },
    "arvancloud": {
        "urls": [
            "https://www.arvancloud.ir/fa/ips.txt",
        ],
        "parser": _parse_lines,
        "category": "cdn",
        "fallback_static": [
            "5.252.32.0/22", "5.252.32.0/24", "5.252.33.0/24",
            "5.252.34.0/24", "5.252.35.0/24",
            "31.214.168.0/21", "37.156.144.0/22", "37.156.144.0/24",
            "37.156.145.0/24", "37.156.146.0/24", "37.156.147.0/24",
            "81.12.0.0/18",
            "94.182.160.0/21", "94.182.160.0/24", "94.182.161.0/24",
            "94.182.162.0/24", "94.182.163.0/24",
            "109.200.192.0/19", "130.185.128.0/21",
            "130.185.128.0/24", "130.185.129.0/24",
            "130.185.130.0/24", "130.185.131.0/24",
            "130.185.132.0/24", "130.185.133.0/24",
            "130.185.134.0/24", "130.185.135.0/24",
            "185.228.236.0/22", "185.228.236.0/24",
            "185.228.237.0/24", "185.228.238.0/24",
            "185.228.239.0/24",
            # Additional ArvanCloud edge ranges
            "185.143.232.0/22",
            "185.166.104.0/24",
            "188.229.116.16/30",
            "94.101.182.0/27", "94.101.183.0/28",
            "2.144.3.128/28",
            "37.32.16.0/27", "37.32.17.0/27",
            "37.32.18.0/27", "37.32.19.0/27",
            "185.215.232.0/22",
            "178.131.120.48/28",
            "78.157.36.112/28",
        ],
    },
    # --- Cloud ---
    "aws": {
        "urls": ["https://ip-ranges.amazonaws.com/ip-ranges.json"],
        "parser": _parse_aws,
        "category": "cloud",
    },
    "gcp": {
        "urls": ["https://www.gstatic.com/ipranges/cloud.json"],
        "parser": _parse_gcp,
        "category": "cloud",
    },
    "azure": {
        "urls": [
            "https://download.microsoft.com/download/7/1/D/"
            "71D86715-5596-4529-9B13-DA13A5DE5B63/"
            "ServiceTags_Public_20240506.json"
        ],
        "parser": _parse_azure,
        "category": "cloud",
    },
    "oracle": {
        "urls": [
            "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
        ],
        "parser": _parse_oracle,
        "category": "cloud",
    },
    "ibm_cloud": {
        "urls": [
            "https://api.cloud.ibm.com/v1/ips"
        ],
        "parser": _parse_lines,
        "category": "cloud",
    },
    # --- Hosting ---
    "hetzner": {
        "urls": ["https://www.hetzner.com/de/meta/news.xml"],
        "parser": _parse_hetzner,
        "category": "hosting",
        # Hetzner official CIDR page is dynamic; fall back to static list
        "fallback_static": [
            "5.9.0.0/16", "46.4.0.0/16", "78.46.0.0/15",
            "88.99.0.0/16", "94.130.0.0/16", "95.216.0.0/16",
            "95.217.0.0/16", "116.202.0.0/16", "116.203.0.0/16",
            "135.181.0.0/16", "138.201.0.0/16", "142.132.128.0/17",
            "144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16",
            "159.69.0.0/16", "162.55.0.0/16", "167.233.0.0/16",
            "168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16",
            "188.40.0.0/16", "195.201.0.0/16", "213.133.96.0/19",
            "213.239.192.0/18", "217.160.0.0/16",
        ],
    },
    "ovh": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "5.39.0.0/17", "5.135.0.0/16", "5.196.0.0/16",
            "37.59.0.0/16", "37.187.0.0/16", "46.105.0.0/16",
            "51.38.0.0/16", "51.68.0.0/16", "51.75.0.0/16",
            "51.77.0.0/16", "51.79.0.0/16", "51.81.0.0/16",
            "51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
            "54.36.0.0/16", "54.37.0.0/16", "54.38.0.0/16",
            "54.39.0.0/16", "87.98.128.0/17", "91.121.0.0/16",
            "91.134.0.0/16", "92.222.0.0/16", "94.23.0.0/16",
            "137.74.0.0/16", "141.94.0.0/16", "141.95.0.0/16",
            "145.239.0.0/16", "146.59.0.0/16", "152.228.128.0/17",
            "164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/15",
            "188.165.0.0/16", "193.70.0.0/17", "198.27.64.0/18",
            "217.182.0.0/16",
        ],
    },
    "vultr": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16",
            "64.176.0.0/16", "66.135.16.0/20", "66.42.0.0/16",
            "95.179.0.0/16", "104.156.224.0/20", "104.207.128.0/18",
            "104.238.128.0/18", "108.61.0.0/16", "140.82.0.0/16",
            "144.202.0.0/16", "149.28.0.0/16", "155.138.128.0/18",
            "167.179.96.0/20", "199.247.0.0/18", "207.148.0.0/18",
            "208.167.224.0/19", "209.222.0.0/18",
        ],
    },
    "linode": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "23.239.0.0/18", "45.33.0.0/16", "45.55.0.0/16",
            "45.56.64.0/18", "45.79.0.0/16", "50.116.0.0/16",
            "66.175.208.0/20", "66.228.32.0/19", "69.164.192.0/18",
            "72.14.176.0/20", "74.207.224.0/19", "96.126.96.0/19",
            "97.107.128.0/20", "104.131.0.0/16", "104.237.128.0/18",
            "139.162.0.0/16", "143.110.128.0/18", "162.159.0.0/16",
            "170.187.128.0/18", "172.104.0.0/16", "173.255.192.0/18",
            "176.58.96.0/19", "178.79.128.0/18", "192.155.80.0/20",
            "194.195.112.0/20", "198.58.96.0/19", "207.192.64.0/18",
            "212.71.128.0/18",
        ],
    },
    "scaleway": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "62.210.0.0/16", "163.172.0.0/16", "195.154.0.0/16",
            "212.47.224.0/19", "151.115.0.0/16", "51.15.0.0/16",
            "51.158.0.0/16",
        ],
    },
    "tencent_cloud": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "43.128.0.0/13", "43.152.0.0/16", "43.159.0.0/16",
            "43.175.0.0/16", "43.208.0.0/13", "49.51.0.0/16",
            "103.7.28.0/22", "103.238.160.0/22", "111.45.0.0/16",
            "119.28.0.0/16", "129.28.0.0/16", "129.204.0.0/16",
            "132.232.0.0/16", "134.175.0.0/16", "150.158.0.0/16",
            "182.254.0.0/16", "203.195.128.0/17",
        ],
    },
    "alibaba": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "8.128.0.0/14", "8.132.0.0/15", "8.136.0.0/13",
            "8.144.0.0/12", "8.208.0.0/12", "47.74.0.0/15",
            "47.88.0.0/14", "47.235.0.0/16", "47.236.0.0/14",
            "47.240.0.0/13", "47.250.0.0/15", "47.252.0.0/15",
            "47.254.0.0/16",
        ],
    },
    "huawei": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "80.225.192.0/18", "85.184.248.0/22", "159.138.0.0/16",
        ],
    },
    "leaseweb": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "5.79.64.0/18", "37.48.64.0/18", "46.16.96.0/21",
            "46.166.128.0/18", "62.212.64.0/18", "81.17.52.0/22",
            "82.192.64.0/19", "85.17.0.0/16", "93.190.136.0/21",
            "95.211.0.0/16", "108.62.0.0/18", "178.162.192.0/18",
            "185.4.224.0/22", "209.197.0.0/19",
        ],
    },
    "contabo": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "5.189.128.0/18", "37.120.160.0/19", "46.4.64.0/18",
            "62.2.72.0/21", "79.143.160.0/19", "80.241.208.0/20",
            "91.215.176.0/22", "109.230.224.0/19", "149.102.128.0/17",
            "154.53.128.0/18", "185.2.96.0/22", "185.100.84.0/22",
            "194.117.252.0/22",
        ],
    },
    "github": {
        "urls": [
            "https://api.github.com/meta",
        ],
        "parser": lambda content: (
            json.loads(content).get("hooks", [])
            + json.loads(content).get("web", [])
            + json.loads(content).get("api", [])
            + json.loads(content).get("git", [])
            + json.loads(content).get("packages", [])
            + json.loads(content).get("pages", [])
            + json.loads(content).get("importer", [])
            + json.loads(content).get("actions", [])
            + json.loads(content).get("dependabot", [])
        ) if isinstance(json.loads(content), dict) else _parse_lines(content),
        "category": "hosting",
    },
    "fly_io": {
        "urls": [],
        "parser": _parse_lines,
        "category": "hosting",
        "fallback_static": [
            "66.241.124.0/23", "77.83.140.0/22",
            "149.248.192.0/23", "149.248.196.0/23",
            "149.248.200.0/23", "149.248.204.0/23",
            "149.248.208.0/23", "149.248.212.0/23",
            "149.248.216.0/23", "149.248.220.0/23",
            "213.188.194.0/23", "213.188.198.0/23",
            "213.188.208.0/23", "213.188.210.0/23",
        ],
    },
}


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def _fetch_one(url: str, parser: ParserFn, timeout: int = 30) -> List[str]:
    """Download a single URL and parse CIDRs."""
    from utils.http_session import get_session
    sess = get_session()
    resp = sess.get(url, timeout=timeout)
    resp.raise_for_status()
    return parser(resp.text)


def _fetch_provider(
    name: str,
    source: dict,
    timeout: int = 30,
    retries: int = 3,
    logger: Optional[Logger] = None,
) -> List[str]:
    """Fetch all URLs for a provider, with retries. Falls back to static list."""
    if logger is None:
        logger = get_logger("CDN-UPDATER")

    all_cidrs: List[str] = []

    for url in source.get("urls", []):
        for attempt in range(1, retries + 1):
            try:
                cidrs = _fetch_one(url, source["parser"], timeout)
                all_cidrs.extend(cidrs)
                logger.info(f"  {name}: {len(cidrs)} CIDRs from {url}")
                break
            except Exception as exc:
                logger.warning(
                    f"  {name}: attempt {attempt}/{retries} for {url} failed – {exc}"
                )
        else:
            logger.error(f"  {name}: all {retries} attempts failed for {url}")

    # Use fallback static list if no dynamic results
    if not all_cidrs and source.get("fallback_static"):
        logger.info(f"  {name}: using {len(source['fallback_static'])} static CIDRs")
        all_cidrs.extend(source["fallback_static"])

    return all_cidrs


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_cidr(cidr: str) -> bool:
    """Return ``True`` if *cidr* is a valid IPv4/IPv6 network."""
    return is_valid_network(cidr)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def update_cdn_ranges(
    output_file: Path,
    logger: Optional[Logger] = None,
    max_workers: int = 20,
    timeout: int = 30,
) -> int:
    """
    Download CIDR ranges from all providers and save to *output_file*.

    Returns the number of unique, valid CIDRs written.
    """
    if logger is None:
        logger = get_logger("CDN-UPDATER")

    logger.info(f"Updating CDN/Cloud/Hosting ranges → {output_file}")
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    collected: List[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_fetch_provider, name, src, timeout, 3, logger): name
            for name, src in CDN_SOURCES.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                cidrs = future.result()
                collected.extend(cidrs)
            except Exception as exc:
                logger.error(f"  {name} failed completely: {exc}")

    # Deduplicate and validate
    unique: Set[str] = set()
    valid: List[str] = []
    for cidr in collected:
        cidr = cidr.strip()
        if cidr and cidr not in unique and validate_cidr(cidr):
            unique.add(cidr)
            valid.append(cidr)

    valid.sort(key=lambda c: ipaddress.ip_network(c, strict=False).network_address.packed)

    with open(output_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(valid) + "\n")

    logger.success(f"Wrote {len(valid)} unique CIDRs to {output_file}")
    return len(valid)


def load_cdn_networks(
    cdn_file: Path,
    logger: Optional[Logger] = None,
    auto_update: bool = True,
) -> List[IPNetwork]:
    """
    Load CDN networks from *cdn_file*.

    If the file does not exist and *auto_update* is ``True``, the ranges
    are downloaded first.
    """
    if logger is None:
        logger = get_logger("CDN-CHECK")

    cdn_file = Path(cdn_file)
    if not cdn_file.exists() and auto_update:
        logger.warning(f"{cdn_file} not found – downloading fresh ranges")
        update_cdn_ranges(cdn_file, logger)

    if not cdn_file.exists():
        logger.error(f"CDN file still missing after update attempt: {cdn_file}")
        return []

    networks: List[IPNetwork] = []
    with open(cdn_file, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except (ValueError, TypeError):
                    pass

    logger.info(f"Loaded {len(networks)} CDN/Cloud/Hosting networks")
    return networks


def build_provider_cidr_map() -> Dict[str, dict]:
    """
    Build a mapping of every known CIDR to its provider name and category.

    Fetches all provider URLs (same sources used by ``update_cdn_ranges``)
    and falls back to ``fallback_static`` lists when a download fails.
    This ensures that dynamically-downloaded ranges (Cloudflare, AWS, …)
    are properly labelled, not just static fallbacks.
    """
    provider_map: Dict[str, dict] = {}

    for name, source in CDN_SOURCES.items():
        category = source.get("category", "unknown")
        cidrs: List[str] = []

        # Fetch from official URLs
        for url in source.get("urls", []):
            try:
                cidrs.extend(_fetch_one(url, source["parser"]))
            except Exception:
                pass

        # Fallback to static list when no dynamic results
        if not cidrs and source.get("fallback_static"):
            cidrs = list(source["fallback_static"])

        for cidr in cidrs:
            try:
                net = ipaddress.ip_network(cidr.strip(), strict=False)
                provider_map[str(net)] = {"provider": name, "category": category}
            except (ValueError, TypeError):
                pass

    return provider_map


# Module-level cache for check_ip_cdn binary-search indexes.
# Keyed by id(networks); safe because callers hold a reference to the list
# for the duration of each scan, and we also store len(networks) as a
# collision guard.
_check_ip_cdn_cache: Dict[int, Tuple[list, list, list, list, int]] = {}


def check_ip_cdn(
    ip_str: str,
    networks: List[IPNetwork],
) -> Optional[str]:
    """
    Check whether *ip_str* falls inside any CDN network.

    Uses binary search on sorted network start-addresses for O(log n)
    lookups instead of O(n) linear scan.

    Returns the matching CIDR string or ``None``.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return None

    # Build sorted index (cached per unique network list)
    net_id = id(networks)
    cache_entry = _check_ip_cdn_cache.get(net_id)
    if cache_entry is not None and cache_entry[4] == len(networks):
        v4_nets, v4_starts, v6_nets, v6_starts, _ = cache_entry
    else:
        # Separate v4 and v6, sort by network address
        v4_nets = sorted(
            [n for n in networks if n.version == 4],
            key=lambda n: int(n.network_address),
        )
        v6_nets = sorted(
            [n for n in networks if n.version == 6],
            key=lambda n: int(n.network_address),
        )
        v4_starts = [int(n.network_address) for n in v4_nets]
        v6_starts = [int(n.network_address) for n in v6_nets]
        _check_ip_cdn_cache[net_id] = (v4_nets, v4_starts, v6_nets, v6_starts, len(networks))

    ip_int = int(ip_obj)

    if ip_obj.version == 4:
        nets, starts = v4_nets, v4_starts
    else:
        nets, starts = v6_nets, v6_starts

    if not starts:
        return None

    # Binary search: find the rightmost network whose start <= ip
    idx = bisect.bisect_right(starts, ip_int) - 1
    # Check a few candidates (overlapping ranges may exist)
    for i in range(max(idx, 0), min(idx + 3, len(nets))):
        if ip_obj in nets[i]:
            return str(nets[i])
    # Also check backwards for larger ranges that contain this IP
    for i in range(max(idx - 2, 0), max(idx, 0)):
        if ip_obj in nets[i]:
            return str(nets[i])

    return None


# ---------------------------------------------------------------------------
# Standalone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from utils.config import get_config

    cfg = get_config()
    _logger = get_logger("CDN-UPDATER")

    # Always write to wordlists/all_cdn.txt (project root)
    _output = cfg.paths.cdn_file
    _logger.info(f"CDN output target: {_output}")

    _count = update_cdn_ranges(
        output_file=_output,
        logger=_logger,
        max_workers=cfg.concurrency.max_cdn_workers,
    )
    _logger.success(f"Done – {_count} CIDRs written to {_output}")
