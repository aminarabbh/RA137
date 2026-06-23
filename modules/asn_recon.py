"""
ASN / IP-range reconnaissance module for RA137.

Uses **ipinfo.io** (Lite API – free, unlimited) to identify the ASN and
organisation behind each known IP, then queries **RIPEstat** for the full
list of announced prefixes for those ASNs.  Prefixes whose organisation
name does not match the target are filtered out.

Inputs
------
* ``<target>/ip.txt``      – direct IPs from CDN check
* ``<target>/realip.txt``  – IPs from real-IP discovery

Outputs
-------
* ``<target>/realip/asn_results.json`` – structured ASN recon results
* ``<target>/realip/asn_info.json``    – per-IP ASN metadata
* ``<target>/asn_recon.txt``           – legacy text format
"""

import ipaddress
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.http_session import get_session, api_cache
from utils.ip_utils import load_ips_from_json, extract_ips_from_text
from utils.ai_report import generate_ai_report, ai_validate
from utils.paths import build_metadata

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IPINFO_LITE_URL = "https://api.ipinfo.io/lite"
RIPESTAT_BASE = "https://stat.ripe.net/data"
PEERINGDB_NET_URL = "https://www.peeringdb.com/api/net"
MAX_WORKERS = 20
RIPESTAT_RETRIES = 2


# ---------------------------------------------------------------------------
# ipinfo.io helpers
# ---------------------------------------------------------------------------

def _ipinfo_lookup(ip: str, token: str, logger: Logger) -> Optional[dict]:
    """Query ipinfo.io Lite API for ASN + org info."""
    cache_key = f"ipinfo:{ip}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        sess = get_session()
        url = f"{IPINFO_LITE_URL}/{ip}"
        params = {"token": token} if token else {}
        resp = sess.get(url, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "ip": ip,
                "asn": data.get("asn", ""),
                "as_name": data.get("as_name", ""),
                "as_domain": data.get("as_domain", ""),
                "country": data.get("country", ""),
            }
            api_cache.put(cache_key, result)
            return result
        elif resp.status_code == 429:
            logger.warning(f"ipinfo.io rate-limited on {ip}")
        else:
            logger.debug(f"ipinfo.io returned {resp.status_code} for {ip}")
    except Exception as exc:
        logger.debug(f"ipinfo.io lookup failed for {ip}: {exc}")

    return None


def _batch_ipinfo(
    ips: List[str],
    token: str,
    logger: Logger,
) -> Dict[str, dict]:
    """Look up multiple IPs on ipinfo.io with concurrency control."""
    results: Dict[str, dict] = {}

    def _lookup(ip: str) -> Optional[dict]:
        time.sleep(0.1)  # gentle rate limit
        return _ipinfo_lookup(ip, token, logger)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_lookup, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                info = future.result()
                if info and info.get("asn"):
                    results[ip] = info
            except Exception as exc:
                logger.error(f"ipinfo lookup error for {ip}: {exc}")

    return results


# ---------------------------------------------------------------------------
# RIPEstat helpers (for prefix discovery)
# ---------------------------------------------------------------------------

def _ripestat(endpoint: str, resource: str, logger: Optional[Logger] = None) -> Optional[dict]:
    """Query RIPEstat API with caching and retry."""
    cache_key = f"ripestat:{endpoint}:{resource}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached

    for attempt in range(1, RIPESTAT_RETRIES + 1):
        try:
            sess = get_session()
            url = f"{RIPESTAT_BASE}/{endpoint}/data.json"
            resp = sess.get(url, params={"resource": resource}, timeout=20)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                api_cache.put(cache_key, data)
                return data
            elif resp.status_code == 429:
                if logger:
                    logger.warning(f"RIPEstat rate-limited for {resource} (attempt {attempt})")
                time.sleep(2 * attempt)  # exponential backoff
            else:
                if logger:
                    logger.warning(f"RIPEstat returned {resp.status_code} for {resource}")
                return None
        except Exception as exc:
            if logger:
                logger.warning(f"RIPEstat query failed for {resource} (attempt {attempt}): {exc}")
            if attempt < RIPESTAT_RETRIES:
                time.sleep(1)

    return None


def _get_announced_prefixes(asn: str, logger: Optional[Logger] = None) -> Set[str]:
    """Get all announced prefixes for an ASN from RIPEstat, with PeeringDB fallback."""
    if not asn:
        return set()

    # Primary: RIPEstat
    data = _ripestat("announced-prefixes", asn, logger=logger)
    if data:
        prefixes = {p["prefix"] for p in data.get("prefixes", []) if "prefix" in p}
        if prefixes:
            return prefixes

    # Fallback: PeeringDB
    peering_prefixes = _peeringdb_prefixes(asn, logger=logger)
    if peering_prefixes:
        if logger:
            logger.info(f"  RIPEstat empty for {asn}, got {len(peering_prefixes)} prefixes from PeeringDB")
        return peering_prefixes

    return set()


def _peeringdb_prefixes(asn: str, logger: Optional[Logger] = None) -> Set[str]:
    """Query PeeringDB for announced prefixes of an ASN."""
    asn_num = asn.upper().replace("AS", "")
    cache_key = f"peeringdb:prefix:{asn_num}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        sess = get_session()
        # Find ASN info from PeeringDB – info_prefixes4/6 contain the CIDR ranges
        resp = sess.get(PEERINGDB_NET_URL, params={"asn": asn_num}, timeout=15)
        if resp.status_code != 200:
            return set()
        nets = resp.json().get("data", [])
        if not nets:
            return set()

        prefixes: Set[str] = set()
        info_prefixes = nets[0].get("info_prefixes4", "") or ""
        info_prefixes6 = nets[0].get("info_prefixes6", "") or ""
        for p in (info_prefixes + " " + info_prefixes6).split():
            p = p.strip()
            if "/" in p:
                prefixes.add(p)

        api_cache.put(cache_key, prefixes)
        return prefixes
    except Exception as exc:
        if logger:
            logger.debug(f"PeeringDB query failed for {asn}: {exc}")
        return set()


def _get_asn_holder(asn: str, logger: Optional[Logger] = None) -> str:
    """Get the organisation/holder name for an ASN from RIPEstat."""
    whois = _ripestat("whois", asn, logger=logger)
    if whois:
        for rec in whois.get("records", []):
            for field in rec:
                if field.get("key") in ("org-name", "descr"):
                    return field.get("value", "")
    return ""


# ---------------------------------------------------------------------------
# Organisation similarity matching
# ---------------------------------------------------------------------------

_STOP_WORDS = {
    "", "ltd", "inc", "llc", "gmbh", "ag", "sa", "co", "corp", "plc",
    "bv", "nv", "pty", "the", "and", "for", "of", "in", "a", "an",
}


def _normalise(text: str) -> Set[str]:
    """Lowercase, strip punctuation, split into keyword set."""
    text = text.lower()
    text = re.sub(r"[,\.\-_()/\[\]{}:;\"'`~!@#$%^&*+=|\\<>?]", " ", text)
    return set(text.split()) - _STOP_WORDS


def _substring_score(kw_a: Set[str], kw_b: Set[str]) -> float:
    """Fraction of kw_b tokens found as substrings in kw_a tokens (or vice versa)."""
    if not kw_a or not kw_b:
        return 0.0
    hits = 0
    for token in kw_b:
        if len(token) < 3:
            continue
        for base in kw_a:
            if token in base or base in token:
                hits += 1
                break
    return hits / len(kw_b)


def calculate_org_similarity(org_name: str, target_domain: str) -> float:
    """
    Combined Jaccard + substring similarity between ASN organisation keywords
    and target domain keywords (excluding TLD).

    Substring matching handles compound domain names like "farsnews" matching
    org keywords "fars" + "news".
    """
    if not org_name or not target_domain:
        return 0.0

    domain_parts = target_domain.split(".")
    if len(domain_parts) > 1:
        domain_parts = domain_parts[:-1]  # drop TLD
    domain_kw = _normalise(" ".join(domain_parts))
    org_kw = _normalise(org_name)

    if not domain_kw or not org_kw:
        return 0.0

    # Exact token overlap (Jaccard)
    intersection = domain_kw & org_kw
    union = domain_kw | org_kw
    jaccard = len(intersection) / len(union) if union else 0.0

    # Substring containment in both directions
    sub_dom_in_org = _substring_score(org_kw, domain_kw)
    sub_org_in_dom = _substring_score(domain_kw, org_kw)
    substring = max(sub_dom_in_org, sub_org_in_dom)

    # Return the better of the two methods
    return max(jaccard, substring)


def _domain_match(as_domain: str, target_domain: str) -> float:
    """Check if the ASN's as_domain matches the target domain.

    Returns 1.0 if they share the same base name (ignoring TLD),
    0.5 if there's a partial match, 0.0 otherwise.
    """
    if not as_domain or not target_domain:
        return 0.0

    # Normalise both: drop TLD, lowercase
    def _base_name(domain: str) -> str:
        parts = domain.lower().split(".")
        if len(parts) > 1:
            parts = parts[:-1]
        return ".".join(parts)

    target_base = _base_name(target_domain)
    as_base = _base_name(as_domain)

    if not target_base or not as_base:
        return 0.0

    # Exact base name match (e.g. "farsnews" == "farsnews")
    if target_base == as_base:
        return 1.0

    # Substring containment
    if target_base in as_base or as_base in target_base:
        return 0.8

    # Keyword overlap
    target_kw = _normalise(target_base.replace(".", " "))
    as_kw = _normalise(as_base.replace(".", " "))
    if target_kw and as_kw:
        overlap = len(target_kw & as_kw)
        if overlap > 0:
            return overlap / max(len(target_kw), len(as_kw))

    return 0.0


# ---------------------------------------------------------------------------
# IP loading
# ---------------------------------------------------------------------------

def _load_ips(output_dir: Path) -> Set[str]:
    """Load IPs from direct_ips.json and realip_results.json."""
    output_dir = Path(output_dir)

    # direct_ips.json (non-CDN IPs from CDN check)
    ips = load_ips_from_json(output_dir / "direct_ips.json")

    # realip_results.json (from realip_discovery)
    ips |= load_ips_from_json(output_dir / "realip_results.json")

    return ips


# ---------------------------------------------------------------------------
# Save helpers
# ---------------------------------------------------------------------------

def _save_results(
    asn_map: Dict[str, dict],
    matched_prefixes: Dict[str, Set[str]],
    output_dir: Path,
    logger: Logger,
    target: str = "",
) -> None:
    """Save structured JSON output."""

    # Build ASN entries (deduplicated by ASN)
    asn_entries: List[dict] = []
    all_prefixes: Set[str] = set()
    seen_asns: Set[str] = set()

    for ip, info in asn_map.items():
        asn = info.get("asn", "")
        if asn in seen_asns:
            continue
        seen_asns.add(asn)

        prefixes = sorted(matched_prefixes.get(asn, set()))
        all_prefixes.update(prefixes)
        asn_entries.append({
            "asn": asn,
            "as_name": info.get("as_name", ""),
            "as_domain": info.get("as_domain", ""),
            "country": info.get("country", ""),
            "origin_ips": sorted(
                ip for ip, inf in asn_map.items() if inf.get("asn") == asn
            ),
            "prefixes": prefixes,
        })

    # Build match entries: origin IPs (individual) + CIDR ranges
    seen_ips: Set[str] = set()
    match_entries: List[dict] = []

    # Add individual origin IPs
    for ip in sorted(asn_map.keys()):
        if ip not in seen_ips:
            seen_ips.add(ip)
            match_entries.append({
                "ip": ip,
                "matched_domain": "",
                "port": 0,
                "source": "asn_recon",
            })

    # Add CIDR ranges (not expanded)
    for cidr in sorted(all_prefixes):
        match_entries.append({
            "ip": cidr,
            "matched_domain": "",
            "port": 0,
            "source": "asn_recon_cidr",
        })

    # Structured JSON output (flat, at scan root)
    json_file = Path(output_dir) / "asn_results.json"
    payload = {
        "metadata": build_metadata("ASN Recon", target),
        "total_asns": len(asn_entries),
        "total_origin_ips": len(seen_ips),
        "total_cidr_ranges": len(all_prefixes),
        "matches": match_entries,
        "asns": asn_entries,
    }
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    logger.info(
        f"Saved {len(asn_entries)} ASN entries, "
        f"{len(seen_ips)} origin IPs, {len(all_prefixes)} CIDR ranges"
    )


# ---------------------------------------------------------------------------
# AI validation helper
# ---------------------------------------------------------------------------

def _ai_validate_asns(
    asn_set: Set[str],
    asn_map: Dict[str, dict],
    target: str,
    logger: Logger,
) -> Optional[Set[str]]:
    """
    Use AI to classify which ASNs are relevant to the target organisation.

    Sends all candidate ASNs with their org name, domain, and associated IPs
    to the AI for independent relevance classification.  Returns the set of
    AI-approved ASNs, or ``None`` if the AI call failed.
    """
    logger.info(f"AI validating {len(asn_set)} ASN candidates for target '{target}'")

    # Build a concise list for the AI
    asn_lines = []
    for asn in sorted(asn_set):
        org_name = ""
        as_domain = ""
        ips: List[str] = []
        for ip, info in asn_map.items():
            if info.get("asn") == asn:
                org_name = org_name or info.get("as_name", "")
                as_domain = as_domain or info.get("as_domain", "")
                ips.append(ip)
        asn_lines.append(
            f"{asn} | org=\"{org_name}\" | domain=\"{as_domain}\" | ips={ips[:5]}"
        )

    prompt = (
        f"You are validating ASN (Autonomous System Number) results for target "
        f"domain \"{target}\".\n\n"
        f"For each ASN below, determine if it likely belongs to the organisation "
        f"behind \"{target}\".\n"
        f"Consider: org name similarity, domain name match, IP association, "
        f"and common hosting/CDN providers.\n"
        f"EXCLUDE generic cloud/CDN/hosting providers (Amazon AWS, Cloudflare, "
        f"Akamai, Google Cloud, Microsoft Azure, Fastly, etc.) unless the "
        f"organisation name specifically mentions the target.\n\n"
        f"ASNs:\n" + "\n".join(asn_lines) + "\n\n"
        f"Respond with ONLY a JSON array of relevant ASN strings, e.g. "
        f'["AS12345", "AS67890"]. If none are relevant, return [].'
    )

    response = ai_validate(prompt)
    if not response:
        logger.warning("AI validation returned empty response – using heuristic only")
        return None

    # Parse AI response — extract JSON array
    try:
        # Find JSON array in response (handles markdown wrapping)
        start = response.find("[")
        end = response.rfind("]")
        if start != -1 and end != -1:
            json_str = response[start:end + 1]
            ai_list = json.loads(json_str)
            ai_approved = {a for a in ai_list if isinstance(a, str) and a in asn_set}
            logger.info(f"AI approved {len(ai_approved)}/{len(asn_set)} ASNs")
            for asn in sorted(ai_approved):
                logger.info(f"  AI KEEP: {asn}")
            for asn in sorted(asn_set - ai_approved):
                logger.info(f"  AI SKIP: {asn}")
            return ai_approved
        else:
            logger.warning("AI response did not contain JSON array")
            return None
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning(f"Failed to parse AI validation response: {exc}")
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def asn_recon(
    output_dir: Path,
    target: str,
    logger: Optional[Logger] = None,
) -> None:
    """
    Identify ASN and IP ranges belonging to the target using ipinfo.io.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    target : str
        Target domain name (used for org similarity filtering).
    logger : Logger, optional
        Module logger.
    """
    if logger is None:
        logger = get_logger("ASN-RECON")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting ASN reconnaissance (ipinfo.io)")

    # --- get ipinfo.io token ----------------------------------------------
    token = getattr(config.api_keys, "ipinfo_api_token", None) or ""

    # --- load known IPs ---------------------------------------------------
    known_ips = _load_ips(output_dir)
    if not known_ips:
        logger.warning("No IPs found in direct_ips.json / realip_results.json – skipping ASN recon")
        return
    logger.info(f"Loaded {len(known_ips)} known IPs")

    # --- query ipinfo.io for each IP --------------------------------------
    ip_info_map = _batch_ipinfo(sorted(known_ips), token, logger)
    if not ip_info_map:
        logger.warning("ipinfo.io returned no results – skipping")
        return
    logger.info(f"Got ASN info for {len(ip_info_map)}/{len(known_ips)} IPs")

    # --- group by ASN and filter by org similarity -------------------------
    asn_set: Set[str] = set()
    relevant_asns: Set[str] = set()
    asn_map: Dict[str, dict] = {}

    for ip, info in sorted(ip_info_map.items()):
        asn = info.get("asn", "")
        as_name = info.get("as_name", "")
        as_domain = info.get("as_domain", "")
        if not asn:
            continue

        asn_map[ip] = info
        asn_set.add(asn)

        # Combined similarity: org_name similarity + as_domain match
        org_sim = calculate_org_similarity(as_name, target)
        dom_sim = _domain_match(as_domain, target)
        # Use the best signal: domain match is strongest, org is secondary
        combined_sim = max(org_sim, dom_sim)

        if combined_sim >= 0.25:
            relevant_asns.add(asn)
            reason = "domain" if dom_sim >= org_sim else "org"
            logger.info(f"  {asn} org='{as_name}' domain='{as_domain}' "
                        f"org_sim={org_sim:.2f} dom_sim={dom_sim:.2f} → KEEP ({reason})")
        else:
            logger.info(f"  {asn} org='{as_name}' domain='{as_domain}' "
                        f"org_sim={org_sim:.2f} dom_sim={dom_sim:.2f} → SKIP")

    if not asn_set:
        logger.warning("No ASNs found")
        return

    logger.info(f"Found {len(asn_set)} unique ASNs, {len(relevant_asns)} relevant (heuristic)")

    # --- AI validation of ASN relevance (optional) -------------------------
    if config.ai.ai_validation and len(asn_set) > 0:
        ai_approved = _ai_validate_asns(asn_set, asn_map, target, logger)
        if ai_approved is not None:
            before = len(relevant_asns)
            # Union: keep heuristic-approved + AI-approved
            relevant_asns = relevant_asns | ai_approved
            logger.info(
                f"AI validation: heuristic={before}, AI approved={len(ai_approved)}, "
                f"merged={len(relevant_asns)}"
            )

    if not relevant_asns:
        logger.warning("No relevant ASNs after filtering")
        return

    logger.info(f"Proceeding with {len(relevant_asns)} relevant ASNs")

    # --- get announced prefixes for relevant ASNs -------------------------
    matched_prefixes: Dict[str, Set[str]] = {}
    logger.info(f"Querying RIPEstat for announced prefixes of {len(relevant_asns)} ASNs")

    for asn in sorted(relevant_asns):
        prefixes = _get_announced_prefixes(asn, logger=logger)
        if prefixes:
            matched_prefixes[asn] = prefixes
            logger.info(f"  {asn}: {len(prefixes)} prefixes")
        else:
            logger.warning(f"  {asn}: no prefixes found (RIPEstat + PeeringDB both empty)")
        time.sleep(0.3)  # gentle rate limit on RIPEstat

    # --- also try to get holder names for better metadata -----------------
    for asn in sorted(relevant_asns):
        holder = _get_asn_holder(asn, logger=logger)
        if holder:
            logger.info(f"  {asn} holder: {holder}")

    total_prefix_ips = sum(len(p) for p in matched_prefixes.values())
    logger.info(f"Total announced prefixes: {len(matched_prefixes)} ({total_prefix_ips} IPs)")

    # --- save results -----------------------------------------------------
    _save_results(asn_map, matched_prefixes, output_dir, logger, target=target)

    asn_json_file = Path(output_dir) / "asn_results.json"
    logger.success(
        f"ASN recon complete: {len(relevant_asns)} ASNs, "
        f"{len(matched_prefixes)} prefix groups → {asn_json_file}"
    )

    # --- AI report -------------------------------------------------------
    # Read back the saved JSON for the report
    report_lines = []
    if asn_json_file.exists():
        try:
            with open(asn_json_file, "r", encoding="utf-8") as fh:
                asn_data = json.load(fh)
            for entry in asn_data.get("asns", []):
                report_lines.append(
                    f"ASN={entry['asn']} ORG={entry['as_name']} "
                    f"ORIGIN={','.join(entry.get('origin_ips', []))} "
                    f"PREFIXES={','.join(entry['prefixes'])}"
                )
        except Exception:
            pass
    generate_ai_report(
        module_name="ASN Recon",
        data="\n".join(report_lines) if report_lines else "No ASN data found.",
        target=target,
    )
