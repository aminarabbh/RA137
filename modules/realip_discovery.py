"""
Real-IP discovery module for RA137.

Consumes CDN analysis output to prioritise CDN-protected subdomains,
then attempts origin-IP discovery using multiple fingerprinting
techniques (favicon hash, JARM, SSL certificates, vhost probing,
body similarity, CNAME chains, DNS history).

Supports Shodan, FOFA, Censys, and SecurityTrails APIs.

Outputs
-------
* ``outputs/realip/realip_results.json`` – structured results
* ``realip.txt`` (per-target) – legacy JSON-lines format
"""

import base64
import difflib
import ipaddress
import json
import random
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

import mmh3
from bs4 import BeautifulSoup

try:
    import jarm
except ImportError:
    jarm = None  # type: ignore[assignment]

try:
    import dns.resolver
except ImportError:
    dns = None  # type: ignore[assignment]

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from utils.config import get_config
from utils.logger import Logger, get_logger
from utils.http_session import get_session, get_insecure_session, api_cache
from utils.ip_utils import is_valid_ip, load_ips_from_json, load_subdomains_from_json
from utils.ai_report import generate_ai_report, ai_validate
from utils.paths import build_metadata

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SSL_PORTS = [443, 4443, 7443, 8443, 9443, 10443]

COMMON_SHARED_CERTS = [
    "cloudflare", "akamai", "fastly", "imperva",
    "amazon", "amazonaws", "edgekey", "cdn",
]

COMMON_SHARED_VHOSTS = [
    "outlook", "exchange", "owa", "autodiscover",
    "cpanel", "plesk", "webmail",
]

MAX_RESULTS = 500


def _rate_limit(lo: float = 1.0, hi: float = 3.0) -> None:
    time.sleep(random.uniform(lo, hi))


# ---------------------------------------------------------------------------
# CDN helpers (consume check_cdn output)
# ---------------------------------------------------------------------------

def _load_cdn_analysis(output_dir: Path, logger: Logger) -> Dict:
    """Load CDN analysis JSON produced by check_cdn module."""
    cdn_json = Path(output_dir) / "cdn_analysis.json"
    if cdn_json.exists():
        try:
            with open(cdn_json, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning(f"Failed to load CDN analysis: {exc}")
    return {}


def _get_protected_subdomains(
    cdn_data: Dict,
    all_subdomains: List[str],
    pure_ips: Set[str],
) -> Set[str]:
    """
    Return the set of subdomains whose IPs are behind CDN/cloud/hosting.

    Simple heuristic: if *all* resolved IPs for the domain are in the
    CDN set, the subdomain is considered "protected".
    """
    cdn_ip_set: Set[str] = set()
    for category in ("cdn_ips", "cloud_ips", "hosting_ips"):
        for entry in cdn_data.get(category, []):
            cdn_ip_set.add(entry.get("ip", ""))

    # We don't have a per-subdomain→IP mapping here, so just return
    # all subdomains when *any* IP is CDN-protected (caller decides
    # priority ordering).
    if cdn_ip_set & pure_ips:
        return set(all_subdomains)
    return set()


# ---------------------------------------------------------------------------
# Fingerprinting helpers
# ---------------------------------------------------------------------------

def _get_favicon_hash(url: str) -> Optional[int]:
    try:
        sess = get_insecure_session()
        _rate_limit()
        resp = sess.get(url, timeout=10)
        if resp.status_code != 200:
            return None

        soup = BeautifulSoup(resp.text, "html.parser")
        favicon_url = None
        for tag_attrs in [{"rel": "icon"}, {"rel": "shortcut icon"},
                          {"rel": "apple-touch-icon"}]:
            target_rel = tag_attrs["rel"]
            tag = soup.find("link", rel=lambda x: bool(x) and target_rel in [v.lower() for v in x])
            if tag and tag.get("href"):
                favicon_url = tag["href"]
                break

        if not favicon_url:
            for path in ["/favicon.ico", "/favicon.png", "/apple-touch-icon.png"]:
                test_url = urljoin(url, path)
                try:
                    _rate_limit()
                    r = sess.head(test_url, timeout=5)
                    if r.status_code == 200:
                        favicon_url = path
                        break
                except Exception:
                    continue

        if not favicon_url:
            return None

        full_url = urljoin(url, favicon_url)
        _rate_limit()
        fr = sess.get(full_url, timeout=10)
        if fr.status_code != 200:
            return None

        return mmh3.hash(base64.encodebytes(fr.content))
    except Exception:
        return None


def _get_ssl_domains(ip: str, port: int = 443) -> Set[str]:
    result: Set[str] = set()
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=None) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if not der:
            return result
        cert = x509.load_der_x509_certificate(der, default_backend())
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            result.add(cn.lower())
        except Exception:
            pass
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            for s in san.value.get_values_for_type(x509.DNSName):
                result.add(s.lower())
        except Exception:
            pass
    except Exception:
        pass
    return result


def _is_subdomain(sub: str, parent: str) -> bool:
    sub = sub.lower().rstrip(".")
    parent = parent.lower().rstrip(".")
    return sub == parent or sub.endswith("." + parent)


def _check_certificate_match(ip: str, target: str) -> bool:
    for port in SSL_PORTS:
        domains = _get_ssl_domains(ip, port)
        for d in domains:
            if _is_subdomain(d, target):
                if not any(c in d for c in COMMON_SHARED_CERTS):
                    return True
    return False


def _check_vhost_match(ip: str, target: str) -> bool:
    try:
        _rate_limit()
        resp = get_insecure_session().get(
            f"https://{ip}",
            headers={"Host": target},
            timeout=8,
        )
        text = resp.text.lower()
        if target.lower() in text:
            if not any(v in text for v in COMMON_SHARED_VHOSTS):
                return True
    except Exception:
        pass
    return False


def _check_body_similarity(ip: str, target: str) -> bool:
    try:
        sess = get_insecure_session()
        _rate_limit()
        r1 = sess.get(f"https://{target}", timeout=10, allow_redirects=True)
        _rate_limit()
        r2 = sess.get(f"https://{ip}", headers={"Host": target}, timeout=10, allow_redirects=True)
        if r1.status_code != 200 or r2.status_code != 200:
            return False
        ratio = difflib.SequenceMatcher(None, r1.text[:5000], r2.text[:5000]).ratio()
        return ratio >= 0.6
    except Exception:
        return False


def _get_jarm(host: str) -> List[str]:
    if jarm is None:
        return []
    hashes: Set[str] = set()
    for port in SSL_PORTS:
        try:
            result = jarm.Scanner.scan(host, port)
            if result and result != "0" * 62:
                hashes.add(result)
        except Exception:
            pass
    return list(hashes)


def _get_cname_ips(domain: str) -> Set[str]:
    results: Set[str] = set()
    if dns is None:
        return results
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname = str(rdata.target).rstrip(".")
            try:
                for a in dns.resolver.resolve(cname, "A"):
                    results.add(str(a))
            except Exception:
                pass
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# API searches (Shodan, FOFA, Censys, SecurityTrails)
# ---------------------------------------------------------------------------

def _shodan_search(query: str, logger: Logger) -> Set[str]:
    config = get_config()
    key = config.api_keys.shodan_api_key
    if not key:
        return set()
    cache_key = f"shodan:{query}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached  # type: ignore[return-value]
    results: Set[str] = set()
    offset = 0
    sess = get_session()
    try:
        while len(results) < MAX_RESULTS:
            _rate_limit()
            url = "https://api.shodan.io/shodan/host/search"
            data = sess.get(url, params={"key": key, "query": query, "offset": offset}, timeout=20).json()
            matches = data.get("matches", [])
            if not matches:
                break
            for m in matches:
                ip = m.get("ip_str")
                if ip and is_valid_ip(ip):
                    results.add(ip)
            total = data.get("total", len(matches))
            offset += len(matches)
            if offset >= total:
                break
    except Exception as exc:
        logger.error(f"Shodan error: {exc}")
    api_cache.put(cache_key, results)
    return results


def _fofa_search(query: str, logger: Logger) -> Set[str]:
    config = get_config()
    email, key = config.api_keys.fofa_email, config.api_keys.fofa_api_key
    if not email or not key:
        return set()
    cache_key = f"fofa:{query}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached  # type: ignore[return-value]
    results: Set[str] = set()
    page = 1
    sess = get_session()
    try:
        q64 = base64.b64encode(query.encode()).decode()
        while len(results) < MAX_RESULTS:
            _rate_limit()
            url = f"https://fofa.info/api/v1/search/all?email={email}&key={key}&qbase64={q64}&page={page}&fields=ip"
            data = sess.get(url, timeout=20).json()
            items = data.get("results", [])
            if not items:
                break
            for item in items:
                # FOFA returns list or tuple; IP is first field when fields=ip
                ip = item[0] if isinstance(item, (list, tuple)) and item else None
                if ip and is_valid_ip(ip):
                    results.add(ip)
            total = data.get("size", len(items))
            if page * len(items) >= total:
                break
            page += 1
    except Exception as exc:
        logger.error(f"FOFA error: {exc}")
    api_cache.put(cache_key, results)
    return results


def _censys_search(query: str, logger: Logger) -> Set[str]:
    config = get_config()
    cid_, csec = config.api_keys.censys_api_id, config.api_keys.censys_api_secret
    if not cid_ or not csec:
        return set()
    cache_key = f"censys:{query}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached  # type: ignore[return-value]
    results: Set[str] = set()
    cursor = None
    sess = get_session()
    try:
        while len(results) < MAX_RESULTS:
            _rate_limit()
            payload: dict = {"q": query, "per_page": 100}
            if cursor:
                payload["cursor"] = cursor
            resp = sess.post(
                "https://search.censys.io/api/v2/hosts/search",
                auth=(cid_, csec),
                json=payload,
                timeout=20,
            )
            data = resp.json()
            hits = data.get("result", {}).get("hits", [])
            if not hits:
                break
            for h in hits:
                ip = h.get("ip")
                if ip and is_valid_ip(ip):
                    results.add(ip)
            cursor = data.get("result", {}).get("links", {}).get("next")
            if not cursor:
                break
    except Exception as exc:
        logger.error(f"Censys error: {exc}")
    api_cache.put(cache_key, results)
    return results


def _securitytrails_history(domain: str, logger: Logger) -> Set[str]:
    config = get_config()
    key = config.api_keys.securitytrails_api_key
    if not key:
        return set()
    cache_key = f"securitytrails:{domain}"
    cached = api_cache.get(cache_key)
    if cached is not None:
        return cached  # type: ignore[return-value]
    results: Set[str] = set()
    sess = get_session()
    try:
        _rate_limit()
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        resp = sess.get(url, headers={"APIKEY": key, "Accept": "application/json"}, timeout=20)
        if resp.status_code == 200:
            for rec in resp.json().get("records", []):
                for val in rec.get("values", []):
                    ip = val.get("ip")
                    if ip and is_valid_ip(ip):
                        results.add(ip)
    except Exception as exc:
        logger.error(f"SecurityTrails error: {exc}")
    api_cache.put(cache_key, results)
    return results


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

def _build_queries(favicon_hash: Optional[int], jarm_hashes: List[str]) -> List[dict]:
    queries: List[dict] = []
    if favicon_hash:
        queries.append({
            "type": "favicon",
            "shodan": f"http.favicon.hash:{favicon_hash}",
            "fofa": f'icon_hash="{favicon_hash}"',
            "censys": f"services.http.response.favicons.mmh3_hash:{favicon_hash}",
        })
    for jh in jarm_hashes:
        if jh:
            queries.append({
                "type": "jarm",
                "shodan": f"ssl.jarm:{jh}",
                "fofa": None,
                "censys": f"services.jarm.fingerprint:{jh}",
            })
    return queries


# ---------------------------------------------------------------------------
# Validation / scoring
# ---------------------------------------------------------------------------

def _validate_real_ip(
    ip: str,
    target: str,
    *,
    favicon: bool = False,
    cert: bool = False,
    vhost: bool = False,
    jarm_m: bool = False,
    body: bool = False,
) -> tuple:
    score = 0
    if favicon:
        score += 1
    if jarm_m:
        score += 2
    if body:
        score += 3
    if vhost:
        score += 4
    if cert:
        score += 5
    # Accept if: any single strong signal (cert=5 or vhost=4),
    # or combined score >= 4 (e.g. body(3)+favicon(1), jarm(2)+favicon(1)+body(3))
    is_valid = cert or vhost or score >= 4
    return is_valid, score


# ---------------------------------------------------------------------------
# AI validation helper
# ---------------------------------------------------------------------------

def _ai_validate_real_ips(
    candidates: List[dict],
    target: str,
    logger: Logger,
) -> Optional[List[dict]]:
    """
    Use AI to validate origin-IP candidates and filter false positives.

    Each candidate has scoring signals (cert_match, vhost_match, body_match,
    score, matched_by).  The AI reviews these and confirms which are likely
    genuine origin IPs for the target.

    Parameters
    ----------
    candidates : list[dict]
        Deduplicated candidate results from the scoring pipeline.
    target : str
        Target domain name.
    logger : Logger

    Returns
    -------
    list[dict] or None
        Filtered list of confirmed candidates, or ``None`` if AI call failed.
    """
    logger.info(f"AI validating {len(candidates)} origin-IP candidates for '{target}'")

    # Build concise candidate summaries for the AI
    lines = []
    for i, c in enumerate(candidates):
        signals = []
        if c.get("cert_match"):
            signals.append("cert")
        if c.get("vhost_match"):
            signals.append("vhost")
        if c.get("body_match"):
            signals.append("body")
        matched_by = c.get("matched_by", [])
        lines.append(
            f"{i}: ip={c['ip']} target={c['target']} score={c['score']} "
            f"signals=[{','.join(signals)}] found_via=[{','.join(matched_by)}]"
        )

    prompt = (
        f"You are validating origin-IP discovery results for target domain "
        f"\"{target}\".\n\n"
        f"Each candidate IP was scored based on signals from CDN-bypass "
        f"fingerprinting:\n"
        f"- cert (5pts): SSL certificate mentions target domain\n"
        f"- vhost (4pts): HTTP vhost probing returns target content\n"
        f"- body (3pts): Response body similarity to target >= 60%\n"
        f"- jarm (2pts): JARM TLS fingerprint match\n"
        f"- favicon (1pt): Favicon hash match\n\n"
        f"Accept candidates that have at least one strong signal (cert or "
        f"vhost) OR a combined score >= 4. Reject false positives.\n\n"
        f"Candidates:\n" + "\n".join(lines) + "\n\n"
        f"Respond with ONLY a JSON array of accepted candidate index numbers, "
        f"e.g. [0, 2, 5]. If all are valid, return all indices."
    )

    response = ai_validate(prompt)
    if not response:
        logger.warning("AI validation returned empty response – using scoring only")
        return None

    try:
        start = response.find("[")
        end = response.rfind("]")
        if start != -1 and end != -1:
            json_str = response[start:end + 1]
            indices = json.loads(json_str)
            valid_indices = {
                int(i) for i in indices
                if isinstance(i, (int, float)) and 0 <= int(i) < len(candidates)
            }
            approved = [candidates[i] for i in sorted(valid_indices)]
            logger.info(f"AI confirmed {len(approved)}/{len(candidates)} candidates")
            for i in sorted(valid_indices):
                c = candidates[i]
                logger.info(f"  AI KEEP [{i}]: {c['ip']} (score={c['score']})")
            for i in range(len(candidates)):
                if i not in valid_indices:
                    c = candidates[i]
                    logger.info(f"  AI REJECT [{i}]: {c['ip']} (score={c['score']})")
            return approved
        else:
            logger.warning("AI response did not contain JSON array")
            return None
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.warning(f"Failed to parse AI validation response: {exc}")
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def real_ip_discovery(
    output_dir: Path,
    logger: Optional[Logger] = None,
    target: str = "",
) -> List[dict]:
    """
    Attempt to discover origin IPs hidden behind CDN / reverse-proxy.

    Parameters
    ----------
    output_dir : Path
        Per-target output directory.
    logger : Logger, optional

    Returns
    -------
    list[dict]
        Validated real-IP results.
    """
    if logger is None:
        logger = get_logger("REALIP")

    config = get_config()
    output_dir = Path(output_dir)
    logger.info("Starting real IP discovery")

    # --- load CDN analysis -----------------------------------------------
    cdn_data = _load_cdn_analysis(output_dir, logger)
    cdn_protected_count = sum(
        len(cdn_data.get(k, [])) for k in ("cdn_ips", "cloud_ips", "hosting_ips")
    )
    logger.info(f"CDN-protected IPs from prior step: {cdn_protected_count}")

    # --- load subdomains -------------------------------------------------
    subdomain_json = output_dir / "subdomains.json"
    if not subdomain_json.exists():
        logger.warning("subdomains.json not found – skipping")
        return []
    subdomains = load_subdomains_from_json(subdomain_json)
    if not subdomains:
        logger.warning("No subdomains loaded")
        return []

    # --- load pure IPs for protected-subdomain detection -----------------
    pure_ip_file = output_dir / "pure_ip.json"
    pure_ips: Set[str] = set()
    if pure_ip_file.exists():
        pure_ips = load_ips_from_json(pure_ip_file)

    protected = _get_protected_subdomains(cdn_data, subdomains, pure_ips)
    # Prioritise: protected first, then the rest
    ordered = sorted(protected) + sorted(set(subdomains) - protected)
    logger.info(f"Processing {len(ordered)} subdomains ({len(protected)} CDN-prioritised)")

    # --- process subdomains in parallel ----------------------------------
    all_results: List[dict] = []

    def _process(subdomain: str) -> List[dict]:
        logger.info(f"Fingerprinting {subdomain}")
        url = f"https://{subdomain}"
        favicon_hash = _get_favicon_hash(url)
        jarm_hashes = _get_jarm(subdomain)
        queries = _build_queries(favicon_hash, jarm_hashes)

        favicon_ips: Set[str] = set()
        jarm_ips: Set[str] = set()
        matched_by: List[str] = []

        for q in queries:
            qt = q["type"]
            if q.get("shodan"):
                r = _shodan_search(q["shodan"], logger)
                if r:
                    matched_by.append(f"shodan-{qt}")
                    (favicon_ips if qt == "favicon" else jarm_ips).update(r)
            if q.get("fofa"):
                r = _fofa_search(q["fofa"], logger)
                if r:
                    matched_by.append(f"fofa-{qt}")
                    (favicon_ips if qt == "favicon" else jarm_ips).update(r)
            if q.get("censys"):
                r = _censys_search(q["censys"], logger)
                if r:
                    matched_by.append(f"censys-{qt}")
                    (favicon_ips if qt == "favicon" else jarm_ips).update(r)

        cname_ips = _get_cname_ips(subdomain)
        history_ips = _securitytrails_history(subdomain, logger)

        candidates = favicon_ips | jarm_ips | cname_ips | history_ips
        target_results: List[dict] = []

        for ip in candidates:
            cert_m = _check_certificate_match(ip, subdomain)
            vhost_m = _check_vhost_match(ip, subdomain)
            body_m = _check_body_similarity(ip, subdomain)
            valid, score = _validate_real_ip(
                ip, subdomain,
                favicon=ip in favicon_ips,
                cert=cert_m,
                vhost=vhost_m,
                jarm_m=ip in jarm_ips,
                body=body_m,
            )
            if not valid:
                continue
            target_results.append({
                "target": subdomain,
                "ip": ip,
                "score": score,
                "cert_match": cert_m,
                "vhost_match": vhost_m,
                "body_match": body_m,
                "matched_by": list(set(matched_by)),
            })
        return target_results

    with ThreadPoolExecutor(max_workers=config.concurrency.cert_discovery_workers) as pool:
        futures = {pool.submit(_process, sub): sub for sub in ordered}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                all_results.extend(future.result())
            except Exception as exc:
                logger.error(f"Error processing {sub}: {exc}")

    # --- deduplicate by (target, ip) -------------------------------------
    seen: Set[tuple] = set()
    unique: List[dict] = []
    for r in all_results:
        key = (r["target"], r["ip"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    # --- AI validation of origin IP candidates (optional) ----------------
    if config.ai.ai_validation and len(unique) > 0:
        ai_approved = _ai_validate_real_ips(unique, target, logger)
        if ai_approved is not None:
            before = len(unique)
            unique = ai_approved
            logger.info(
                f"AI validation: {before} candidates → {len(unique)} confirmed origin IPs"
            )

    # --- save JSON output (flat, at scan root) -------------------------
    json_file = Path(output_dir) / "realip_results.json"
    payload = {
        "metadata": build_metadata("Real IP Discovery", target),
        "total": len(unique),
        "results": unique,
    }
    with open(json_file, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    logger.success(f"Real IP discovery: {len(unique)} unique results → {json_file}")

    # --- AI report -------------------------------------------------------
    report_lines = [
        f"IP={r['ip']} score={r['score']} cert={r['cert_match']} "
        f"vhost={r['vhost_match']} body={r['body_match']}"
        for r in unique
    ]
    generate_ai_report(
        module_name="Real IP Discovery",
        data="\n".join(report_lines) if report_lines else "No real IPs discovered.",
        target=target,
    )

    return unique
