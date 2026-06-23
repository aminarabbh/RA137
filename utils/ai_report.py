"""
AI-powered report generation and PDF export for RA137.

Features:
- Lazy OpenAI client initialisation (no import-time crash)
- Target-scoped report storage and retrieval
- Markdown-aware PDF rendering via fpdf2
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from utils.config import get_config
from utils.database import save_report, get_reports_for_target
from utils.logger import get_logger

_log = get_logger("AI-REPORT")


# ---------------------------------------------------------------------------
# Lazy AI client
# ---------------------------------------------------------------------------

_client = None
_model: Optional[str] = None
_client_built = False


def _build_client():
    """
    Lazily build an OpenAI-compatible client.

    Returns ``(client, model_name)`` or ``(None, None)`` if the provider
    is not configured or the ``openai`` package is not installed.
    """
    global _client, _model, _client_built

    if _client_built:
        return _client, _model

    _client_built = True
    config = get_config()
    provider = config.ai.provider.lower()

    try:
        from openai import OpenAI
    except ImportError:
        _log.warning("openai package not installed – AI reports disabled (pip install openai)")
        return None, None

    if provider == "ollama":
        base_url = config.ai.base_url or "http://localhost:11434/v1"
        model = config.ai.model or "llama3"
        _client = OpenAI(base_url=base_url, api_key="ollama")
        _model = model
        return _client, _model

    # Default: OpenAI (or compatible)
    api_key = config.ai.api_key
    if not api_key:
        _log.info("AI API key not set – AI reports disabled")
        return None, None

    kwargs = {"api_key": api_key}
    if config.ai.base_url:
        kwargs["base_url"] = config.ai.base_url
    _client = OpenAI(**kwargs)
    _model = config.ai.model or "gpt-4.1-mini"
    return _client, _model


# ---------------------------------------------------------------------------
# Module prompts
# ---------------------------------------------------------------------------

MODULE_PROMPTS = {
    "Subdomain Enumeration": """
    This output contains the results of subdomain enumeration for the target domain.
    Each line is a discovered subdomain. Analyze: total subdomain count, naming patterns
    (dev/staging/api/internal), wildcard entries, attack surface breadth,
    and security significance. Highlight any sensitive or unusual subdomains.
    """,

    "IP Extraction": """
    This output lists IP addresses extracted from DNS resolution (dnsx) and HTTP probing (httpx)
    of discovered subdomains. Each line is a unique valid IP.
    Analyze: total IP count, infrastructure size, signs of load balancing or CDN usage,
    IP ranges suggesting cloud/hosting providers, and security implications
    of the exposed infrastructure footprint.
    """,

    "CDN Analysis": """
    This output contains CDN, Cloud, and Hosting provider classification results.
    Each line follows the format: IP | category | provider | CIDR_range
    Categories include: cdn, cloud, hosting, direct.
    Analyze: how many IPs are behind CDN vs exposed directly, which providers dominate,
    whether cloud/hosting IPs suggest origin infrastructure, and implications
    for further reconnaissance targeting unprotected assets.
    """,

    "Certificate Discovery": """
    This output contains SSL/TLS certificate analysis results from scanning IP ranges.
    Each MATCH line shows: IP, port, Common Name (CN), and Subject Alternative Names (SAN).
    Analyze: related domains found in certificates, hidden assets revealed via SAN,
    wildcard certificates that expose broad infrastructure, certificate leakage
    from unrelated domains, and potential for discovering additional attack surface.
    """,

    "Real IP Discovery": """
    This output contains origin IP discovery results for CDN-protected targets.
    Each line follows the format: IP=x score=y cert=match vhost=match body=match
    The score is based on: favicon(1) + jarm(2) + body(3) + vhost(4) + cert(5).
    IPs are accepted when cert or vhost matches, or combined score >= 4.
    Analyze: how many origin IPs were confirmed, which fingerprinting signals
    were most effective, confidence distribution, and indicators of
    unprotected infrastructure behind the CDN.
    """,

    "ASN Recon": """
    This output contains ASN and IP-range reconnaissance results.
    Each line follows the format: ASN=ASxxxxx ORG=organization_name ORIGIN=ip PREFIXES=cidr1,cidr2,...
    Analyze: which ASNs are associated with the target organization, the breadth of
    announced network prefixes, whether ASN expansion reveals additional infrastructure
    not found by other modules, org-name filtering effectiveness,
    and shadow infrastructure indicators.
    """,

    "Final IP Aggregation": """
    This output contains the final aggregated results from all reconnaissance modules.
    It includes: total IP count, total CIDR range count, per-source breakdown,
    individual IPs, and CIDR ranges.
    Analyze: total unique IPs discovered across all modules, which discovery source
    contributed the most, infrastructure footprint assessment, overlap between sources,
    and prioritisation recommendations for vulnerability scanning.
    """,

    "Tech Detection": """
    This output contains technology detection results from httpx probing.
    Each line is an httpx result with target URL, status code, title, web server,
    technologies detected, and WAF information.
    Analyze: identified web servers and frameworks, WAF presence and type,
    default pages suggesting misconfiguration, outdated technologies
    with known vulnerabilities, and technology stack security posture.
    """,

    "Network Discovery": """
    This output contains network intelligence gathering from multiple sources.
    Sections include: NMAP (host, port/service), SHODAN (IP, ports list),
    FOFA (IP, ports list), CENSYS (IP, services list), SECURITYTRAILS (IP, domains).
    Analyze: open ports and services per IP, cross-source corroboration,
    associated hosts/domains, notable banners and service versions,
    overall network exposure, and potential entry points.
    """,

    "Nuclei Scan": """
    This output contains automated vulnerability scanning results using Nuclei.
    Each finding follows the format: [template-id] [severity] [type] matched-at
    Analyze: total vulnerability count, severity distribution (critical/high/medium/low),
    most common vulnerability templates, affected endpoints,
    and prioritised remediation recommendations based on severity and exploitability.
    """,
}


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_ai_report(module_name: str, data: str, target: str = "") -> Optional[str]:
    """
    Generate an AI-powered analysis report for a module's output.

    Parameters
    ----------
    module_name : str
        Name of the reconnaissance module.
    data : str
        Raw module output to analyse.
    target : str
        Target domain (for DB scoping).

    Returns
    -------
    str or None
        The AI-generated report text, or None on failure.
    """
    client, model = _build_client()

    if client is None:
        _log.info(f"AI not configured – skipping report for {module_name}")
        return None

    module_prompt = MODULE_PROMPTS.get(
        module_name,
        "Analyse the following reconnaissance output and provide a concise "
        "security assessment in a few short paragraphs."
    )

    prompt = f"{module_prompt}\n\nOutput:\n{data}"

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
        )
        report = response.choices[0].message.content.strip()
        save_report(module_name, report, target=target)
        return report

    except Exception as exc:
        _log.error(f"AI report generation failed for {module_name}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Lightweight AI validation (for ASN / RealIP filtering)
# ---------------------------------------------------------------------------

def ai_validate(prompt: str, temperature: float = 0.1) -> str:
    """
    Lightweight AI call for result validation / classification.

    Used by modules that need the AI to make quick yes/no decisions
    about individual results (e.g. "is this ASN related to the target?",
    "is this IP a real origin IP?").

    Parameters
    ----------
    prompt : str
        Concise validation prompt.  Keep short to save tokens.
    temperature : float
        Low temperature for deterministic classification.

    Returns
    -------
    str
        Raw AI response text, or empty string on failure.
    """
    client, model = _build_client()
    if client is None:
        _log.info("AI not configured – skipping validation")
        return ""

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=2000,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        _log.error(f"AI validation call failed: {exc}")
        return ""


# ---------------------------------------------------------------------------
# PDF Report Generation
# ---------------------------------------------------------------------------

def generate_pdf_report(target: str, output_dir: Path) -> Optional[Path]:
    """
    Generate a combined PDF report from all AI-generated module reports
    for a specific target.

    Parameters
    ----------
    target : str
        Target domain name (used as the report title and DB filter).
    output_dir : Path
        Per-target output directory where the PDF will be saved.

    Returns
    -------
    Path or None
        Path to the generated PDF, or None on failure.
    """
    try:
        from fpdf import FPDF
    except ImportError:
        _log.warning("fpdf2 not installed – skipping PDF generation (pip install fpdf2)")
        return None

    reports = get_reports_for_target(target)
    if not reports:
        _log.info(f"No AI reports found for target '{target}' – skipping PDF")
        return None

    pdf_path = Path(output_dir) / "ai_report.pdf"

    try:
        pdf = FPDF(orientation="P", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=15)

        # Register DejaVu fonts for Unicode support
        _font_dir = "/usr/share/fonts/truetype/dejavu"
        _regular = f"{_font_dir}/DejaVuSans.ttf"
        _bold = f"{_font_dir}/DejaVuSans-Bold.ttf"

        _use_unicode = False
        if Path(_regular).exists():
            pdf.add_font("DejaVu", "", _regular)
            if Path(_bold).exists():
                pdf.add_font("DejaVu", "B", _bold)
            _use_unicode = True
        else:
            _log.warning("DejaVu fonts not found – falling back to Helvetica")

        _font = "DejaVu" if _use_unicode else "Helvetica"

        pdf.add_page()

        # --- Title page ---------------------------------------------------
        pdf.set_font(_font, "B" if _use_unicode else "", 22)
        pdf.ln(40)
        pdf.cell(0, 12, "RA137 Reconnaissance Report",
                 new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(8)
        pdf.set_font(_font, "", 14)
        pdf.cell(0, 10, f"Target: {target}",
                 new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(4)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                 new_x="LMARGIN", new_y="NEXT", align="C")

        # --- Module sections ----------------------------------------------
        for module_name, content in reports:
            pdf.add_page()

            # Section heading
            pdf.set_font(_font, "B" if _use_unicode else "", 16)
            pdf.set_fill_color(41, 128, 185)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(0, 10, f"  {module_name}",
                     new_x="LMARGIN", new_y="NEXT", fill=True)
            pdf.ln(4)

            # Section body
            pdf.set_text_color(0, 0, 0)
            pdf.set_font(_font, "", 10)

            def _safe_multi_cell(w, h, text):
                """Render text with fallback if width is too narrow."""
                pdf.set_x(pdf.l_margin)  # always reset to left margin
                try:
                    pdf.multi_cell(w, h, text)
                except Exception:
                    # Truncate or skip problematic lines
                    try:
                        pdf.set_x(pdf.l_margin)
                        pdf.multi_cell(w, h, text[:80] + "...")
                    except Exception:
                        pass

            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                if line.startswith("## "):
                    pdf.set_font(_font, "B" if _use_unicode else "", 12)
                    pdf.ln(3)
                    _safe_multi_cell(0, 6, line[3:])
                    pdf.set_font(_font, "", 10)
                    pdf.ln(2)
                elif line.startswith("# "):
                    pdf.set_font(_font, "B" if _use_unicode else "", 14)
                    pdf.ln(4)
                    _safe_multi_cell(0, 7, line[2:])
                    pdf.set_font(_font, "", 10)
                    pdf.ln(2)
                elif line.startswith("- ") or line.startswith("* "):
                    _safe_multi_cell(0, 5, f"  - {line[2:]}")
                else:
                    _safe_multi_cell(0, 5, line)

            pdf.ln(4)

        pdf.output(str(pdf_path))
        _log.success(f"PDF report generated: {pdf_path}")
        return pdf_path

    except Exception as exc:
        _log.error(f"PDF report generation failed: {exc}")
        return None
