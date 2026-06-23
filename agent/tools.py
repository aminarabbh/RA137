"""
Tool registry — wraps each RA137 module as an AI-callable tool.

Provides:
- TOOLS: OpenAI function-calling schema for all 10 recon modules + read_results + scan_complete
- ToolExecutor: runs tools against a specific scan directory
"""

import json
from pathlib import Path
from typing import List

from utils.paths import create_target_output, generate_scan_id
from utils.config import get_config
from utils.logger import get_logger

_log = get_logger("AGENT-TOOLS")


# ---------------------------------------------------------------------------
# Tool definitions (OpenAI function-calling schema for the LLM)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "subdomain_enum",
        "description": (
            "Enumerate subdomains for a target domain using subfinder and gobuster. "
            "Returns a JSON file with all discovered subdomains. "
            "Always run this first as all other modules depend on it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain (e.g. example.com)",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "ip_extractor",
        "description": (
            "Resolve subdomains to IP addresses using dnsx and httpx, "
            "then extract and validate all discovered IPs. "
            "Requires subdomain_enum to have run first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "check_cdn",
        "description": (
            "Classify IPs as CDN/Cloud/Hosting/Direct. "
            "Identifies which IPs are behind CDN and which are directly exposed. "
            "Requires ip_extractor to have run first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "cert_discovery",
        "description": (
            "Scan SSL/TLS certificates on IP ranges to discover related domains "
            "via CN and SAN fields. Expands IPs to /24 subnets. "
            "Requires check_cdn to have run first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "realip_discovery",
        "description": (
            "Discover origin IPs hidden behind CDN using fingerprinting "
            "(favicon hash, JARM, SSL certs, vhost, body similarity, CNAME, DNS history). "
            "Requires check_cdn. Skip if cdn_analysis.json shows zero CDN IPs."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "asn_recon",
        "description": (
            "Identify ASN and IP ranges belonging to the target using ipinfo.io "
            "and RIPEstat. Finds additional infrastructure via org-name matching. "
            "Requires check_cdn or realip_discovery to have run."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "final_ip_builder",
        "description": (
            "Aggregate ALL discovered IPs from every module into a final deduplicated list. "
            "Should be run after discovery modules (check_cdn, cert_discovery, realip_discovery, asn_recon). "
            "Reads from cdn_analysis, realip_results, asn_results, cert_discovery, and pure_ip JSON files."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "tech_detection",
        "description": (
            "Detect web technologies, servers, and WAF using httpx. "
            "Requires final_ip_builder to have run first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "network_discovery",
        "description": (
            "Gather network intelligence: nmap port scanning, Shodan/FOFA/Censys/SecurityTrails "
            "lookups. Requires final_ip_builder to have run first."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vuln_check",
        "description": (
            "Run nuclei vulnerability scanner against all discovered IPs and open ports. "
            "Requires final_ip_builder. Ideally run after network_discovery for port-aware scanning."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target domain",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "read_results",
        "description": (
            "Read and return the contents of a JSON output file from the current scan. "
            "Use this to analyze results before deciding next steps. "
            "Common files: subdomains.json, pure_ip.json, cdn_analysis.json, "
            "cert_discovery.json, realip_results.json, asn_results.json, "
            "final_ips.json, tech_results.json, network_results.json, vuln_results.json."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "JSON filename to read (e.g. cdn_analysis.json)",
                },
            },
            "required": ["filename"],
        },
    },
    {
        "name": "scan_complete",
        "description": (
            "Signal that the scan is complete and generate the final PDF report. "
            "Call this when all desired modules have been executed and you have "
            "provided your analysis summary to the user."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
]


# ---------------------------------------------------------------------------
# Tool executor
# ---------------------------------------------------------------------------

class ToolExecutor:
    """Executes tools against a specific scan directory."""

    def __init__(self, target: str, scan_dir: Path):
        self.target = target
        self.scan_dir = scan_dir
        self.completed_steps: List[str] = []

    # ------------------------------------------------------------------
    # Internal: import and run each module
    # ------------------------------------------------------------------

    def _import_and_run(self, tool_name: str) -> str:
        """Lazy-import and run a module, returning a summary string."""
        target = self.target
        output_dir = self.scan_dir

        if tool_name == "subdomain_enum":
            from modules.subdomain_enum import collect_subdomains
            result = collect_subdomains(
                domain=target,
                wordlist_path="wordlists/subdomains.txt",
                output_dir=output_dir,
                target=target,
            )
            self.completed_steps.append(tool_name)
            return f"Subdomain enum complete: {len(result)} subdomains found. Output: subdomains.json"

        elif tool_name == "ip_extractor":
            from modules.ip_extractor import collect_ips
            result = collect_ips(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            return f"IP extraction complete: {len(result)} IPs found. Output: pure_ip.json"

        elif tool_name == "check_cdn":
            from modules.check_cdn import filter_non_cdn_ips
            result = filter_non_cdn_ips(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            return (
                f"CDN check complete: {len(result['direct_ips'])} direct, "
                f"{len(result['cdn_ips'])} CDN, {len(result['cloud_ips'])} cloud, "
                f"{len(result['hosting_ips'])} hosting. "
                f"Outputs: cdn_analysis.json, direct_ips.json"
            )

        elif tool_name == "cert_discovery":
            from modules.cert_discovery import cert_discovery
            cert_discovery(target=target, output_dir=output_dir)
            self.completed_steps.append(tool_name)
            cert_file = output_dir / "cert_discovery.json"
            if cert_file.exists():
                data = json.loads(cert_file.read_text())
                return f"Cert discovery complete: {data.get('total', 0)} certificate matches. Output: cert_discovery.json"
            return "Cert discovery complete. Output: cert_discovery.json"

        elif tool_name == "realip_discovery":
            from modules.realip_discovery import real_ip_discovery
            result = real_ip_discovery(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            return f"Real IP discovery complete: {len(result)} unique origin IPs found. Output: realip_results.json"

        elif tool_name == "asn_recon":
            from modules.asn_recon import asn_recon
            asn_recon(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            asn_file = output_dir / "asn_results.json"
            if asn_file.exists():
                data = json.loads(asn_file.read_text())
                return (
                    f"ASN recon complete: {data.get('total_asns', 0)} ASNs, "
                    f"{data.get('total_origin_ips', 0)} origin IPs, "
                    f"{data.get('total_cidr_ranges', 0)} CIDR ranges. "
                    f"Output: asn_results.json"
                )
            return "ASN recon complete. Output: asn_results.json"

        elif tool_name == "final_ip_builder":
            from modules.final_ip_builder import build_final_ips
            result = build_final_ips(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            return f"Final IP aggregation complete: {len(result)} unique IPs. Output: final_ips.json"

        elif tool_name == "tech_detection":
            from modules.tech_detect import tech_detection
            tech_detection(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            return "Tech detection complete. Output: tech_results.json"

        elif tool_name == "network_discovery":
            from modules.network_discovery import network_discovery
            result = network_discovery(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            sources = result.get("sources", {})
            total = sum(sources.values())
            breakdown = ", ".join(f"{k}: {v}" for k, v in sources.items() if v)
            return f"Network discovery complete: {total} findings ({breakdown}). Output: network_results.json"

        elif tool_name == "vuln_check":
            from modules.vuln_check import nuclei_scan
            result = nuclei_scan(output_dir=output_dir, target=target)
            self.completed_steps.append(tool_name)
            return f"Vulnerability scan complete: {len(result)} findings. Output: vuln_results.json"

        elif tool_name == "scan_complete":
            from utils.ai_report import generate_pdf_report
            pdf = generate_pdf_report(self.target, self.scan_dir)
            pdf_path = str(pdf) if pdf else "not generated"
            return (
                f"Scan complete for {self.target}.\n"
                f"Steps completed: {', '.join(self.completed_steps)}\n"
                f"PDF report: {pdf_path}\n"
                f"Scan directory: {self.scan_dir}"
            )

        return f"Unknown tool: {tool_name}"

    # ------------------------------------------------------------------
    # Public: execute any tool
    # ------------------------------------------------------------------

    def execute(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool and return the result as a string."""
        _log.info(f"Executing tool: {tool_name}({arguments})")

        # Special handling for read_results
        if tool_name == "read_results":
            return self._handle_read_results(arguments)

        try:
            result = self._import_and_run(tool_name)
            _log.info(f"Tool result: {result[:200]}")
            return result
        except Exception as exc:
            _log.error(f"Tool {tool_name} failed: {exc}")
            return f"ERROR running {tool_name}: {exc}"

    def _handle_read_results(self, arguments: dict) -> str:
        """Read a JSON file from the scan directory."""
        filename = arguments.get("filename", "")
        if not filename:
            return "ERROR: filename is required"

        filepath = self.scan_dir / filename
        if not filepath.exists():
            available = self._list_files()
            return f"File not found: {filename}. Available JSON files: {available}"

        try:
            content = filepath.read_text(encoding="utf-8")
            # Truncate large files to protect LLM context window
            max_chars = 8000
            if len(content) > max_chars:
                return (
                    content[:max_chars]
                    + f"\n... [TRUNCATED: file is {len(content)} chars total. "
                    f"Focus on the key fields: metadata, total/summary, and key results.]"
                )
            return content
        except Exception as exc:
            return f"ERROR reading {filename}: {exc}"

    def _list_files(self) -> str:
        """List available JSON files in scan dir."""
        files = [f.name for f in self.scan_dir.glob("*.json") if not f.name.startswith(".")]
        return ", ".join(sorted(files)) if files else "(no JSON files yet)"
