"""
RA137 AI Agent — ReAct (Reason + Act) loop using OpenAI-compatible API.

The agent receives a target domain, decides which modules to run,
reads results between steps, and adapts its strategy based on findings.

Architecture:
    User target → LLM decides tool → ToolExecutor runs module →
    Result → LLM analyzes → LLM decides next tool → ... → scan_complete
"""

import json
from pathlib import Path
from typing import Optional

from utils.config import get_config
from utils.paths import create_target_output, generate_scan_id
from utils.logger import get_logger
from utils.database import init_db

from agent.tools import TOOLS, ToolExecutor

_log = get_logger("AGENT")


# ---------------------------------------------------------------------------
# System prompt — teaches the LLM how to be a recon agent
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are RA137, an AI-powered reconnaissance agent for offensive security and bug bounty hunting.

You have access to reconnaissance tools that you run sequentially against a target domain.
Your job is to:
1. Decide the optimal order of modules based on the target and previous results
2. Read key results between steps to make intelligent decisions
3. Skip unnecessary modules (e.g. skip realip_discovery if no CDN IPs found)
4. Provide a brief analysis after reading each result

AVAILABLE TOOLS AND THEIR DEPENDENCIES:
- subdomain_enum: Entry point. ALWAYS run first. Discovers subdomains.
- ip_extractor: Requires subdomain_enum. Resolves subdomains to IPs.
- check_cdn: Requires ip_extractor. Classifies IPs as CDN/Cloud/Hosting/Direct.
- cert_discovery: Requires check_cdn. Finds related domains via SSL certificates.
- realip_discovery: Requires check_cdn. SKIP if cdn_analysis shows 0 CDN IPs. Finds origin IPs behind CDN.
- asn_recon: Requires check_cdn or realip_discovery. Finds org infrastructure via ASN.
- final_ip_builder: Requires discovery modules done. Aggregates ALL IPs into final list.
- tech_detection: Requires final_ip_builder. Detects web technologies, servers, WAF.
- network_discovery: Requires final_ip_builder. Port scanning (nmap) + OSINT lookups.
- vuln_check: Requires final_ip_builder + ideally network_discovery. Nuclei vulnerability scan.
- read_results: Read any JSON output file to analyze before deciding next steps.
- scan_complete: Call when ALL desired modules done. Generates PDF report.

RECOMMENDED FLOW:
1. subdomain_enum
2. ip_extractor
3. check_cdn
4. read cdn_analysis.json to decide: if CDN IPs > 0 → run realip_discovery, else skip
5. cert_discovery
6. asn_recon
7. final_ip_builder
8. read final_ips.json to check total IP count
9. tech_detection
10. network_discovery
11. vuln_check
12. read vuln_results.json for final analysis
13. scan_complete

RULES:
- After each major tool, call read_results on its output JSON before proceeding
- If a step returns 0 results, skip dependent steps
- Be efficient — don't read every single file, just key decision points
- At the end (before scan_complete), provide a concise executive summary
- If a tool fails, log the error and continue with remaining tools
- Maximum efficiency: don't repeat tools that already ran
"""


# ---------------------------------------------------------------------------
# LLM client builder (reuses config from ai_report)
# ---------------------------------------------------------------------------

def _build_client():
    """Build OpenAI-compatible client from config."""
    config = get_config()
    provider = config.ai.provider.lower()

    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError(
            "openai package required for agent mode: pip install openai"
        )

    if provider == "ollama":
        base_url = config.ai.base_url or "http://localhost:11434/v1"
        model = config.ai.model or "llama3"
        _log.info(f"Using Ollama: {model} @ {base_url}")
        return OpenAI(base_url=base_url, api_key="ollama"), model

    api_key = config.ai.api_key
    if not api_key:
        raise RuntimeError(
            "AI_API_KEY or OPENAI_API_KEY not set in .env — required for agent mode"
        )

    kwargs = {"api_key": api_key}
    if config.ai.base_url:
        kwargs["base_url"] = config.ai.base_url
    model = config.ai.model or "gpt-4.1-mini"
    _log.info(f"Using model: {model}")
    return OpenAI(**kwargs), model


# ---------------------------------------------------------------------------
# OpenAI tool schema conversion
# ---------------------------------------------------------------------------

def _to_openai_tools(tool_defs: list) -> list:
    """Convert our tool definitions to OpenAI function-calling format."""
    return [
        {"type": "function", "function": tool_def}
        for tool_def in tool_defs
    ]


# ---------------------------------------------------------------------------
# Agent loop
# ---------------------------------------------------------------------------

def run_agent(
    target: str,
    max_steps: int = 40,
    model_override: Optional[str] = None,
) -> None:
    """
    Run the AI agent against a target domain.

    The agent loops: think → call tool → observe result → think again.

    Parameters
    ----------
    target : str
        Target domain to scan (e.g. "example.com").
    max_steps : int
        Safety limit on agent iterations (default 40).
    model_override : str, optional
        Override the model name from config.
    """
    config = get_config()
    init_db()

    # Create per-scan directory
    scan_id = generate_scan_id()
    scan_dir = create_target_output(target, config.paths.output_base, scan_id)
    executor = ToolExecutor(target, scan_dir)

    # Build LLM client
    client, model = _build_client()
    if model_override:
        model = model_override

    _log.info(f"{'=' * 60}")
    _log.info(f"RA137 AI Agent — Starting")
    _log.info(f"Target: {target}")
    _log.info(f"Model:  {model}")
    _log.info(f"Scan:   {scan_id}")
    _log.info(f"Dir:    {scan_dir}")
    _log.info(f"Max steps: {max_steps}")
    _log.info(f"{'=' * 60}")

    # Build conversation
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Target domain: {target}\n\n"
                f"Start the full reconnaissance scan. Run all modules in the optimal order, "
                f"read key results between steps, and provide analysis. "
                f"Call scan_complete when done."
            ),
        },
    ]

    openai_tools = _to_openai_tools(TOOLS)

    for step_num in range(1, max_steps + 1):
        _log.info(f"--- Step {step_num}/{max_steps} ---")

        try:
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                tools=openai_tools,
                tool_choice="auto",
            )
        except Exception as exc:
            _log.error(f"LLM API call failed: {exc}")
            # Retry once after a short delay
            import time
            time.sleep(2)
            try:
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=openai_tools,
                    tool_choice="auto",
                )
            except Exception as exc2:
                _log.error(f"LLM API retry failed: {exc2}")
                break

        msg = response.choices[0].message

        # ---------------------------------------------------------------
        # Case 1: LLM wants to call tool(s)
        # ---------------------------------------------------------------
        if msg.tool_calls:
            # Append the assistant message with tool calls
            messages.append(msg)

            for tool_call in msg.tool_calls:
                tool_name = tool_call.function.name
                try:
                    arguments = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    arguments = {}

                _log.info(f"Agent calls: {tool_name}({json.dumps(arguments)})")

                # Execute the tool
                result = executor.execute(tool_name, arguments)

                _log.info(f"Tool result ({len(result)} chars): {result[:300]}")

                # Append tool result to conversation
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result,
                })

                # Stop if scan is complete
                if tool_name == "scan_complete":
                    _log.success(f"{'=' * 60}")
                    _log.success("Agent scan complete!")
                    _log.success(f"Steps executed: {', '.join(executor.completed_steps)}")
                    _log.success(f"Output: {scan_dir}")
                    _log.success(f"{'=' * 60}")
                    return

        # ---------------------------------------------------------------
        # Case 2: LLM responds with text only (analysis/thinking)
        # ---------------------------------------------------------------
        elif msg.content:
            # Print agent's thinking to console
            print(f"\n{'─' * 60}")
            print(f"[RA137 Agent]")
            print(f"{'─' * 60}")
            print(msg.content)
            print(f"{'─' * 60}\n")

            _log.info(f"Agent says: {msg.content[:500]}")
            messages.append(msg)

        # ---------------------------------------------------------------
        # Case 3: Empty response (shouldn't happen, but handle it)
        # ---------------------------------------------------------------
        else:
            _log.warning("Agent returned empty response")
            messages.append({
                "role": "user",
                "content": "Please continue with the reconnaissance scan.",
            })

    # Reached max steps
    _log.warning(
        f"Agent reached max steps ({max_steps}). "
        f"Completed: {', '.join(executor.completed_steps)}"
    )
    _log.info(f"Partial results available at: {scan_dir}")
