"""
Centralized configuration for RA137 Reconnaissance Framework.

Loads settings from .env file or environment variables.
Provides type-safe access to API keys, timeouts, concurrency limits, and paths.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use env vars directly


@dataclass
class APIKeys:
    """API keys for external services."""
    shodan_api_key: Optional[str] = None
    fofa_email: Optional[str] = None
    fofa_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    securitytrails_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    ipinfo_api_token: Optional[str] = None


@dataclass
class Timeouts:
    """Timeout settings in seconds."""
    http_request: int = 30
    ssl_connection: int = 5
    command_execution: int = 10000
    api_call: int = 60
    nmap_scan: int = 600


@dataclass
class Concurrency:
    """Concurrency and worker limits."""
    max_workers: int = 50
    max_cdn_workers: int = 20
    max_api_workers: int = 10
    max_cert_workers: int = 100
    max_ssl_workers: int = 50
    cert_discovery_workers: int = 100


@dataclass
class Retry:
    """Retry settings."""
    max_retries: int = 2
    backoff_factor: float = 2.0
    http_retries: int = 3


@dataclass
class Paths:
    """File and directory paths."""
    output_base: Path = field(default_factory=lambda: Path("outputs"))
    wordlists_dir: Path = field(default_factory=lambda: Path("wordlists"))
    cdn_file: Path = field(default_factory=lambda: Path("wordlists/all_cdn.txt"))
    targets_file: Path = field(default_factory=lambda: Path("targets.txt"))
    log_file: Path = field(default_factory=lambda: Path("outputs/recon.log"))


@dataclass
class AIConfig:
    """AI provider configuration (OpenAI or Ollama)."""
    provider: str = "openai"          # "openai" or "ollama"
    model: str = "gpt-4.1-mini"       # model name (e.g. llama3, mistral)
    base_url: Optional[str] = None    # auto-detected for ollama
    api_key: Optional[str] = None     # not needed for ollama
    ai_validation: bool = True        # use AI to validate ASN/RealIP results


@dataclass
class Config:
    """Main configuration container."""
    api_keys: APIKeys = field(default_factory=APIKeys)
    timeouts: Timeouts = field(default_factory=Timeouts)
    concurrency: Concurrency = field(default_factory=Concurrency)
    retry: Retry = field(default_factory=Retry)
    paths: Paths = field(default_factory=Paths)
    ai: AIConfig = field(default_factory=AIConfig)
    scan_id: str = ""  # set at startup per-scan (e.g. 20260618_143000)

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables / .env file."""
        return cls(
            api_keys=APIKeys(
                shodan_api_key=os.getenv("SHODAN_API_KEY"),
                fofa_email=os.getenv("FOFA_EMAIL"),
                fofa_api_key=os.getenv("FOFA_API_KEY"),
                censys_api_id=os.getenv("CENSYS_API_ID"),
                censys_api_secret=os.getenv("CENSYS_API_SECRET"),
                securitytrails_api_key=os.getenv("SECURITYTRAILS_API_KEY"),
                openai_api_key=os.getenv("OPENAI_API_KEY"),
                telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
                telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID"),
                ipinfo_api_token=os.getenv("IPINFO_API_TOKEN"),
            ),
            timeouts=Timeouts(
                http_request=int(os.getenv("HTTP_TIMEOUT", "30")),
                ssl_connection=int(os.getenv("SSL_TIMEOUT", "5")),
                command_execution=int(os.getenv("COMMAND_TIMEOUT", "10000")),
                api_call=int(os.getenv("API_TIMEOUT", "60")),
                nmap_scan=int(os.getenv("NMAP_TIMEOUT", "600")),
            ),
            concurrency=Concurrency(
                max_workers=int(os.getenv("MAX_WORKERS", "50")),
                max_cdn_workers=int(os.getenv("MAX_CDN_WORKERS", "20")),
                max_api_workers=int(os.getenv("MAX_API_WORKERS", "10")),
                max_cert_workers=int(os.getenv("MAX_CERT_WORKERS", "100")),
                max_ssl_workers=int(os.getenv("MAX_SSL_WORKERS", "50")),
                cert_discovery_workers=int(os.getenv("CERT_DISCOVERY_WORKERS", "100")),
            ),
            retry=Retry(
                max_retries=int(os.getenv("MAX_RETRIES", "2")),
                backoff_factor=float(os.getenv("BACKOFF_FACTOR", "2.0")),
                http_retries=int(os.getenv("HTTP_RETRIES", "3")),
            ),
            paths=Paths(
                output_base=Path(os.getenv("OUTPUT_BASE", "outputs")),
                wordlists_dir=Path(os.getenv("WORDLISTS_DIR", "wordlists")),
                cdn_file=Path(os.getenv("CDN_FILE", "wordlists/all_cdn.txt")),
                targets_file=Path(os.getenv("TARGETS_FILE", "targets.txt")),
                log_file=Path(os.getenv("LOG_FILE", "outputs/recon.log")),
            ),
            ai=AIConfig(
                provider=os.getenv("AI_PROVIDER", "openai"),
                model=os.getenv("AI_MODEL", "gpt-4.1-mini"),
                base_url=os.getenv("AI_BASE_URL"),
                api_key=os.getenv("AI_API_KEY") or os.getenv("OPENAI_API_KEY"),
                ai_validation=os.getenv("AI_VALIDATION", "true").lower() in ("true", "1", "yes"),
            ),
        )


# ---------------------------------------------------------------------------
# Global singleton – import and use directly
# ---------------------------------------------------------------------------
_config: Optional[Config] = None


def get_config() -> Config:
    """Return the global config singleton (lazy init)."""
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config
