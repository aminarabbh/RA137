"""
Shared HTTP session and thread-safe cache utilities for RA137.

Provides:
- A singleton ``requests.Session`` with proper connection pooling and
  TLS verification (configurable for recon targets that may have bad certs).
- A thread-safe, bounded LRU cache for API responses.
"""

import threading
from collections import OrderedDict
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

_session_lock = threading.Lock()
_session: Optional[requests.Session] = None
_insecure_session: Optional[requests.Session] = None


def _build_session(verify_ssl: bool = True, pool_connections: int = 20) -> requests.Session:
    """Create a properly configured ``requests.Session``."""
    sess = requests.Session()
    sess.verify = verify_ssl
    sess.headers.update({
        "User-Agent": "RA137/1.0 (reconnaissance framework)",
        "Accept": "application/json, */*",
    })

    retry_strategy = Retry(
        total=2,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD"],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=pool_connections,
        pool_maxsize=pool_connections,
    )
    sess.mount("https://", adapter)
    sess.mount("http://", adapter)
    return sess


def get_session() -> requests.Session:
    """
    Return the global shared ``requests.Session`` (TLS-verified).

    Thread-safe – the session is created lazily under a lock.
    """
    global _session
    if _session is None:
        with _session_lock:
            if _session is None:
                _session = _build_session(verify_ssl=True)
    return _session


def get_insecure_session() -> requests.Session:
    """
    Return a session with TLS verification disabled.

    Used ONLY for probing recon targets whose certificates are unknown.
    Never use this session for API calls that carry secrets.
    """
    global _insecure_session
    if _insecure_session is None:
        with _session_lock:
            if _insecure_session is None:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                _insecure_session = _build_session(verify_ssl=False)
    return _insecure_session


# ---------------------------------------------------------------------------
# Thread-safe bounded LRU cache
# ---------------------------------------------------------------------------

class ThreadSafeCache:
    """
    A thread-safe, bounded LRU cache backed by ``OrderedDict``.

    Parameters
    ----------
    max_size : int
        Maximum number of entries.  Oldest entries are evicted when the
        limit is reached.
    """

    def __init__(self, max_size: int = 2000):
        self._lock = threading.Lock()
        self._data: OrderedDict[str, Any] = OrderedDict()
        self._max_size = max_size

    def get(self, key: str) -> Optional[Any]:
        """Return cached value or ``None``.  Moves key to end (MRU)."""
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return self._data[key]
        return None

    def put(self, key: str, value: Any) -> None:
        """Insert or update a cache entry, evicting the LRU item if full."""
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self._data[key] = value
            else:
                self._data[key] = value
                if len(self._data) > self._max_size:
                    self._data.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._data.clear()


# Global API response cache shared across all modules
api_cache = ThreadSafeCache(max_size=5000)
