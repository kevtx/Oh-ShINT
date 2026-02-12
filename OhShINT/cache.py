import os
from pathlib import Path

import certifi
import httpx
from hishel import SyncSqliteStorage
from hishel.httpx import SyncCacheTransport

DEFAULT_CACHE_DB = "httpx_cache.db"

storage = SyncSqliteStorage(database_path=(Path(__file__).parent / DEFAULT_CACHE_DB))


def get_cache_transport(proxy: str | None = None) -> SyncCacheTransport:
    """Get a cache transport with proxy support via environment variables.

    Args:
        proxy: Optional proxy URL to use for requests.

    Returns:
        SyncCacheTransport configured with proxy support.
    """
    # Extract proxy from environment variables if not explicitly provided
    if proxy is None:
        proxy = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy") or \
                os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
    
    return SyncCacheTransport(
        storage=storage,
        next_transport=httpx.HTTPTransport(proxy=proxy, verify=certifi.where()),
    )
