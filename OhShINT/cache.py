from pathlib import Path

import httpx
from hishel import SyncSqliteStorage
from hishel.httpx import SyncCacheTransport

DEFAULT_CACHE_DB = "httpx_cache.db"

storage = SyncSqliteStorage(database_path=(Path(__file__).parent / DEFAULT_CACHE_DB))
transport = SyncCacheTransport(
    storage=storage,
    next_transport=httpx.HTTPTransport(),
)


def get_cache_transport(proxy: str | None = None) -> SyncCacheTransport:
    """Get a cache transport with optional proxy configuration.
    
    Args:
        proxy: Optional proxy URL to use for HTTP requests.
        
    Returns:
        SyncCacheTransport configured with the specified proxy.
    """
    return SyncCacheTransport(
        storage=storage,
        next_transport=httpx.HTTPTransport(proxy=proxy),
    )
