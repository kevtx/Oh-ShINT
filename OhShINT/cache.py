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
