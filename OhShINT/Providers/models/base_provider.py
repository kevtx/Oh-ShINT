from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from .auth import HeaderAuth, ParamAuth
from typing import Any, ClassVar
import httpx


@dataclass(slots=True)
class BaseProvider:
    """
    Base provider.

    Requirements:
      - api_base_url is overridden on child classes (ClassVar)
      - auth is optional (None if token not provided)
      - auth_name defined here to avoid duplication
    """

    api_base_url: ClassVar[str] = ""  # MUST be overridden by concrete providers
    auth_name: ClassVar[str] = "api_key"  # Default; override per provider if needed

    token: str | None = None
    timeout: float = 10.0

    auth: httpx.Auth | None = field(default=None, init=False)
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def _ensure_base_url(self) -> None:
        if not self.api_base_url:
            raise ValueError(
                f"{self.__class__.__name__}.api_base_url must be set on the subclass."
            )

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._ensure_base_url()
            self._client = httpx.Client(
                base_url=self.api_base_url,
                auth=self.auth,  # optional
                timeout=self.timeout,
            )
        return self._client

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return self._get_client().request(method, path, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "BaseProvider":
        self._get_client()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


@dataclass(slots=True)
class HeaderAuthProviderBase(BaseProvider):
    """
    Provider base for header auth.
    """
    auth_name: ClassVar[str] = "Authorization"
    header_prefix: str = "Bearer "

    def __post_init__(self) -> None:
        self.auth = (
            HeaderAuth(name=self.auth_name, token=self.token, prefix=self.header_prefix)
            if self.token
            else None
        )


@dataclass(slots=True)
class ParamAuthProviderBase(BaseProvider):
    """
    Provider base for query parameter auth.
    """
    def __post_init__(self) -> None:
        self.auth = (
            ParamAuth(name=self.auth_name, token=self.token) if self.token else None
        )