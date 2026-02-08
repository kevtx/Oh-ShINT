from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

import httpx
from boltons.dictutils import OMD
from boltons.tbutils import ExceptionInfo
from dotenv import dotenv_values
from loguru import logger

from ..cache import transport
from ..history import History
from .auth import HeaderAuth, ParamAuth
from .ioc import IOC


@dataclass(slots=True)
class RequestConfig:
    """
    Configuration for an HTTP request to be made by a provider.

    Attributes:
        method: HTTP method (GET, POST, etc.)
        path: API endpoint path (relative to base_url)
        params: Query parameters
        json: JSON body data
        data: Form data
        headers: Additional headers
    """

    method: str
    path: str
    params: dict[str, Any] | None = field(default=None)
    json: dict[str, Any] | None = field(default=None)
    data: dict[str, Any] | None = field(default=None)
    headers: dict[str, str] | None = field(default=None)


@dataclass(slots=True)
class BaseProvider:
    """
    Base provider.

    Requirements:
      - api_base_url is overridden on child classes (ClassVar)
      - auth is optional (None if token not provided)
      - auth_name defined here to avoid duplication
    """

    human_name: ClassVar[str] = ""
    api_base_url: ClassVar[str] = ""
    auth_token_name: ClassVar[str] = ""

    token: str | None = field(default=None, repr=False)
    timeout: int = 30

    auth: httpx.Auth | None = field(default=None, init=False)
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def try_load_token(self):
        """
        Attempt to load token from .env using the class name as the key.
        """
        if not self.token:
            try:
                logger.debug(f"Checking for {self.__class__.__name__} key in .env")
                dotenv = OMD(dotenv_values(".env"))
                if token := dotenv.get(self.__class__.__name__.upper()):
                    logger.debug(f"Setting {self.__class__.__name__} key from .env")
                    self.token = token
                else:
                    logger.warning(
                        f"No key found for {self.__class__.__name__} provider in .env"
                    )
            except Exception:
                exc_info = ExceptionInfo.from_current()
                logger.error(
                    f"Error loading {self.__class__.__name__} key from .env: {exc_info.exc_msg}"
                )
                logger.debug(exc_info.get_formatted())

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
                auth=self.auth,
                timeout=self.timeout,
                transport=transport,
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

    @abstractmethod
    def build_request(self, ioc: IOC) -> RequestConfig:
        """
        Build a request configuration for the given IOC based on its type.

        Each provider subclass must implement this to assemble the appropriate
        request for the IOC types it supports.

        Args:
            ioc: The IOC to build a request for

        Returns:
            RequestConfig with method, path, and optional params/json/data/headers

        Raises:
            NotImplementedError: If the provider doesn't support this IOC type
        """
        raise NotImplementedError

    def search(self, ioc: IOC | str, history: History = History(create=True)):
        if isinstance(ioc, str):
            ioc = IOC(ioc)

        if history:
            stored = history.get(ioc.value, self.__class__.__name__)
            if stored is not None:
                return stored

        request_config = self.build_request(ioc)
        response = self.request(
            request_config.method,
            request_config.path,
            params=request_config.params,
            json=request_config.json,
            data=request_config.data,
            headers=request_config.headers,
        )

        try:
            results = response.json()
        except ValueError:
            results = response.text

        if history:
            history.add(
                {
                    "ioc": {"type": ioc.typ, "value": ioc.value},
                    "provider_name": self.__class__.__name__,
                    "data": results,
                }
            )

        return results


@dataclass(slots=True)
class HeaderAuthProvider(BaseProvider):
    """
    Provider base for header auth.
    """

    auth_name: ClassVar[str] = "Authorization"
    header_prefix: str = field(default="Bearer ", repr=False)

    def __post_init__(self) -> None:
        self.try_load_token()
        self.auth = (
            HeaderAuth(name=self.auth_name, token=self.token, prefix=self.header_prefix)
            if self.token
            else None
        )


@dataclass(slots=True)
class ParamAuthProvider(BaseProvider):
    """
    Provider base for query parameter auth.
    """

    def __post_init__(self) -> None:
        self.try_load_token()
        self.auth = (
            ParamAuth(name=self.auth_token_name, token=self.token)
            if self.token
            else None
        )
