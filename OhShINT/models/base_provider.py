from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Optional

import httpx
from boltons.tbutils import ExceptionInfo
from dotenv import dotenv_values
from loguru import logger

from ..cache import transport
from ..history import History
from .auth import HeaderAuth, ParamAuth
from .ioc import IOC


@dataclass(slots=True)
class RequestConfig:
    """Configuration for an HTTP request to be made by a provider."""

    method: str
    path: Optional[str] = None
    params: Optional[dict[str, Any]] = field(default=None)
    json: Optional[dict[str, Any]] = field(default=None)
    data: Optional[dict[str, Any]] = field(default=None)
    headers: Optional[dict[str, str]] = field(default=None)

    def __post_init__(self) -> None:
        self.method = self.method.upper()


@dataclass(slots=True)
class BaseProvider:
    """Base class for OSINT providers."""

    human_name: ClassVar[str] = ""
    api_base_url: ClassVar[str] = ""
    auth_token_name: ClassVar[str] = ""

    token: str | None = field(default=None, repr=False)
    timeout: int = 30
    proxy: str | None = field(default=None)
    auth: httpx.Auth | None = field(default=None, init=False)
    _client: httpx.Client | None = field(default=None, init=False, repr=False)

    def try_load_token(self):
        """Attempt to load token from .env using the class name as the key."""
        if not self.token:
            try:
                logger.debug(f"Checking for {self.__class__.__name__} key in .env")

                dotenv = {**dotenv_values(".env")}
                token = dotenv.get(self.__class__.__name__)
                if not token:
                    token = dotenv.get(self.__class__.__name__.upper())
                if token:
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

    def try_load_proxy(self):
        """Attempt to load proxy from .env. Checks for HTTP_PROXY, HTTPS_PROXY, and PROXY environment variables."""
        if not self.proxy:
            try:
                logger.debug("Checking for proxy configuration in .env")
                dotenv = {**dotenv_values(".env")}

                # Check for proxy in order of preference
                proxy = (
                    dotenv.get("HTTPS_PROXY")
                    or dotenv.get("HTTP_PROXY")
                    or dotenv.get("PROXY")
                )

                if proxy:
                    logger.debug(f"Setting proxy from .env")
                    self.proxy = proxy
                else:
                    logger.debug("No proxy configuration found in .env")
            except Exception:
                exc_info = ExceptionInfo.from_current()
                logger.error(
                    f"Error loading proxy configuration from .env: {exc_info.exc_msg}"
                )
                logger.debug(exc_info.get_formatted())

    def _ensure_base_url(self) -> None:
        """Ensure the provider subclass has an api_base_url defined, otherwise raise an error.

        Raises:
            ValueError: If api_base_url is not set on the subclass.
        """
        if not self.api_base_url:
            raise ValueError(
                f"{self.__class__.__name__}.api_base_url must be set on the subclass."
            )

    def _get_client(self) -> httpx.Client:
        """Get or create the httpx.Client for this provider, ensuring the base URL is set.

        Returns:
            httpx.Client: The client instance for making requests to the provider's API.
        """
        if self._client is None:
            self._ensure_base_url()
            self._client = httpx.Client(
                base_url=self.api_base_url,
                auth=self.auth,
                timeout=self.timeout,
                transport=transport,
                proxy=self.proxy,
            )
        return self._client

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make an HTTP request to the provider's API using the configured client.

        Args:
            method (str): The HTTP method to use for the request (e.g., "GET", "POST").
            path (str): The path or endpoint to request, relative to the base URL.
            **kwargs: Keyword arguments to pass to httpx.Client.request().

        Returns:
            httpx.Response: The response object resulting from the HTTP request.
        """
        return self._get_client().request(method, path, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        """Convenience method for making a GET request to the provider's API.

        Args:
            path (str): The path or endpoint to request, relative to the base URL.
            **kwargs: Keyword arguments to pass to httpx.Client.request().

        Returns:
            httpx.Response: The response object resulting from the GET request.
        """
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        """Convenience method for making a POST request to the provider's API.

        Args:
            path (str): The path or endpoint to request, relative to the base URL.
            **kwargs: Keyword arguments to pass to httpx.Client.request().

        Returns:
            httpx.Response: The response object resulting from the POST request.
        """
        return self.request("POST", path, **kwargs)

    def close(self) -> None:
        """Close the provider's HTTP client if it exists, and set it to None."""
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "BaseProvider":
        """Enter the runtime context related to this object.

        Returns:
            BaseProvider: The provider instance itself.
        """
        self._get_client()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Exit the runtime context and close the HTTP client."""
        self.close()

    @abstractmethod
    def build_preauth_request_config(self, ioc: IOC) -> RequestConfig:
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

    def search(
        self,
        ioc: IOC | str,
        history: Optional[History] = History(create=True),
        **kwargs,
    ):
        """Search for the given IOC using the provider, utilizing caching via History.

        Args:
            ioc (IOC | str): The IOC to search for. If a string is provided, it will be converted to an IOC object.
            history (History, optional): History object for caching. Defaults to History(create=True).
        """
        if isinstance(ioc, str):
            ioc = IOC(ioc)

        if history:
            if stored := history.get(ioc.value, self.__class__.__name__):
                return stored

        request_config = self.build_preauth_request_config(ioc, **kwargs)
        response = self.request(
            request_config.method,
            request_config.path if request_config.path else "",
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
                    "ioc": {"type": ioc.cn, "value": ioc.value},
                    "provider_name": self.__class__.__name__,
                    "data": results,
                }
            )

        return results


@dataclass(slots=True)
class HeaderAuthProvider(BaseProvider):
    """Provider base for header auth."""

    header_prefix: str = ""

    def __post_init__(self) -> None:
        self.try_load_token()
        self.try_load_proxy()
        self.auth = (
            HeaderAuth(
                name=self.auth_token_name, token=self.token, prefix=self.header_prefix
            )
            if self.token
            else None
        )


@dataclass(slots=True)
class ParamAuthProvider(BaseProvider):
    """Provider base for query parameter auth."""

    def __post_init__(self) -> None:
        self.try_load_token()
        self.try_load_proxy()
        self.auth = (
            ParamAuth(name=self.auth_token_name, token=self.token)
            if self.token
            else None
        )
