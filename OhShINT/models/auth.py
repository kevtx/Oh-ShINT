from __future__ import annotations

from typing import Optional

import httpx


class BaseAuth(httpx.Auth):
    """Common base for token-style auth strategies."""

    name: str
    token: str

    def __init__(self, name: str, token: str) -> None:
        self.name = name
        self.token = token

    def _apply(self, request: httpx.Request) -> None:
        """Implemented by subclasses."""
        raise NotImplementedError

    def auth_flow(self, request: httpx.Request):
        self._apply(request)
        yield request

    def __repr__(self) -> str:
        if self.token:
            return f"{self.__class__.__name__}(name='{self.name}', token=****)"
        return f"{self.__class__.__name__}(name='{self.name}')"


class HeaderAuth(BaseAuth):
    """
    Applies token as a header: {name}: {prefix} {token}
    Example: Authorization: Bearer <token>
    """

    prefix: str = ""

    def __init__(self, name: str, token: str, prefix: Optional[str] = None) -> None:
        super().__init__(name, token)
        if prefix:
            self.prefix = prefix

    def _apply(self, request: httpx.Request) -> None:
        request.headers[self.name] = f"{self.prefix or ''} {self.token}".strip()


class ParamAuth(BaseAuth):
    """
    Applies token as a query parameter: ?{name}={token}
    """

    def _apply(self, request: httpx.Request) -> None:
        request.url = request.url.copy_merge_params({self.name: self.token})
