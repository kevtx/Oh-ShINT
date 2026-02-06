from __future__ import annotations


from dataclasses import dataclass

import httpx


@dataclass(slots=True)
class BaseAuth(httpx.Auth):
    """
    Common base for token-style auth strategies.

    Shared attributes:
      - name: header name OR query param name (depends on strategy)
      - token: credential value
    """

    name: str
    token: str

    def _apply(self, request: httpx.Request) -> None:
        """Implemented by subclasses."""
        raise NotImplementedError

    def auth_flow(self, request: httpx.Request):
        self._apply(request)
        yield request


@dataclass(slots=True)
class HeaderAuth(BaseAuth):
    """
    Applies token as a header: {name}: {prefix}{token}
    Example: Authorization: Bearer <token>
    """

    prefix: str = "Bearer "

    def _apply(self, request: httpx.Request) -> None:
        request.headers[self.name] = (
            f"{self.prefix}{self.token}" if self.prefix else self.token
        )


@dataclass(slots=True)
class ParamAuth(BaseAuth):
    """
    Applies token as a query parameter: ?{name}={token}
    """

    def _apply(self, request: httpx.Request) -> None:
        request.url = request.url.copy_merge_params({self.name: self.token})
