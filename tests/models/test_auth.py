import unittest

import httpx

from OhShINT.models.auth import BaseAuth, HeaderAuth, ParamAuth


class DummyAuth(BaseAuth):
    def _apply(self, request: httpx.Request) -> None:
        request.headers[self.name] = self.token


class TestBaseAuth(unittest.TestCase):
    def test_repr_with_token_masked(self):
        auth = DummyAuth(name="X-Token", token="secret")
        self.assertEqual(repr(auth), "DummyAuth(name='X-Token', token=****)")

    def test_repr_without_token(self):
        auth = DummyAuth(name="X-Token", token="")
        self.assertEqual(repr(auth), "DummyAuth(name='X-Token')")

    def test_auth_flow_applies(self):
        auth = DummyAuth(name="X-Token", token="secret")
        request = httpx.Request("GET", "https://example.com")
        flow = auth.auth_flow(request)
        first = next(flow)
        self.assertEqual(first.headers["X-Token"], "secret")
        with self.assertRaises(StopIteration):
            next(flow)

    def test_apply_not_implemented(self):
        class NoApply(BaseAuth):
            pass

        auth = NoApply(name="X-Token", token="secret")
        request = httpx.Request("GET", "https://example.com")
        with self.assertRaises(NotImplementedError):
            auth._apply(request)


class TestHeaderAuth(unittest.TestCase):
    def test_header_auth_default_prefix(self):
        auth = HeaderAuth(name="Authorization", token="abc123")
        request = httpx.Request("GET", "https://example.com")
        auth._apply(request)
        self.assertEqual(request.headers["Authorization"], "abc123")

    def test_header_auth_custom_prefix(self):
        auth = HeaderAuth(name="Authorization", token="abc123", prefix="Token")
        request = httpx.Request("GET", "https://example.com")
        auth._apply(request)
        self.assertEqual(request.headers["Authorization"], "Token abc123")

    def test_header_auth_no_prefix(self):
        auth = HeaderAuth(name="Authorization", token="abc123", prefix="")
        request = httpx.Request("GET", "https://example.com")
        auth._apply(request)
        self.assertEqual(request.headers["Authorization"], "abc123")

    def test_header_auth_overwrites_existing_header(self):
        auth = HeaderAuth(name="Authorization", token="newtoken")
        request = httpx.Request(
            "GET", "https://example.com", headers={"Authorization": "old"}
        )
        auth._apply(request)
        self.assertEqual(request.headers["Authorization"], "newtoken")

    def test_header_auth_flow(self):
        auth = HeaderAuth(name="Authorization", token="abc123")
        request = httpx.Request("GET", "https://example.com")
        flow = auth.auth_flow(request)
        first = next(flow)
        self.assertEqual(first.headers["Authorization"], "abc123")
        with self.assertRaises(StopIteration):
            next(flow)


class TestParamAuth(unittest.TestCase):
    def test_param_auth_adds_query_param(self):
        auth = ParamAuth(name="api_key", token="secret")
        request = httpx.Request("GET", "https://example.com")
        auth._apply(request)
        self.assertEqual(request.url.params["api_key"], "secret")

    def test_param_auth_merges_with_existing_params(self):
        auth = ParamAuth(name="api_key", token="secret")
        request = httpx.Request("GET", "https://example.com?foo=bar")
        auth._apply(request)
        self.assertEqual(request.url.params["foo"], "bar")
        self.assertEqual(request.url.params["api_key"], "secret")

    def test_param_auth_overwrites_existing_param(self):
        auth = ParamAuth(name="api_key", token="secret")
        request = httpx.Request("GET", "https://example.com?api_key=old")
        auth._apply(request)
        self.assertEqual(request.url.params["api_key"], "secret")

    def test_param_auth_flow(self):
        auth = ParamAuth(name="api_key", token="secret")
        request = httpx.Request("GET", "https://example.com")
        flow = auth.auth_flow(request)
        first = next(flow)
        self.assertEqual(first.url.params["api_key"], "secret")
        with self.assertRaises(StopIteration):
            next(flow)
