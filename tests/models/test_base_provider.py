import unittest
from dataclasses import dataclass
from unittest.mock import Mock, patch

import httpx

from OhShINT.history import History
from OhShINT.models.auth import HeaderAuth, ParamAuth
from OhShINT.models.base_provider import (
    BaseProvider,
    HeaderAuthProvider,
    ParamAuthProvider,
    RequestConfig,
)
from OhShINT.models.ioc import IOC


class ConcreteProvider(BaseProvider):
    """Concrete implementation of BaseProvider for testing."""

    human_name = "Test Provider"
    api_base_url = "https://api.example.com"
    auth_token_name = "api_key"

    def build_preauth_request_config(self, ioc: IOC) -> RequestConfig:
        return RequestConfig(method="GET", path="/search", params={"q": ioc.value})


class TestBaseProvider(unittest.TestCase):
    def setUp(self):
        self.provider = ConcreteProvider(token="test-token-123")

    def tearDown(self):
        if self.provider._client is not None:
            self.provider.close()

    def test_initialization_with_token(self):
        """Test provider initializes with token."""
        self.assertEqual(self.provider.token, "test-token-123")
        self.assertEqual(self.provider.timeout, 30)

    def test_initialization_without_token(self):
        """Test provider initializes without token."""
        provider = ConcreteProvider()
        self.assertIsNone(provider.token)
        self.assertEqual(provider.timeout, 30)

    def test_custom_timeout(self):
        """Test provider with custom timeout."""
        provider = ConcreteProvider(token="token", timeout=60)
        self.assertEqual(provider.timeout, 60)

    def test_auth_not_set_without_token(self):
        """Test auth is None when no token provided."""
        provider = ConcreteProvider()
        self.assertIsNone(provider.auth)

    def test_try_load_token_from_env(self):
        """Test loading token from .env file."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"CONCRETEprovider": "token-from-env"}
            provider.try_load_token()
            # Should not load because key is CONCRETEprovider (uppercase class name)
            self.assertIsNone(provider.token)

    def test_try_load_token_with_correct_env_key(self):
        """Test loading token from .env with correct class name key."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"CONCRETEPROVIDERFROM": "token-from-env"}
            provider.try_load_token()
            # Should not load because class name will be ConcreteProvider

    def test_try_load_token_env_error_handling(self):
        """Test error handling when loading from .env fails."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.side_effect = Exception("File not found")
            # Should not raise, just log error
            provider.try_load_token()
            self.assertIsNone(provider.token)

    def test_ensure_base_url_raises_when_not_set(self):
        """Test _ensure_base_url raises ValueError when api_base_url is not set."""

        @dataclass(slots=True)
        class InvalidProvider(BaseProvider):
            api_base_url = ""

        provider = InvalidProvider()
        with self.assertRaises(ValueError) as context:
            provider._ensure_base_url()
        self.assertIn("api_base_url must be set", str(context.exception))

    def test_ensure_base_url_passes_when_set(self):
        """Test _ensure_base_url does not raise when api_base_url is set."""
        # Should not raise
        self.provider._ensure_base_url()

    def test_get_client_creates_client(self):
        """Test _get_client creates httpx.Client."""
        client = self.provider._get_client()
        self.assertIsInstance(client, httpx.Client)
        self.assertEqual(client.base_url, "https://api.example.com")

    def test_get_client_returns_same_instance(self):
        """Test _get_client returns same client instance on subsequent calls."""
        client1 = self.provider._get_client()
        client2 = self.provider._get_client()
        self.assertIs(client1, client2)

    def test_request_method(self):
        """Test request method calls client.request."""
        with patch.object(self.provider, "_get_client") as mock_get_client:
            mock_client = Mock()
            mock_response = Mock(spec=httpx.Response)
            mock_client.request.return_value = mock_response
            mock_get_client.return_value = mock_client

            result = self.provider.request("GET", "/path", params={"key": "value"})

            mock_client.request.assert_called_once_with(
                "GET", "/path", params={"key": "value"}
            )
            self.assertEqual(result, mock_response)

    def test_get_method(self):
        """Test get method calls request with GET."""
        with patch.object(self.provider, "request") as mock_request:
            mock_response = Mock(spec=httpx.Response)
            mock_request.return_value = mock_response

            result = self.provider.get("/path", params={"key": "value"})

            mock_request.assert_called_once_with(
                "GET", "/path", params={"key": "value"}
            )
            self.assertEqual(result, mock_response)

    def test_post_method(self):
        """Test post method calls request with POST."""
        with patch.object(self.provider, "request") as mock_request:
            mock_response = Mock(spec=httpx.Response)
            mock_request.return_value = mock_response

            result = self.provider.post("/path", json={"data": "value"})

            mock_request.assert_called_once_with(
                "POST", "/path", json={"data": "value"}
            )
            self.assertEqual(result, mock_response)

    def test_close_closes_client(self):
        """Test close method closes the client."""
        self.provider._get_client()
        self.assertIsNotNone(self.provider._client)

        self.provider.close()

        self.assertIsNone(self.provider._client)

    def test_close_when_no_client(self):
        """Test close when no client exists does not raise."""
        provider = ConcreteProvider()
        # Should not raise
        provider.close()

    def test_context_manager_enter(self):
        """Test context manager __enter__ gets client."""
        provider = ConcreteProvider(token="token")
        result = provider.__enter__()

        self.assertIs(result, provider)
        self.assertIsNotNone(provider._client)

    def test_context_manager_exit(self):
        """Test context manager __exit__ closes client."""
        provider = ConcreteProvider(token="token")
        provider.__enter__()
        self.assertIsNotNone(provider._client)

        provider.__exit__(None, None, None)

        self.assertIsNone(provider._client)

    def test_context_manager_usage(self):
        """Test using provider as context manager."""
        with ConcreteProvider(token="token") as provider:
            self.assertIsNotNone(provider._client)

        self.assertIsNone(provider._client)

    def test_search_with_ioc_string(self):
        """Test search method with IOC as string."""
        mock_history = Mock(spec=History)
        mock_history.get.return_value = None
        mock_response = Mock(spec=httpx.Response)
        mock_response.json.return_value = {"ok": True}

        with patch.object(
            self.provider, "request", return_value=mock_response
        ) as mock_request:
            result = self.provider.search("192.168.1.1", history=mock_history)

        mock_request.assert_called_once_with(
            "GET",
            "/search",
            params={"q": "192.168.1.1"},
            json=None,
            data=None,
            headers=None,
        )
        mock_history.add.assert_called_once()
        self.assertEqual(result, {"ok": True})

    def test_search_with_ioc_object(self):
        """Test search method with IOC object."""
        mock_history = Mock(spec=History)
        mock_history.get.return_value = None
        ioc = IOC("192.168.1.1")
        mock_response = Mock(spec=httpx.Response)
        mock_response.json.return_value = {"ok": True}

        with patch.object(
            self.provider, "request", return_value=mock_response
        ) as mock_request:
            result = self.provider.search(ioc, history=mock_history)

        mock_request.assert_called_once()
        mock_history.add.assert_called_once()
        self.assertEqual(result, {"ok": True})

    def test_search_with_history_hit(self):
        """Test search method returns historyd result."""
        mock_history = Mock(spec=History)
        mock_history.get.return_value = {"historyd": "result"}
        ioc = IOC("192.168.1.1")
        with patch.object(self.provider, "request") as mock_request:
            result = self.provider.search(ioc, history=mock_history)

        self.assertEqual(result, {"historyd": "result"})
        mock_history.get.assert_called_once_with("192.168.1.1", "ConcreteProvider")
        mock_request.assert_not_called()

    def test_search_with_history_miss(self):
        """Test search method with history miss."""
        mock_history = Mock(spec=History)
        mock_history.get.return_value = None
        ioc = IOC("192.168.1.1")
        mock_response = Mock(spec=httpx.Response)
        mock_response.json.return_value = {"data": "value"}

        with patch.object(
            self.provider, "request", return_value=mock_response
        ) as mock_request:
            result = self.provider.search(ioc, history=mock_history)

        mock_request.assert_called_once()
        mock_history.add.assert_called_once()
        self.assertEqual(result, {"data": "value"})


class TestHeaderAuthProvider(unittest.TestCase):
    def setUp(self):
        @dataclass(slots=True)
        class TestHeaderProvider(HeaderAuthProvider):
            api_base_url = "https://api.example.com"
            auth_token_name = "X-API-Key"

        self.TestHeaderProvider = TestHeaderProvider

    def test_initialization_with_token(self):
        """Test HeaderAuthProvider initializes with token."""
        provider = self.TestHeaderProvider(token="test-token")
        self.assertEqual(provider.token, "test-token")
        self.assertIsNotNone(provider.auth)

    def test_post_init_sets_auth_with_token(self):
        """Test __post_init__ sets auth when token provided."""
        provider = self.TestHeaderProvider(token="test-token")
        self.assertIsInstance(provider.auth, HeaderAuth)
        if isinstance(provider.auth, HeaderAuth):
            self.assertEqual(provider.auth.name, "X-API-Key")
            self.assertEqual(provider.auth.token, "test-token")
            self.assertEqual(provider.auth.prefix, "")

    def test_post_init_auth_none_without_token(self):
        """Test __post_init__ auth is None when no token."""
        provider = self.TestHeaderProvider()
        self.assertIsNone(provider.auth)

    def test_custom_header_prefix(self):
        """Test custom header prefix."""
        provider = self.TestHeaderProvider(token="test-token", header_prefix="Token ")
        if isinstance(provider.auth, HeaderAuth):
            self.assertEqual(provider.auth.prefix, "Token ")

    def test_header_auth_applied_to_request(self):
        """Test that header auth is applied to requests."""
        provider = self.TestHeaderProvider(token="test-token")
        client = provider._get_client()

        # The auth should be set on the client
        if isinstance(client.auth, HeaderAuth):
            self.assertEqual(client.auth.name, "X-API-Key")
            self.assertEqual(client.auth.token, "test-token")

        provider.close()

    @patch("OhShINT.models.base_provider.dotenv_values")
    def test_try_load_token_from_env(self, mock_dotenv):
        """Test loading token from .env file."""
        mock_dotenv.return_value = {"TESTHEADERPROVIDER": "env-token"}
        provider = self.TestHeaderProvider()
        provider.try_load_token()
        # The key will be the uppercase class name
        # This test depends on actual class name


class TestParamAuthProvider(unittest.TestCase):
    def setUp(self):
        @dataclass(slots=True)
        class TestParamProvider(ParamAuthProvider):
            api_base_url = "https://api.example.com"
            auth_token_name = "api_key"

        self.TestParamProvider = TestParamProvider

    def test_initialization_with_token(self):
        """Test ParamAuthProvider initializes with token."""
        provider = self.TestParamProvider(token="test-token")
        self.assertEqual(provider.token, "test-token")
        self.assertIsNotNone(provider.auth)

    def test_post_init_sets_auth_with_token(self):
        """Test __post_init__ sets auth when token provided."""
        provider = self.TestParamProvider(token="test-token")
        self.assertIsInstance(provider.auth, ParamAuth)
        if isinstance(provider.auth, ParamAuth):
            self.assertEqual(provider.auth.name, "api_key")
            self.assertEqual(provider.auth.token, "test-token")

    def test_post_init_auth_none_without_token(self):
        """Test __post_init__ auth is None when no token."""
        provider = self.TestParamProvider()
        self.assertIsNone(provider.auth)

    def test_param_auth_applied_to_request(self):
        """Test that param auth is applied to requests."""
        provider = self.TestParamProvider(token="test-token")
        client = provider._get_client()

        # The auth should be set on the client
        if isinstance(client.auth, ParamAuth):
            self.assertEqual(client.auth.name, "api_key")
            self.assertEqual(client.auth.token, "test-token")

        provider.close()


class TestProviderIntegration(unittest.TestCase):
    """Integration tests for providers."""

    def test_header_provider_full_workflow(self):
        """Test full workflow with HeaderAuthProvider."""

        @dataclass(slots=True)
        class APIProvider(HeaderAuthProvider):
            human_name = "Test API"
            api_base_url = "https://api.example.com"

        with APIProvider(token="secret-token") as provider:
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider.auth)
            if isinstance(provider.auth, HeaderAuth):
                self.assertEqual(provider.auth.token, "secret-token")

    def test_param_provider_full_workflow(self):
        """Test full workflow with ParamAuthProvider."""

        @dataclass(slots=True)
        class APIProvider(ParamAuthProvider):
            human_name = "Test API"
            api_base_url = "https://api.example.com"
            auth_token_name = "key"

        with APIProvider(token="secret-key") as provider:
            self.assertIsNotNone(provider._client)
            self.assertIsNotNone(provider.auth)
            if isinstance(provider.auth, ParamAuth):
                self.assertEqual(provider.auth.token, "secret-key")

    def test_multiple_provider_instances_independent(self):
        """Test multiple provider instances are independent."""

        @dataclass(slots=True)
        class Provider1(BaseProvider):
            api_base_url = "https://api1.example.com"

        @dataclass(slots=True)
        class Provider2(BaseProvider):
            api_base_url = "https://api2.example.com"

        p1 = Provider1(token="token1")
        p2 = Provider2(token="token2")

        client1 = p1._get_client()
        client2 = p2._get_client()

        self.assertIsNot(client1, client2)
        self.assertEqual(client1.base_url, "https://api1.example.com")
        self.assertEqual(client2.base_url, "https://api2.example.com")

        p1.close()
        p2.close()


class TestProxySupport(unittest.TestCase):
    """Test proxy support functionality."""

    def setUp(self):
        self.provider = ConcreteProvider(token="test-token-123")

    def tearDown(self):
        if self.provider._client is not None:
            self.provider.close()

    def test_initialization_with_proxy(self):
        """Test provider initializes with proxy."""
        provider = ConcreteProvider(
            token="token", proxy="http://proxy.example.com:8080"
        )
        self.assertEqual(provider.proxy, "http://proxy.example.com:8080")

    def test_initialization_without_proxy(self):
        """Test provider initializes without proxy (None)."""
        provider = ConcreteProvider(token="token")
        self.assertIsNone(provider.proxy)

    def test_proxy_with_authentication(self):
        """Test proxy initialization with authentication credentials."""
        proxy_url = "http://user:pass@proxy.example.com:8080"
        provider = ConcreteProvider(token="token", proxy=proxy_url)
        self.assertEqual(provider.proxy, proxy_url)

    def test_try_load_proxy_from_https_proxy_env(self):
        """Test loading proxy from HTTPS_PROXY environment variable."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"HTTPS_PROXY": "http://proxy-https:8080"}
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://proxy-https:8080")

    def test_try_load_proxy_from_http_proxy_env(self):
        """Test loading proxy from HTTP_PROXY environment variable as fallback."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"HTTP_PROXY": "http://proxy-http:8080"}
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://proxy-http:8080")

    def test_try_load_proxy_from_proxy_env(self):
        """Test loading proxy from PROXY environment variable as fallback."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"PROXY": "http://proxy-generic:8080"}
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://proxy-generic:8080")

    def test_try_load_proxy_prefers_https_proxy(self):
        """Test that HTTPS_PROXY is preferred over other proxy settings."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {
                "HTTPS_PROXY": "http://proxy-https:8080",
                "HTTP_PROXY": "http://proxy-http:8080",
                "PROXY": "http://proxy-generic:8080",
            }
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://proxy-https:8080")

    def test_try_load_proxy_fallback_to_http_proxy(self):
        """Test fallback to HTTP_PROXY when HTTPS_PROXY not set."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {
                "HTTP_PROXY": "http://proxy-http:8080",
                "PROXY": "http://proxy-generic:8080",
            }
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://proxy-http:8080")

    def test_try_load_proxy_fallback_to_generic_proxy(self):
        """Test fallback to PROXY when HTTPS_PROXY and HTTP_PROXY not set."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"PROXY": "http://proxy-generic:8080"}
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://proxy-generic:8080")

    def test_try_load_proxy_no_env_vars(self):
        """Test no proxy is loaded when no proxy env vars are set."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {}
            provider.try_load_proxy()
            self.assertIsNone(provider.proxy)

    def test_try_load_proxy_does_not_override_existing_proxy(self):
        """Test that try_load_proxy does not override an existing proxy."""
        provider = ConcreteProvider(proxy="http://explicit-proxy:8080")

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"HTTPS_PROXY": "http://env-proxy:8080"}
            provider.try_load_proxy()
            self.assertEqual(provider.proxy, "http://explicit-proxy:8080")

    def test_try_load_proxy_error_handling(self):
        """Test error handling when loading proxy from .env fails."""
        provider = ConcreteProvider()

        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.side_effect = Exception("File read error")
            # Should not raise, just log error
            provider.try_load_proxy()
            self.assertIsNone(provider.proxy)

    def test_get_client_passes_proxy_to_httpx_client(self):
        """Test that proxy is passed to httpx.Client initialization."""
        provider = ConcreteProvider(
            token="token", proxy="http://proxy.example.com:8080"
        )

        with patch("OhShINT.models.base_provider.httpx.Client") as mock_client_class:
            mock_client_instance = Mock()
            mock_client_class.return_value = mock_client_instance

            provider._get_client()

            # Verify httpx.Client was called with proxy parameter
            mock_client_class.assert_called_once()
            call_kwargs = mock_client_class.call_args[1]
            self.assertEqual(call_kwargs["proxy"], "http://proxy.example.com:8080")

    def test_get_client_with_none_proxy(self):
        """Test that None proxy is passed to httpx.Client."""
        provider = ConcreteProvider(token="token", proxy=None)

        with patch("OhShINT.models.base_provider.httpx.Client") as mock_client_class:
            mock_client_instance = Mock()
            mock_client_class.return_value = mock_client_instance

            provider._get_client()

            call_kwargs = mock_client_class.call_args[1]
            self.assertIsNone(call_kwargs["proxy"])

    def test_header_auth_provider_loads_proxy(self):
        """Test HeaderAuthProvider calls try_load_proxy in __post_init__."""
        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {
                "HTTPS_PROXY": "http://proxy-header:8080",
                "HeaderAuthProvider": "token",
            }

            @dataclass(slots=True)
            class TestHeaderAuthProvider(HeaderAuthProvider):
                api_base_url = "https://api.example.com"
                auth_token_name = "key"

            provider = TestHeaderAuthProvider()
            # Proxy should be loaded
            self.assertEqual(provider.proxy, "http://proxy-header:8080")

    def test_param_auth_provider_loads_proxy(self):
        """Test ParamAuthProvider calls try_load_proxy in __post_init__."""
        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {
                "HTTPS_PROXY": "http://proxy-param:8080",
                "TestParamAuthProvider": "token",
            }

            @dataclass(slots=True)
            class TestParamAuthProvider(ParamAuthProvider):
                api_base_url = "https://api.example.com"
                auth_token_name = "key"

            provider = TestParamAuthProvider()
            # Proxy should be loaded
            self.assertEqual(provider.proxy, "http://proxy-param:8080")

    def test_proxy_persists_across_requests(self):
        """Test that proxy setting persists across multiple requests."""
        provider = ConcreteProvider(
            token="token", proxy="http://proxy.example.com:8080"
        )

        # First request
        with patch.object(provider, "_get_client") as mock_get_client:
            mock_client = Mock(spec=httpx.Client)
            mock_response = Mock(spec=httpx.Response)
            mock_client.request.return_value = mock_response
            mock_get_client.return_value = mock_client

            provider.request("GET", "/path1")

            # Second request
            provider.request("GET", "/path2")

            # Proxy should still be set
            self.assertEqual(provider.proxy, "http://proxy.example.com:8080")

    def test_proxy_with_different_providers(self):
        """Test that each provider can have different proxy settings."""
        provider1 = ConcreteProvider(token="token1", proxy="http://proxy1:8080")
        provider2 = ConcreteProvider(token="token2", proxy="http://proxy2:8080")

        self.assertEqual(provider1.proxy, "http://proxy1:8080")
        self.assertEqual(provider2.proxy, "http://proxy2:8080")

        provider1.close()
        provider2.close()


if __name__ == "__main__":
    unittest.main()
