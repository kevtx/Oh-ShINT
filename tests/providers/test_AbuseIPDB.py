import unittest
from unittest.mock import Mock, patch

import httpx

from OhShINT.models.base_provider import RequestConfig
from OhShINT.models.ioc import Domain, IPv4, IPv6
from OhShINT.providers.AbuseIPDB import DEFAULT_MAX_AGE_DAYS, AbuseIPDB


class TestAbuseIPDB(unittest.TestCase):
    def setUp(self) -> None:
        dotenv_mock = {
            "AbuseIPDB": "test-token",
        }
        patcher = patch(
            "OhShINT.models.base_provider.dotenv_values", return_value=dotenv_mock
        )
        self.addCleanup(patcher.stop)
        patcher.start()
        self.provider = AbuseIPDB()

    def test_build_request_ipv4_default_max_age(self):
        ioc = IPv4("8.8.8.8")

        config = self.provider.build_preauth_request_config(ioc)

        self.assertIsInstance(config, RequestConfig)
        self.assertEqual(config.method, "GET")
        self.assertEqual(config.path, "check")
        self.assertEqual(
            config.params,
            {"ipAddress": "8.8.8.8", "maxAgeInDays": DEFAULT_MAX_AGE_DAYS},
        )
        self.assertEqual(config.headers, {"Accept": "application/json"})
        self.assertIsNone(config.json)
        self.assertIsNone(config.data)

    def test_build_request_ipv4_custom_max_age(self):
        ioc = IPv4("1.1.1.1")

        config = self.provider.build_preauth_request_config(ioc, max_age_days=7)

        self.assertEqual(config.params, {"ipAddress": "1.1.1.1", "maxAgeInDays": 7})

    def test_build_request_ipv6_default_max_age(self):
        ioc = IPv6("2001:4860:4860::8888")

        config = self.provider.build_preauth_request_config(ioc)

        self.assertEqual(
            config.params,
            {"ipAddress": "2001:4860:4860::8888", "maxAgeInDays": DEFAULT_MAX_AGE_DAYS},
        )

    def test_build_request_unsupported_ioc(self):
        ioc = Domain("example.com")

        with self.assertRaises(NotImplementedError) as context:
            self.provider.build_preauth_request_config(ioc)

        self.assertIn("AbuseIPDB doesn't support Domain", str(context.exception))

    def test_search_sends_expected_request_structure(self):
        mock_history = Mock()
        mock_history.get.return_value = None
        captured_requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_requests.append(request)
            return httpx.Response(200, json={"ok": True})

        mock_transport = httpx.MockTransport(handler)

        # Close any existing client so it gets recreated with the mocked transport
        self.provider.close()

        with patch("OhShINT.models.base_provider.get_cache_transport", return_value=mock_transport):
            result = self.provider.search("8.8.8.8", history=mock_history)

        self.assertEqual(result, {"ok": True})
        self.assertEqual(len(captured_requests), 1)
        req = captured_requests[0]
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url.path, "/api/v2/check")
        self.assertEqual(
            dict(req.url.params),
            {"ipAddress": "8.8.8.8", "maxAgeInDays": str(DEFAULT_MAX_AGE_DAYS)},
        )
        self.assertEqual(req.headers.get("Accept"), "application/json")
        self.assertEqual(req.headers.get("key"), "test-token")

    def test_abuseipdb_with_proxy(self):
        """Test AbuseIPDB provider with proxy configuration."""
        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {"AbuseIPDB": "test-token"}
            provider = AbuseIPDB(proxy="http://proxy.example.com:8080")
            self.assertEqual(provider.proxy, "http://proxy.example.com:8080")
            provider.close()

    def test_abuseipdb_loads_proxy_from_env(self):
        """Test AbuseIPDB provider loads proxy from environment variables."""
        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {
                "AbuseIPDB": "test-token",
                "HTTPS_PROXY": "http://env-proxy:8080",
            }
            provider = AbuseIPDB()
            self.assertEqual(provider.proxy, "http://env-proxy:8080")
            provider.close()

    def test_abuseipdb_proxy_priority_over_env(self):
        """Test that explicit proxy takes priority over environment variables."""
        with patch("OhShINT.models.base_provider.dotenv_values") as mock_dotenv:
            mock_dotenv.return_value = {
                "AbuseIPDB": "test-token",
                "HTTPS_PROXY": "http://env-proxy:8080",
            }
            provider = AbuseIPDB(proxy="http://explicit-proxy:9090")
            self.assertEqual(provider.proxy, "http://explicit-proxy:9090")
            provider.close()


if __name__ == "__main__":
    unittest.main()
