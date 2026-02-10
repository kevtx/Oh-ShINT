from __future__ import annotations

from dataclasses import dataclass

from OhShINT.models.ioc import CIDR, IOC, IPv4, IPv6

from ..models.base_provider import HeaderAuthProvider, RequestConfig

DEFAULT_MAX_AGE_DAYS = 30


@dataclass(slots=True)
class AbuseIPDB(HeaderAuthProvider):
    human_name = "AbuseIPDB"
    api_base_url = "https://api.abuseipdb.com/api/v2/"
    auth_token_name = "key"
    header_prefix = ""

    def build_preauth_request_config(self, ioc: IOC, **kwargs) -> RequestConfig:
        params = {"maxAgeInDays": kwargs.get("max_age_days", DEFAULT_MAX_AGE_DAYS)}
        rc = RequestConfig(
            method="GET",
            params=params,
            headers={"Accept": "application/json"},
        )
        if isinstance(ioc, (IPv4, IPv6)):
            rc.path = "check"
            params["ipAddress"] = ioc.value
            rc.params = params
            return rc
        elif isinstance(ioc, CIDR):
            rc.path = "check-block"
            params["network"] = ioc.value
            rc.params = params
            return rc

        raise NotImplementedError(
            f"{self.human_name} doesn't support {ioc.cn} indicators"
        )
