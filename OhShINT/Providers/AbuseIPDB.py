from __future__ import annotations

from dataclasses import dataclass

from OhShINT.models.ioc import IOC, IPv4, IPv6

from ..models.base_provider import ParamAuthProvider, RequestConfig

DEFAULT_MAX_AGE_DAYS = 30


@dataclass(slots=True)
class AbuseIPDB(ParamAuthProvider):
    human_name = "AbuseIPDB"
    api_base_url = "https://api.abuseipdb.com/api/v2/"
    auth_token_name = "key"

    def build_request(self, ioc: IOC, **kwargs) -> RequestConfig:
        if isinstance(ioc, (IPv4, IPv6)):
            return RequestConfig(
                method="GET",
                path="check",
                params={
                    "ipAddress": str(ioc),
                    "maxAgeInDays": kwargs.get("max_age_days", DEFAULT_MAX_AGE_DAYS),
                },
            )

        raise NotImplementedError(f"{self.human_name} doesn't support {ioc.cn}")
