from __future__ import annotations

from dataclasses import dataclass

from OhShINT.models.ioc import IOC, MD5, SHA1, SHA256, Domain, IPv4, IPv6

from ..models.base_provider import HeaderAuthProvider, RequestConfig


@dataclass(slots=True)
class VirusTotal(HeaderAuthProvider):
    human_name = "VirusTotal"
    api_base_url = "https://www.virustotal.com/api/v3"
    auth_token_name = "x-apikey"

    def build_preauth_request_config(self, ioc: IOC, **kwargs) -> RequestConfig:
        rc = RequestConfig(
            method="GET",
            path="",
            headers={"Accept": "application/json"},
        )

        if isinstance(ioc, (IPv4, IPv6)):
            rc.path = f"ip_addresses/{ioc}"
            return rc
        elif isinstance(ioc, Domain):
            rc.path = f"domains/{ioc}"
            return rc
        elif isinstance(ioc, (SHA256, SHA1, MD5)):
            rc.path = f"files/{ioc}"
            return rc

        raise NotImplementedError(
            f"{self.human_name} doesn't support {ioc.cn} indicators"
        )
