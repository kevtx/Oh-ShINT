from __future__ import annotations

from dataclasses import dataclass

from ..models.base_provider import HeaderAuthProvider


@dataclass(slots=True)
class AlienVault(HeaderAuthProvider):
    human_name = "AlienVault OTX"
    api_base_url = "https://otx.alienvault.com/api/v1/indicators"
    auth_token_name = "X-OTX-API-KEY"
