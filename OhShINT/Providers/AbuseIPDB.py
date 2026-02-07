from __future__ import annotations

from dataclasses import dataclass

from ..models.base_provider import ParamAuthProvider


@dataclass(slots=True)
class AbuseIPDB(ParamAuthProvider):
    human_name = "AbuseIPDB"
    api_base_url = "https://api.abuseipdb.com/api/v2/"
    auth_token_name = "key"
