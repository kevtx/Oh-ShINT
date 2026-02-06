from __future__ import annotations
from dataclasses import dataclass
from .models import ParamAuthProviderBase


@dataclass(slots=True)
class AbuseIPDB(ParamAuthProviderBase):
    human_name = "AbuseIPDB"
    api_base = "https://api.abuseipdb.com/api/v2/"
