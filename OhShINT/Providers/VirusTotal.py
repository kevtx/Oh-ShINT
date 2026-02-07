from __future__ import annotations

from dataclasses import dataclass

from ..models.base_provider import HeaderAuthProvider


@dataclass(slots=True)
class VirusTotal(HeaderAuthProvider):
    human_name = "VirusTotal"
    api_base_url = "https://www.virustotal.com/api/v3"
    auth_token_name = "x-apikey"
