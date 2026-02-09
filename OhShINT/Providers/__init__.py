from dotenv import dotenv_values

from ..models.base_provider import BaseProvider
from .AbuseIPDB import AbuseIPDB
from .AlienVault import AlienVault
from .VirusTotal import VirusTotal

__all__ = [
    "AbuseIPDB",
    "AlienVault",
    "VirusTotal",
]


def iter_load_providers(provider_list: list[str] = __all__):
    for k, v in dotenv_values(".env").items():
        if not v:
            continue
        for p in provider_list:
            if k.upper() == p.upper():
                yield globals()[p](token=v)


def load_provider(name: str) -> object | None:
    for provider in iter_load_providers([name]):
        if provider.human_name.lower() == name.lower():
            return provider
    raise KeyError(f"Provider '{name}' not found.")


def get_all_providers() -> dict[str, BaseProvider]:
    return {provider.human_name: provider for provider in iter_load_providers()}
