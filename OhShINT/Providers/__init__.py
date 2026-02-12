import os


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
    for p in __all__:
        if p.upper() in [pl.upper() for pl in provider_list]:
            yield globals()[p](token=os.getenv(f"{p.upper()}_API_KEY"))


def load_provider(name: str) -> object | None:
    for provider in iter_load_providers([name]):
        if provider.human_name.lower() == name.lower():
            return provider
    raise KeyError(f"Provider '{name}' not found.")


def get_all_providers() -> dict[str, BaseProvider]:
    return {provider.human_name: provider for provider in iter_load_providers()}
