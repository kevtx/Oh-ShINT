import fnmatch
import glob
import re
from pathlib import Path
from sys import stderr
from typing import Iterable

from dotenv import dotenv_values
from loguru import logger
from tinydb.table import Document as TinyDocument

from .functions import get_ioc_type
from .history import Cache
from .models_old import IOC, Provider

__all__ = [
    "IOC",
    "Providers",
    "get_provider",
    "get_all_providers",
    "load_providers_and_keys",
    "get_ioc_type",
]

provider_config_dir = Path(__file__).parent / "Providers"

Providers: dict[str, Provider] = {}


def get_provider_json(provider_name: str) -> str:
    raise NotImplementedError("This function is not implemented")
    logger.info(f"Searching for {provider_name} provider")

    regexp = re.compile(
        fnmatch.translate(
            provider_config_dir.absolute().joinpath(f"/{provider_name}.json")
        ),
        re.IGNORECASE,
    )

    logger.debug(f"Regexp: {regexp.pattern}")

    for j in glob.iglob(
        (str(provider_config_dir.absolute()) + "/*.json"), recursive=False
    ):
        logger.debug(f"Checking {j}")
        if regexp.match(j):
            return j


def __load_provider_key(provider: Provider) -> None:
    name = provider.NAME.upper()
    logger.debug(f"Checking for {provider.NAME} key")
    if name in dotenv:
        logger.debug(f"Setting {provider.NAME} key")
        if k := dotenv.get(name):
            provider.set_key(k, force=True)
        else:
            logger.error(f"Key not found: {k}")
    else:
        logger.warning(f"No key found for {provider.NAME} provider")


def __load_provider_keys(providers: list[Provider]) -> None:
    if not providers or len(providers) < 1:
        raise ValueError("No providers provided")

    for provider in providers:
        __load_provider_key(provider)


def get_provider(name: str, load_key: bool) -> Provider:
    p = Provider(str(provider_config_dir.absolute()) + f"/{name}.json")
    if load_key:
        __load_provider_key(p)
    return p


def get_available_providers_iter() -> Iterable[str]:
    for j in glob.iglob(
        (str(provider_config_dir.absolute()) + "/*.json"), recursive=False
    ):
        yield Path(j).stem


def get_all_providers(load_keys: bool) -> dict[str, Provider]:
    p = {
        provider: Provider(str(provider_config_dir.absolute()) + f"/{provider}.json")
        for provider in get_available_providers_iter()
    }

    if load_keys:
        __load_provider_keys(list(p.values()))

    return p


def load_providers_and_keys() -> None:
    global Providers
    Providers = get_all_providers(load_keys=True)


def indicator_history_search(
    indicator: str, cache: Cache = Cache()
) -> list[TinyDocument]:
    return cache.get(indicator)


logger.remove()
dotenv = {**dotenv_values(".env")}

if log_level := dotenv.get("LOG_LEVEL", ""):
    if log_level == "":
        log_level = "INFO"
    else:
        log_level = log_level.upper()

    logger.add(stderr, level=log_level)
    logger.info(f"Setting log level to {log_level}")
    logger.debug("Debugging enabled")
