import fnmatch
import glob
import re
from pathlib import Path
from sys import stderr
from typing import Iterable

from dotenv import dotenv_values
from loguru import logger

from .Classes import Provider
from .History import Cache

provider_yaml_dir = Path(__file__).parent / "Providers"

Providers: dict[str, Provider] = {}


def get_provider_yml(provider_name: str) -> str:
    raise NotImplementedError("This function is not implemented")
    logger.info(f"Searching for {provider_name} provider")

    regexp = re.compile(
        fnmatch.translate(str(provider_yaml_dir.absolute()) + f"/{provider_name}.yml"),
        re.IGNORECASE,
    )

    logger.debug(f"Regexp: {regexp.pattern}")

    for yml in glob.iglob(
        (str(provider_yaml_dir.absolute()) + "/*.yml"), recursive=False
    ):
        logger.debug(f"Checking {yml}")
        if regexp.match(yml):
            return yml


def __load_provider_key(provider: Provider) -> None:
    name = provider.NAME.upper()
    logger.debug(f"Checking for {provider.NAME} key")
    if name in dotenv:
        logger.debug(f"Setting {provider.NAME} key")
        try:
            provider.set_key(dotenv[name], force=True)
        except ValueError as e:
            logger.error(e)
    else:
        logger.warning(f"No key found for {provider.NAME} provider")


def __load_provider_keys(providers: list[Provider]) -> None:
    if not providers or len(providers) < 1:
        raise ValueError("No providers provided")

    for provider in providers.values():
        __load_provider_key(provider)


def get_provider(name: str, load_key: bool) -> Provider:
    p = Provider(str(provider_yaml_dir.absolute()) + f"/{name}.yml")
    if load_key:
        __load_provider_key(p)
    return p


def get_available_providers_iter() -> Iterable[str]:
    for yml in glob.iglob(
        (str(provider_yaml_dir.absolute()) + "/*.yml"), recursive=False
    ):
        yield Path(yml).stem


def get_all_providers(load_keys: bool) -> dict[str, Provider]:
    p = {
        provider: Provider(str(provider_yaml_dir.absolute()) + f"/{provider}.yml")
        for provider in get_available_providers_iter()
    }

    if load_keys:
        __load_provider_keys(p)

    return p


def load_providers_and_keys() -> None:
    global Providers
    Providers = get_all_providers(load_keys=True)


def indicator_history_search(
    indicator: str, cache: Cache = Cache()
) -> list[dict[str, str]]:
    return cache.get(indicator)


logger.remove()
dotenv = {**dotenv_values(".env")}

if "LOG_LEVEL" in dotenv:
    if dotenv["LOG_LEVEL"] == "":
        log_level = "INFO"
    else:
        log_level = dotenv["LOG_LEVEL"].upper()

    logger.add(stderr, level=log_level)
    logger.info(f"Setting log level to {log_level}")
    logger.debug("Debugging enabled")
