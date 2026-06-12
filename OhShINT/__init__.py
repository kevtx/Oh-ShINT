import os
from sys import stderr

from dotenv import load_dotenv
from loguru import logger

from .models import IOC, MD5, SHA1, SHA256, Domain, IPv4, IPv6
from .providers import get_all_providers, iter_load_providers, load_provider

__all__ = [
    "ALL_PROVIDERS",
    "Domain",
    "get_all_providers",
    "IPv4",
    "IPv6",
    "iter_load_providers",
    "load_provider",
    "MD5",
    "SHA1",
    "SHA256",
    "IOC",
]

__loaded = load_dotenv()
if __loaded:
    logger.debug(f"Loaded environment variables")

logger.remove()
ALL_PROVIDERS = get_all_providers()

APP_STATE = {"verbose": False, "quiet": False, "log_level": "", "pretty": False}


if env_log_level := os.getenv("LOG_LEVEL"):
    APP_STATE["log_level"] = env_log_level.upper()

    logger.add(stderr, level=APP_STATE["log_level"])
    logger.info(f"Setting log level to {APP_STATE['log_level']}")
    logger.debug("Debugging enabled")
