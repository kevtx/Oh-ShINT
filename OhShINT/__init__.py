from sys import stderr

from dotenv import dotenv_values
from loguru import logger

from .providers import get_all_providers, iter_load_providers, load_provider

__all__ = [
    "get_all_providers",
    "load_provider",
    "iter_load_providers",
    "ALL_PROVIDERS",
]

DEFAULT_DOTENV_FILE = ".env"

logger.remove()
ALL_PROVIDERS = get_all_providers()
APP_STATE = {"verbose": False, "quiet": False, "log_level": "", "pretty": False}
dotenv = {**dotenv_values(DEFAULT_DOTENV_FILE)}

if env_log_level := dotenv.get("LOG_LEVEL"):
    APP_STATE["log_level"] = env_log_level.upper()

    logger.add(stderr, level=APP_STATE["log_level"])
    logger.info(f"Setting log level to {APP_STATE['log_level']}")
    logger.debug("Debugging enabled")
