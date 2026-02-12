import os
from sys import stderr

from dotenv import find_dotenv, load_dotenv
from loguru import logger

from .providers import get_all_providers, iter_load_providers, load_provider

__all__ = [
    "get_all_providers",
    "load_provider",
    "iter_load_providers",
    "ALL_PROVIDERS",
]

DEFAULT_DOTENV_FILE = ".env"

dotenv_path = find_dotenv(DEFAULT_DOTENV_FILE, raise_error_if_not_found=True)
_ = load_dotenv(dotenv_path)
logger.debug(f"Loaded environment variables from {dotenv_path}")

logger.remove()
ALL_PROVIDERS = get_all_providers()

APP_STATE = {"verbose": False, "quiet": False, "log_level": "", "pretty": False}


if env_log_level := os.getenv("LOG_LEVEL"):
    APP_STATE["log_level"] = env_log_level.upper()

    logger.add(stderr, level=APP_STATE["log_level"])
    logger.info(f"Setting log level to {APP_STATE['log_level']}")
    logger.debug("Debugging enabled")
