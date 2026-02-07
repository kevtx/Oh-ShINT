from sys import stderr

from dotenv import dotenv_values
from loguru import logger

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
