import string
from dataclasses import __all__, dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

import pycountry
import regex as re
from boltons.cacheutils import cachedproperty
from boltons.dictutils import FrozenDict
from boltons.tbutils import ExceptionInfo
from boltons.typeutils import get_all_subclasses
from loguru import logger
from validators import domain as v_domain

__all__ = ["IOC", "get_ioc_type", "ioc_regex_search"]


def _try_validate(value, *validators) -> bool:
    for validator in validators:
        try:
            if not validator(value):
                return False
        except Exception:
            exc_info = ExceptionInfo.from_current()
            logger.debug(
                f"Error validating value '{value}' with validator {validator.__name__}: {exc_info.exc_msg}"
            )
            logger.debug(exc_info.get_formatted())
            return False
    return True


_all_hex_chars = lambda x: bool(x) and all(ch in string.hexdigits for ch in x)

is_ipv6 = lambda x: _try_validate(x, lambda v: type(ip_address(v)) == IPv6Address)
is_ipv4 = lambda x: _try_validate(x, lambda v: type(ip_address(v)) == IPv4Address)
is_public_ip = lambda x: _try_validate(x, lambda v: ip_address(v).is_global)
is_cidr = lambda x: _try_validate(
    x, lambda v: type(ip_network(v, strict=False)) in (IPv4Address, IPv6Address)
)
is_domain = lambda x: _try_validate(x, v_domain)
is_md5 = lambda x: _try_validate(x, lambda v: len(v) == 32 and _all_hex_chars(v))
is_sha1 = lambda x: _try_validate(x, lambda v: len(v) == 40 and _all_hex_chars(v))
is_sha256 = lambda x: _try_validate(x, lambda v: len(v) == 64 and _all_hex_chars(v))


@dataclass
class IOC:
    """Base class for IOCs. Returns a subclass based on the type of value provided."""

    value: str

    def __new__(cls, value: str):
        if cls != IOC:
            return object.__new__(cls)
        ioc_class = get_ioc_type(value)
        logger.debug(f"Creating IOC of type {ioc_class.__name__} with value {value}")
        return object.__new__(ioc_class)

    def __str__(self) -> str:
        return self.value

    @cachedproperty
    def cn(self) -> str:
        return self.__class__.__name__

    @cachedproperty
    def cls(self) -> type:
        return self.__class__

    @classmethod
    def validate(cls, value: str) -> bool:
        raise NotImplementedError("Subclasses must implement validate method")


@dataclass
class IPv4(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_ipv4(value)


@dataclass
class IPv6(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_ipv6(value)


@dataclass
class CIDR(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_cidr(value)


@dataclass
class Domain(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_domain(value)


@dataclass
class SHA1(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_sha1(value)


@dataclass
class SHA256(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_sha256(value)


@dataclass
class MD5(IOC):
    @classmethod
    def validate(cls, value: str) -> bool:
        return is_md5(value)


def get_country_by_alpha2(alpha2: str):
    return pycountry.countries.get(alpha_2=alpha2)


REGEXP = FrozenDict(
    {
        IPv4: r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        IPv6: r"\b(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b",
        CIDR: r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b",
        Domain: r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        SHA256: r"\b[a-fA-F0-9]{64}\b",
        SHA1: r"\b([a-fA-F\d]{40})\b",
        MD5: r"\b([a-fA-F\d]{32})\b",
        IOC: "",
    }
)


def ioc_regex_search(ioc: IOC | str, search_content: str) -> list[str]:
    """Use Regex to search for IOCs in a given string

    Args:
        regexp_name (str): The type of IOC to search for (e.g. "ip", "domain", "sha256", "sha1", "md5")
        search_content (str): The string to search for IOCs in

    Returns:
        list[str]: A list of matched IOCs found in the search content
    """
    if isinstance(ioc, str):
        ioc = IOC(ioc)

    try:
        regexp = REGEXP[ioc.cls]
    except KeyError as e:
        exc_info = ExceptionInfo.from_current()
        logger.error(f"No regex found for IOC type {ioc.cn}: {exc_info.exc_msg}")
        logger.debug(exc_info.get_formatted())
        raise e

    matches = re.findall(regexp, search_content)

    if len(matches) == 0:
        error_msg = f"No {ioc.cn} matches found"
        logger.error(error_msg)
        raise ValueError(error_msg)
    return matches


def get_ioc_type(ioc_value: str) -> type[IOC]:
    """
    Returns the type of an IOC
    - ioc_value: IOC string to get type from

    """

    result = {}

    types = [t for t in get_all_subclasses(IOC)]
    for typ in types:
        try:
            if typ.validate(ioc_value):
                result[typ.__name__] = typ
        except Exception:
            # Exceptions are expected from validation functions, so we catch and log them without interrupting the flow
            exc_info = ExceptionInfo.from_current()
            logger.debug(
                f"Error validating IOC value '{ioc_value}' against type {typ.__name__}: {exc_info.exc_msg}"
            )
            logger.debug(exc_info.get_formatted())

    rl = len(result)
    if rl == 0 or rl > 1:
        msg = (
            "Could not determine IOC type" if rl == 0 else "Multiple IOC types detected"
        )
        raise ValueError(msg)

    ioc_class = list(result.values())[0]
    logger.debug(f"Got IOC type {ioc_class.__name__} for value {ioc_value}")
    return ioc_class
