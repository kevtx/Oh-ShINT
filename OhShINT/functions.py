from ipaddress import IPv4Address, IPv6Address, ip_address

import pycountry
import regex as re
from loguru import logger


def get_country_by_alpha2(alpha2: str):
    return pycountry.countries.get(alpha_2=alpha2)


def is_ipv6(ip: str) -> bool:
    try:
        return True if type(ip_address(ip)) == IPv6Address else False
    except ValueError:
        return False


def is_ipv4(ip: str) -> bool:
    try:
        return True if type(ip_address(ip)) == IPv4Address else False
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    try:
        return ip_address(ip).is_global
    except ValueError:
        return False


def is_domain(domain: str) -> bool:
    if domain.count(".") >= 1 and len([i for i in domain if i.isalpha()]):
        return True
    else:
        return False


def is_md5(hash: str) -> bool:
    return True if len(hash) == 32 else False


def is_sha256(hash: str) -> bool:
    return True if len(hash) == 64 else False


def is_sha1(hash: str) -> bool:
    return True if len(hash) == 40 else False


def ioc_regex_search(regexp_name: str, search_content: str) -> list[str]:
    """
    Use Regex to search for IOCs in a given string
    - regexp_name: Name of the regexp search to use
    - search_content: String to search for IOCs in

    """
    # . No plurals!
    if regexp_name.endswith("s"):
        regexp_name = regexp_name[:-1]

    regexp_strings = {
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domain": r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
        "sha256": r"\b[a-fA-F0-9]{64}\b",
        "sha1": r"\b([a-fA-F\d]{40})\b",
        "md5": r"\b([a-fA-F\d]{32})\b",
    }

    if regexp_name not in regexp_strings.keys():
        logger.error("Invalid regexp name")
        raise (ValueError("Invalid regexp name"))
    else:
        regexp = regexp_strings[regexp_name]

    matches = re.findall(regexp, search_content)

    if len(matches) == 0:
        logger.info(f"No matches found for {regexp_name}")
        raise (ValueError(f"No matches found for {regexp_name}"))
    else:
        return matches


def get_ioc_type(ioc_value: str) -> tuple[str, str]:
    """
    Returns the type of an IOC
    - ioc_value: IOC string to get type from

    """

    logger.debug
    types = []

    try:
        if is_ipv6(ioc_value):
            types.append(("IPv6", "IP"))
            if not is_public_ip(ioc_value):
                logger.error("Non-public IPv6 address detected")
        if is_ipv4(ioc_value):
            types.append(("IPv4", "IP"))
            if not is_public_ip(ioc_value):
                logger.error("Non-public IPv4 address detected")
        if is_sha1(ioc_value):
            types.append(("SHA1", "SHA1"))
            logger.debug("SHA1 detected")
        if is_sha256(ioc_value):
            types.append(("SHA256", "SHA256"))
            logger.debug("SHA256 detected")
        if is_md5(ioc_value):
            types.append(("MD5", "MD5"))
            logger.debug("MD5 detected")
        if is_domain(ioc_value):
            types.append(("Domain", "Domain"))
            logger.debug("Domain detected")
    except Exception as e:
        logger.error(f"Error: {e}")
        raise e

    e = None
    if len(types) == 0:
        e = ValueError("No IOC types detected")
    if len(types) > 1:
        e = ValueError("Multiple IOC types detected")

    if e:
        logger.error(e)
        raise e

    got_type = types[0]
    logger.debug(f"Got IOC type: {got_type[0]}")

    return got_type
