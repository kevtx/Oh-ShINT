import json
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Optional, Union

import httpx
from httpx_cache import Client, FileCache
from jsonpath_ng import parse
from loguru import logger
from pydantic import BaseModel, root_validator
from pydantic.dataclasses import dataclass

from .functions import get_ioc_type
from .history import Cache


@dataclass
class IOC:
    value: str
    type: str

    @classmethod
    def auto_type(cls, value: str):
        typ, _ = get_ioc_type(value)
        return cls(value=value, type=typ)


@dataclass
class OSINT:
    ioc: IOC
    provider_name: str
    data: dict
    timestamp: datetime = datetime.now(timezone.utc)


@dataclass
class ASN:
    asn: int
    name: str
    country: str
    country_code: str


class Provider(BaseModel):
    @dataclass
    class Key:
        key: str
        required_length: int

        @root_validator(allow_reuse=True)
        def key_length(cls, values):
            key = values.get("key")
            required_length = values.get("required_length")
            if required_length and len(key) != required_length:
                raise ValueError(f"Key must be {required_length} characters long")
            return values

    NAME: str
    ENABLED: bool = True
    API_BASE: str
    URL_BASE: str
    AVAILABLE_IOC_TYPES: dict
    ASN_CAPABLE: bool = False
    KEY_LENGTH: int
    KEY: Optional[Key] = None
    KEY_VALIDATED: bool = False
    TEMPLATES: Optional[dict[str, str]] = None
    auth_type: Optional[str] = None
    auth_header: Optional[str] = None
    additional_headers: Optional[dict[str, str]] = None
    request_datamap: Optional[dict] = None
    response_datamap: Optional[dict] = None
    config_yml: Path

    def __init__(self, config_yml: Path | str) -> None:
        data = self.__load_json(config_yml)

        ioc_types: dict[str, dict] = {}
        for ti in data["ioc_types"]:
            logger.debug(f"Processing IOC type: {ti}")
            if "=" in ti or "|" in ti:
                try:
                    d, title = self.__parse_kvpstring_to_dict(
                        input_string=ti, with_title=True
                    )
                except ValueError as e:
                    logger.error(f"Error parsing {ti}: {e}")
            else:
                title = ti
                d = {
                    "api": ti,
                    "web": ti,
                }

            if d == {}:
                logger.error(f"Error parsing IOC type: {ti}")
                raise ValueError(f"Error parsing IOC type: {ti}")

            if "api" not in d:
                d["api"] = title

            if "web" not in d:
                d["web"] = title

            ioc_types[title] = d

        auth_type = data["auth_type"].split("=")[0]
        logger.debug(f"Auth type: {auth_type}")
        if auth_type not in ["header", "none"]:
            e = ValueError(f"Invalid auth_type: {auth_type}")
            logger.error(e)
            raise e

        auth_header = None
        if auth_type == "header":
            logger.debug("Auth type is header; getting header name")
            auth_header = data["auth_type"].split("=")[1]
            logger.debug(f"Auth header: {auth_header}")
        elif auth_type == "none":
            logger.debug("Auth type is none; no header needed")

        additional_headers = None
        if "additional_headers" in data:
            logger.debug(f"Additional headers: {data['additional_headers']}")
            additional_headers = data["additional_headers"]

        super().__init__(
            NAME=data["name"],
            ENABLED=data["enabled"] if "enabled" in data else True,
            API_BASE=data["url"]["api"],
            URL_BASE=data["url"]["web"],
            AVAILABLE_IOC_TYPES=ioc_types,
            ASN_CAPABLE=data["capabilities"]["asn"],
            KEY_LENGTH=data["key_length"],
            TEMPLATES=data["templates"],
            auth_type=auth_type,
            auth_header=auth_header,
            additional_headers=additional_headers if additional_headers else None,
            request_datamap=(
                data["request_datamap"] if "request_datamap" in data else None
            ),
            response_datamap=(
                data["response_datamap"] if "response_datamap" in data else None
            ),
            config_yml=config_yml,
        )

        logger.debug(f"Provider {self.NAME} initialized")
        logger.debug(f"Auth type: {self.auth_type}")

    def __repr__(self) -> str:
        return f"{self.NAME} Provider"

    def __parse_kvpstring_to_dict(
        self,
        input_string: str,
        item_delimiter: str = "|",
        key_value_delimiter: str = "=",
        with_title: bool = False,
    ) -> Union[dict, str] | dict:
        if len(item_delimiter) != 1:
            raise ValueError(
                f"Item delimiter must be a single character: {item_delimiter}"
            )
        elif len(key_value_delimiter) != 1:
            raise ValueError(
                f"Key-value delimiter must be a single character: {key_value_delimiter}"
            )

        if item_delimiter == key_value_delimiter:
            raise ValueError("Delimiters cannot be identical")

        items = input_string.split(item_delimiter)

        if len(items) == 0:
            raise ValueError("No items found")

        if with_title:
            title = items.pop(0) if len(items) > 1 else items[0]

        results = {}
        skipped = []
        for i in items:
            try:
                k, v = i.split(key_value_delimiter)
                logger.debug(f"Adding {k} = {v}")
                results[k] = v
            except ValueError as e:
                logger.debug(
                    f"Error parsing string: {e}\titem = {i}\tinput = {input_string}"
                )
                skipped.append(i)

        if skipped:
            logger.warning(f"Skipped items: {skipped}")

        if with_title:
            return (results, title)
        else:
            return results

    def __load_json(self, file_path: Path | str) -> dict:
        if isinstance(file_path, str):
            file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "r") as f:
            try:
                data = json.load(f)
            except Exception as e:
                raise e

        return data

    def __get_template(self, template_name: str) -> Template:
        if template_name not in self.TEMPLATES:
            raise ValueError(f"Template not found: {template_name}")
        return Template(self.TEMPLATES[template_name])

    def get_key(self) -> str:
        if not self.KEY:
            raise ValueError("Key not set")
        return self.KEY.key

    def set_key(self, key: str, force: bool = False) -> None:
        if self.KEY and not force:
            raise ValueError("Key already set")
        self.KEY = self.Key(key=key, required_length=self.KEY_LENGTH)

    def __get_request_url(self, ioc: IOC | str, api: bool = True) -> str:
        if isinstance(ioc, str):
            got_type, _ = get_ioc_type(ioc)
            ioc = IOC(value=ioc, type=got_type)

        if ioc.type not in self.AVAILABLE_IOC_TYPES.keys():
            logger.error(f"Unsupported IOC type ({ioc.type})")
            raise ValueError(f"Unsupported IOC type ({ioc.type})")
        else:
            ioc_type = self.AVAILABLE_IOC_TYPES[ioc.type]

        if api:
            try:
                logger.debug(f"Getting API URL for {ioc.value}")
                t = self.__get_template("url_api")
                logger.debug(f"Template: {t.template}")
                r = t.safe_substitute(
                    base=self.API_BASE, type=ioc_type["api"], ioc=ioc.value
                )
                logger.debug(f"Result: {r}")
                return r
            except KeyError as e:
                logger.error(f"Error getting API URL: {e}")
        else:
            try:
                logger.debug(f"Getting Web URL for {ioc.value}")
                t = self.__get_template("url_web")
                logger.debug(f"Template: {t.template}")
                r = t.safe_substitute(
                    base=self.URL_BASE, type=ioc_type["web"], ioc=ioc.value
                )
                logger.debug(f"Result: {r}")
                return r
            except KeyError as e:
                logger.error(f"Error getting Web URL: {e}")

        raise ValueError("Error getting URL")

    def __build_request(self, ioc: IOC) -> httpx.Request:
        if not self.KEY:
            raise ValueError("Key not set")

        def __handle_var(var: str, locals: dict = locals()) -> str:
            var_name = var[3:]  # prefix == '$__'

            if var_name not in locals:
                raise ValueError(f"Variable {var_name} not found in locals")
            if isinstance(locals[var_name], IOC):
                return locals[var_name].value
            elif isinstance(locals[var_name], str):
                return locals[var_name]

            raise ValueError(f"Invalid variable type for {var_name}: {type(var_name)}")

        url = self.__get_request_url(ioc, api=True)
        logger.debug(f"Request URL: {url}")

        logger.debug(f"Auth type: {self.auth_type}")

        headers = {}
        if self.auth_type == "header":
            logger.debug(f"Adding {self.auth_header} header")
            headers[self.auth_header] = self.get_key()

        if self.additional_headers:
            for k, v in self.additional_headers.items():
                if str(v).startswith("$__"):
                    try:
                        v = __handle_var(v)
                    except ValueError as e:
                        logger.error(e)
                        continue
                headers[k] = v

        data = {}
        params = {}
        if self.request_datamap:
            if "params" in self.request_datamap:
                for k, v in self.request_datamap["params"].items():
                    if str(v).startswith("$__"):
                        try:
                            v = __handle_var(v)
                        except ValueError as e:
                            logger.error(e)
                            continue
                    params[k] = v

            if "data" in self.request_datamap:
                for k, v in self.request_datamap["data"].items():
                    if str(v).startswith("$__"):
                        try:
                            v = __handle_var(v)
                        except ValueError as e:
                            logger.error(e)
                            continue
                    data[k] = v

        logger.debug(f"Headers: {headers}")
        return httpx.Request(
            "GET",
            url,
            headers=headers,
            params=params,
            data=data,
        )

    @staticmethod
    def __extract_jsonpath(dot_notation_path: str, json_data: dict) -> str:
        jsonpath_expr = parse(dot_notation_path)
        matches = [match.value for match in jsonpath_expr.find(json_data)]

        if matches:
            if len(matches) > 1:
                e = ValueError(
                    f"Multiple matches found for JSONPath expression '{dot_notation_path}'"
                )
                logger.error(e)
                raise e
            return str(matches[0])

        e = ValueError(
            f"No matches found for JSONPath expression '{dot_notation_path}'"
        )
        logger.error(e)
        raise e

    def __handle_response(self, response: httpx.Response | dict) -> dict:
        try:
            if isinstance(response, httpx.Response):
                if response.is_error:
                    e = ValueError(f"Response error: {response.status_code}")
                    logger.error(e)
                    raise e
                response = response.json()
        except Exception as e:
            logger.error(f"Failed to handle response: {e}")
            raise e

        if not self.response_datamap:
            raise ValueError("No response datamap found")

        indicators = {}
        for k in self.response_datamap["indicators"]:
            jsonmap = self.response_datamap["indicators"][k]
            v = Provider.__extract_jsonpath(jsonmap, response)
            indicators[k] = v

        if self.ASN_CAPABLE and "asn" in self.response_datamap:
            asn = {}
            try:
                for k in self.response_datamap["asn"]:
                    jsonmap = self.response_datamap["asn"][k]
                    v = Provider.__extract_jsonpath(jsonmap, response)
                    asn[k] = v
            except Exception as e:
                logger.debug(f"No ASN data found: {e}")
                asn = None

        if "other" in self.response_datamap:
            other = {}
            for k in self.response_datamap["other"]:
                jsonmap = self.response_datamap["other"][k]
                try:
                    v = Provider.__extract_jsonpath(jsonmap, response)
                    other[k] = v
                except Exception as e:
                    logger.error(f"Error extracting {k}")
                    other[k] = None
        else:
            other = None

        return {
            "indicators": indicators,
            "asn": asn if self.ASN_CAPABLE else None,
            "other": other,
        }

    def search(
        self,
        ioc: IOC | str,
        do_print: bool = False,
        history: Cache = Cache(create=True),
        #        only_return_asn: bool = False,
        #        only_return_indicators: bool = False,
        #        only_return_data: bool = False,
        ignore_disabled: bool = False,
    ) -> OSINT:
        if not self.ENABLED and not ignore_disabled:
            raise ValueError(f"{self.NAME} provider is not enabled")

        if isinstance(ioc, str):
            ioc = IOC.auto_type(ioc)

        #        x = (only_return_asn, only_return_indicators, only_return_data)
        #        if sum(x) > 1:
        #            raise ValueError(
        #                "Only one of only_return_asn, only_return_indicators, and only_return_data can be True"
        #            )

        if history:
            logger.debug(f"Checking cached history for {ioc.value}")
            cached = history.get(ioc.value, self.NAME)
            if cached:
                if len(cached) > 1:
                    e = ValueError(f"Multiple results found in cache for {ioc.value}")
                    logger.error(e)
                    raise e
                logger.debug(f"Found {ioc.value} in cache")
                return OSINT(ioc=ioc, provider_name=self.NAME, data=cached[0]["data"])

        with Client(
            cache=FileCache(cache_dir=Path(__file__).parent / ".cache" / "httpx"),
            verify=False,  # TODO: Proxy isn't playing nice.
        ) as c:
            try:
                logger.debug("Building request")
                req = self.__build_request(ioc)
                logger.debug("Sending request")
                logger.trace(req.url)
                resp = c.send(req)
                logger.debug("Received response")
                logger.trace(resp.json())
                results = self.__handle_response(resp)
            except Exception as e:
                logger.error(f"Failed to search: {e}")
                raise e

            c.close()

        if do_print:
            print(results)

        result = OSINT(ioc=ioc, provider_name=self.NAME, data=results)

        if history:
            try:
                logger.trace(f"Adding {result} to history")
                history.add(result)
            except Exception as e:
                logger.error(f"Failed to add result to history: {e}")

        return result

    #        if only_return_asn:
    #            return results["asn"]
    #        elif only_return_indicators:
    #            return results["indicators"]
    #
    #        return results

    def search_to_md(self) -> str:
        raise NotImplementedError("search_to_md() not implemented")

    @staticmethod
    def new_from_string(ioc_value: str) -> IOC:
        """
        Returns an IOC object from a string
        - ioc_value: String to convert to IOC
        """
        type = get_ioc_type(ioc_value)
        return IOC(value=ioc_value, type=type)
