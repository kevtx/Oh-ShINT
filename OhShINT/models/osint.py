from datetime import datetime, timezone

from pydantic.dataclasses import dataclass

from .ioc import IOC


@dataclass
class OSINT:
    ioc: IOC
    provider_name: str
    data: dict
    timestamp: datetime = datetime.now(timezone.utc)
