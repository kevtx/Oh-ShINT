from dataclasses import dataclass


@dataclass
class ASN:
    asn: int
    name: str
    country: str
    country_code: str
