"""Synthetic geo lookup for documentation-range IPs.

All mappings are fictional and use RFC 5737 TEST-NET plus RFC 1918 space.
Nothing here is a live geolocation service.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from ipaddress import ip_address, ip_network, IPv4Network


@dataclass(frozen=True)
class GeoFix:
    city: str
    country: str
    lat: float
    lon: float
    internal: bool
    cidr: str

    def label(self) -> str:
        kind = "internal" if self.internal else "external"
        return f"{self.city}, {self.country} ({kind})"


# Longest-prefix match: more specific CIDRs first after sort.
_GEO_TABLE: list[tuple[IPv4Network, GeoFix]] = []


def _register(cidr: str, city: str, country: str, lat: float, lon: float, internal: bool) -> None:
    net = ip_network(cidr)
    if not isinstance(net, IPv4Network):
        raise ValueError(f"only IPv4 CIDRs are supported, got {cidr}")
    _GEO_TABLE.append(
        (
            net,
            GeoFix(
                city=city,
                country=country,
                lat=lat,
                lon=lon,
                internal=internal,
                cidr=cidr,
            ),
        )
    )


_register("10.0.0.0/8", "San Francisco", "US", 37.7749, -122.4194, True)
_register("172.16.0.0/12", "San Francisco", "US", 37.7749, -122.4194, True)
_register("192.168.0.0/16", "San Francisco", "US", 37.7749, -122.4194, True)
_register("192.0.2.0/24", "San Francisco", "US", 37.7749, -122.4194, False)  # TEST-NET-1 / HQ VPN
_register("198.51.100.10/32", "New York", "US", 40.7128, -74.0060, False)
_register("198.51.100.200/32", "Frankfurt", "DE", 50.1109, 8.6821, False)
_register("198.51.100.0/24", "Frankfurt", "DE", 50.1109, 8.6821, False)  # TEST-NET-2
_register("203.0.113.50/32", "Moscow", "RU", 55.7558, 37.6173, False)
_register("203.0.113.80/32", "Tokyo", "JP", 35.6762, 139.6503, False)
_register("203.0.113.0/24", "London", "GB", 51.5074, -0.1278, False)  # TEST-NET-3 default

_GEO_TABLE.sort(key=lambda item: item[0].prefixlen, reverse=True)

_UNKNOWN = GeoFix("Unknown", "ZZ", 0.0, 0.0, False, "0.0.0.0/0")


def lookup(ip: str) -> GeoFix:
    """Return the most specific synthetic geo fix for an IPv4 address."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return _UNKNOWN
    for net, fix in _GEO_TABLE:
        if addr in net:
            return fix
    return _UNKNOWN


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
