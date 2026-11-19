"""Target feeder configuration mirroring Angry IP Scanner's Range, Random, and File feeders."""

from __future__ import annotations

import copy
import ipaddress
import os
from typing import Any


def validate_ip(value: str) -> str:
    """Validate an IPv4 or IPv6 address and return its normalized string form."""
    addr = ipaddress.ip_address(value.strip())
    return str(addr)


def expand_cidr_to_range(cidr: str, include_network_broadcast: bool = False) -> tuple[str, str, int]:
    """Expand a CIDR notation (e.g. ``192.168.1.0/24``) into ``(start_ip, end_ip, count)``.

    Args:
        cidr: Network CIDR specification.
        include_network_broadcast: If False and prefix allows host addresses,
            skip network & broadcast addresses for IPv4 subnets larger than /31.

    Returns:
        Tuple of ``(start_ip, end_ip, host_count)``.
    """
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if net.num_addresses == 1:
        ip_str = str(net.network_address)
        return ip_str, ip_str, 1
    if include_network_broadcast or net.version == 6 or net.num_addresses <= 2:
        start_ip = str(net.network_address)
        end_ip = str(net.broadcast_address)
        return start_ip, end_ip, int(net.num_addresses)
    start_ip = str(net.network_address + 1)
    end_ip = str(net.broadcast_address - 1)
    return start_ip, end_ip, int(net.num_addresses - 2)


def get_target(project: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the project's active feeder target specification."""
    return copy.deepcopy(project.get("target", {}))


def set_range_target(project: dict[str, Any], start_ip: str, end_ip: str) -> dict[str, Any]:
    """Configure an Angry IP Scanner IP Range feeder (``feeder.range``)."""
    s_addr = ipaddress.ip_address(start_ip.strip())
    e_addr = ipaddress.ip_address(end_ip.strip())
    if s_addr.version != e_addr.version:
        raise ValueError("Start IP and End IP must use the same IP protocol version (IPv4 or IPv6).")
    count = abs(int(e_addr) - int(s_addr)) + 1
    target = {
        "feeder": "range",
        "start_ip": str(s_addr),
        "end_ip": str(e_addr),
        "address_count": count,
    }
    project["target"] = target
    return copy.deepcopy(target)


def set_cidr_target(
    project: dict[str, Any],
    cidr: str,
    include_network_broadcast: bool = False,
) -> dict[str, Any]:
    """Configure an IP Range feeder expanded from CIDR notation."""
    start_ip, end_ip, count = expand_cidr_to_range(
        cidr,
        include_network_broadcast=include_network_broadcast,
    )
    target = {
        "feeder": "range",
        "cidr": cidr.strip(),
        "start_ip": start_ip,
        "end_ip": end_ip,
        "address_count": count,
    }
    project["target"] = target
    return copy.deepcopy(target)


def set_random_target(project: dict[str, Any], base_ip: str, mask: str, count: int) -> dict[str, Any]:
    """Configure an Angry IP Scanner Random feeder (``feeder.random``)."""
    base = validate_ip(base_ip)
    mask_str = mask.strip()
    if not mask_str:
        raise ValueError("Random feeder mask cannot be empty (e.g. '255.255.255.0' or '/24').")
    if count <= 0:
        raise ValueError("Random feeder count must be a positive integer.")
    target = {
        "feeder": "random",
        "base_ip": base,
        "mask": mask_str,
        "count": int(count),
    }
    project["target"] = target
    return copy.deepcopy(target)


def set_file_target(project: dict[str, Any], file_path: str) -> dict[str, Any]:
    """Configure an Angry IP Scanner Text File feeder (``feeder.file``)."""
    abs_path = os.path.abspath(file_path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"Target hosts file not found: {file_path}")
    target = {
        "feeder": "file",
        "file_path": abs_path,
    }
    project["target"] = target
    return copy.deepcopy(target)
