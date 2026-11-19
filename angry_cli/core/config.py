"""Scanner configuration and pinger management mirroring Angry IP Scanner's ScannerConfig."""

import copy
import re
from typing import Any, Dict, List

from angry_cli.core.project import DEFAULT_SCANNER_CONFIG


PINGER_CATALOG: Dict[str, Dict[str, Any]] = {
    "pinger.windows": {
        "name": "Windows ICMP",
        "platform": "windows",
        "description": "Native Windows ICMP.dll / Iphlpapi.dll pinger via JNA (Windows only).",
    },
    "pinger.java": {
        "name": "Java Built-in",
        "platform": "all",
        "description": "Java InetAddress.isReachable() pinger (ICMP when privileged, TCP echo fallback).",
    },
    "pinger.udp": {
        "name": "UDP packet",
        "platform": "all",
        "description": "Unprivileged UDP port probe detecting ICMP port-unreachable replies.",
    },
    "pinger.tcp": {
        "name": "TCP port probe",
        "platform": "all",
        "description": "Unprivileged TCP handshake/RST probe on port 80 (works through ICMP-blocking firewalls).",
    },
    "pinger.combined": {
        "name": "Combined UDP+TCP",
        "platform": "all",
        "description": "Unprivileged combined UDP + TCP liveness probe.",
    },
    "pinger.arp": {
        "name": "ARP (LAN only)",
        "platform": "all",
        "description": "Layer-2 ARP resolution pinger for local broadcast segments.",
    },
}

_PINGER_ALIASES: Dict[str, str] = {
    "windows": "pinger.windows",
    "icmp": "pinger.windows",
    "java": "pinger.java",
    "udp": "pinger.udp",
    "tcp": "pinger.tcp",
    "combined": "pinger.combined",
    "arp": "pinger.arp",
}

_INT_KEYS = {"max_threads", "thread_delay", "ping_timeout", "ping_count", "port_timeout", "min_port_timeout"}
_BOOL_KEYS = {"scan_dead_hosts", "skip_broadcast_addresses", "adapt_port_timeout", "use_requested_ports"}
_STR_KEYS = {"selected_pinger", "port_string", "not_available_text", "not_scanned_text"}


def normalize_pinger_id(value: str) -> str:
    """Normalize a short alias or full pinger ID to Angry IP Scanner's canonical ID."""
    v = value.strip().lower()
    if v in PINGER_CATALOG:
        return v
    if v in _PINGER_ALIASES:
        return _PINGER_ALIASES[v]
    valid = ", ".join(PINGER_CATALOG.keys())
    raise ValueError(f"Unknown pinger '{value}'. Valid pingers: {valid}")


def validate_port_string(port_string: str) -> List[int]:
    """Validate an Angry IP Scanner port specification (e.g., ``80,443,8000-8005``).

    Matches ``net.azib.ipscan.core.PortIterator`` rules (ports 1..65535).
    An empty string is allowed (disables port scanning).
    """
    raw = port_string.strip()
    if not raw:
        return []

    ports: List[int] = []
    tokens = [t.strip() for t in re.split(r"[,\s]+", raw) if t.strip()]
    for token in tokens:
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                raise ValueError(f"Invalid port range '{token}' in port string '{port_string}'")
            start, end = int(parts[0]), int(parts[1])
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port out of valid range (1-65535) in '{token}'")
            if start > end:
                raise ValueError(f"Port range start > end in '{token}'")
            ports.extend(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port '{token}' in port string '{port_string}'")
            p = int(token)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} out of valid range (1-65535)")
            ports.append(p)
    return ports


def list_pingers() -> List[Dict[str, Any]]:
    """Return catalog of all Angry IP Scanner pinger backends."""
    return [
        {"id": pid, **meta}
        for pid, meta in PINGER_CATALOG.items()
    ]


def get_scanner_config(project: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of the project's ScannerConfig dictionary."""
    return copy.deepcopy(project["scanner_config"])


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"Invalid boolean value: '{value}'")


def set_scanner_config(project: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and apply updates to ``project['scanner_config']``."""
    cfg = project["scanner_config"]
    applied: Dict[str, Any] = {}

    for raw_key, raw_val in updates.items():
        key = raw_key.strip().replace("-", "_")
        # Friendly aliases
        alias_map = {
            "pinger": "selected_pinger",
            "ports": "port_string",
            "threads": "max_threads",
            "skip_broadcast": "skip_broadcast_addresses",
        }
        key = alias_map.get(key, key)

        if key in _INT_KEYS:
            val = int(raw_val)
            if key == "max_threads" and val < 0:
                raise ValueError("max_threads must be >= 0 (0 uses Java virtual threads)")
            if key in ("ping_timeout", "port_timeout", "min_port_timeout") and val < 1:
                raise ValueError(f"{key} must be >= 1 ms")
            if key == "ping_count" and val < 1:
                raise ValueError("ping_count must be >= 1")
            if key == "thread_delay" and val < 0:
                raise ValueError("thread_delay must be >= 0 ms")
            cfg[key] = val
            applied[key] = val
        elif key in _BOOL_KEYS:
            val = _parse_bool(raw_val)
            cfg[key] = val
            applied[key] = val
        elif key in _STR_KEYS:
            sval = str(raw_val)
            if key == "selected_pinger":
                sval = normalize_pinger_id(sval)
            elif key == "port_string":
                validate_port_string(sval)
            cfg[key] = sval
            applied[key] = sval
        else:
            valid = sorted(_INT_KEYS | _BOOL_KEYS | _STR_KEYS)
            raise ValueError(f"Unknown config key '{raw_key}'. Valid keys: {', '.join(valid)}")

    return applied


def reset_scanner_config(project: Dict[str, Any]) -> Dict[str, Any]:
    """Reset ``project['scanner_config']`` to Angry IP Scanner defaults."""
    project["scanner_config"] = copy.deepcopy(DEFAULT_SCANNER_CONFIG)
    return copy.deepcopy(project["scanner_config"])
