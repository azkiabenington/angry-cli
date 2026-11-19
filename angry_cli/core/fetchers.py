"""Fetcher catalog, selection, ordering, and preference management for Angry IP Scanner."""

import copy
from typing import Any, Dict, List, Optional, Set


FETCHER_CATALOG: Dict[str, Dict[str, Any]] = {
    "fetcher.ip": {
        "name": "IP",
        "mandatory": True,
        "pref_node": None,
        "description": "Displays the scanned IP address (mandatory first column).",
    },
    "fetcher.ping": {
        "name": "Ping",
        "mandatory": False,
        "pref_node": None,
        "description": "Average round-trip ping latency using the selected pinger.",
    },
    "fetcher.ping.ttl": {
        "name": "TTL",
        "mandatory": False,
        "pref_node": None,
        "description": "Time-To-Live value from ICMP ping replies.",
    },
    "fetcher.packetloss": {
        "name": "Packet Loss",
        "mandatory": False,
        "pref_node": None,
        "description": "Packets lost out of total ping probes sent.",
    },
    "fetcher.hostname": {
        "name": "Hostname",
        "mandatory": False,
        "pref_node": None,
        "description": "Reverse DNS lookup (and mDNS/NetBIOS fallback in Angry IP Scanner).",
    },
    "fetcher.ports": {
        "name": "Ports",
        "mandatory": False,
        "pref_node": None,
        "description": "Open TCP ports detected from the configured port string.",
    },
    "fetcher.ports.filtered": {
        "name": "Filtered Ports",
        "mandatory": False,
        "pref_node": None,
        "description": "TCP ports that timed out (likely firewall-filtered).",
    },
    "fetcher.mac": {
        "name": "MAC Address",
        "mandatory": False,
        "pref_node": "mac",
        "description": "Local-network hardware MAC address via OS ARP table / WinIpHlp.",
    },
    "fetcher.mac.vendor": {
        "name": "MAC Vendor",
        "mandatory": False,
        "pref_node": None,
        "description": "Hardware vendor resolved from Angry IP Scanner's IEEE OUI database.",
    },
    "fetcher.comment": {
        "name": "Comments",
        "mandatory": False,
        "pref_node": None,
        "description": "Persistent per-host comments (matched by MAC or IP).",
    },
    "fetcher.webDetect": {
        "name": "Web detect",
        "mandatory": False,
        "pref_node": "webDetect",
        "description": "Detects HTTP Server header via HEAD /robots.txt probe.",
    },
    "fetcher.httpSender": {
        "name": "HTTP Sender",
        "mandatory": False,
        "pref_node": "httpSender",
        "description": "Sends custom TCP/HTTP request text and extracts regex capture group.",
    },
    "fetcher.httpProxy": {
        "name": "HTTP Proxy",
        "mandatory": False,
        "pref_node": "httpProxy",
        "description": "Detects working HTTP proxy on port 3128 or open/requested ports.",
    },
    "fetcher.netbios": {
        "name": "NetBIOS Info",
        "mandatory": False,
        "pref_node": None,
        "description": "Queries UDP/137 NetBIOS node status (DOMAIN\\USER@COMPUTER).",
    },
}

_FETCHER_ALIASES: Dict[str, str] = {
    "ip": "fetcher.ip",
    "ping": "fetcher.ping",
    "ttl": "fetcher.ping.ttl",
    "ping.ttl": "fetcher.ping.ttl",
    "packetloss": "fetcher.packetloss",
    "packet-loss": "fetcher.packetloss",
    "hostname": "fetcher.hostname",
    "ports": "fetcher.ports",
    "filtered": "fetcher.ports.filtered",
    "filtered-ports": "fetcher.ports.filtered",
    "ports.filtered": "fetcher.ports.filtered",
    "mac": "fetcher.mac",
    "vendor": "fetcher.mac.vendor",
    "mac-vendor": "fetcher.mac.vendor",
    "mac.vendor": "fetcher.mac.vendor",
    "comment": "fetcher.comment",
    "comments": "fetcher.comment",
    "webdetect": "fetcher.webDetect",
    "web-detect": "fetcher.webDetect",
    "httpsender": "fetcher.httpSender",
    "http-sender": "fetcher.httpSender",
    "httpproxy": "fetcher.httpProxy",
    "http-proxy": "fetcher.httpProxy",
    "netbios": "fetcher.netbios",
}


def normalize_fetcher_id(fetcher_id: str) -> str:
    """Resolve short aliases or full IDs to Angry IP Scanner's canonical fetcher ID."""
    raw = fetcher_id.strip()
    if raw in FETCHER_CATALOG:
        return raw
    lower = raw.lower()
    if lower in _FETCHER_ALIASES:
        return _FETCHER_ALIASES[lower]
    for fid in FETCHER_CATALOG:
        if fid.lower() == lower or fid.lower() == f"fetcher.{lower}":
            return fid
    valid = ", ".join(FETCHER_CATALOG.keys())
    raise ValueError(f"Unknown fetcher '{fetcher_id}'. Available fetchers: {valid}")


def list_available_fetchers() -> List[Dict[str, Any]]:
    """Return metadata for all 14 Angry IP Scanner fetchers."""
    return [
        {"id": fid, **meta}
        for fid, meta in FETCHER_CATALOG.items()
    ]


def list_selected_fetchers(project: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return ordered list of currently selected fetchers in the project."""
    out: List[Dict[str, Any]] = []
    for idx, fid in enumerate(project.get("selected_fetchers", [])):
        meta = FETCHER_CATALOG.get(fid, {"name": fid, "mandatory": False, "pref_node": None, "description": ""})
        out.append({"index": idx, "id": fid, **meta})
    return out


def select_fetchers(project: Dict[str, Any], fetcher_ids: List[str]) -> List[str]:
    """Replace the project's selected fetchers list, ensuring ``fetcher.ip`` is first."""
    normalized: List[str] = []
    for raw in fetcher_ids:
        fid = normalize_fetcher_id(raw)
        if fid not in normalized:
            normalized.append(fid)

    # Angry IP Scanner treats fetcher.ip as mandatory at column 0
    if "fetcher.ip" in normalized:
        normalized.remove("fetcher.ip")
    normalized.insert(0, "fetcher.ip")

    project["selected_fetchers"] = normalized
    return list(normalized)


def add_fetcher(project: Dict[str, Any], fetcher_id: str, position: Optional[int] = None) -> List[str]:
    """Add a fetcher to the selected list if not already present."""
    fid = normalize_fetcher_id(fetcher_id)
    selected: List[str] = list(project.get("selected_fetchers", ["fetcher.ip"]))
    if fid in selected:
        return selected

    if position is None or position >= len(selected):
        selected.append(fid)
    else:
        idx = max(1, position)  # Keep fetcher.ip at index 0
        selected.insert(idx, fid)

    project["selected_fetchers"] = selected
    return list(selected)


def remove_fetcher(project: Dict[str, Any], fetcher_id: str) -> List[str]:
    """Remove a non-mandatory fetcher from the selected list."""
    fid = normalize_fetcher_id(fetcher_id)
    if fid == "fetcher.ip":
        raise ValueError("Cannot remove mandatory fetcher 'fetcher.ip'.")
    selected: List[str] = list(project.get("selected_fetchers", ["fetcher.ip"]))
    if fid not in selected:
        raise ValueError(f"Fetcher '{fid}' is not currently selected.")
    selected.remove(fid)
    project["selected_fetchers"] = selected
    return list(selected)


def move_fetcher(project: Dict[str, Any], fetcher_id: str, new_index: int) -> List[str]:
    """Move a selected fetcher to a new column index (index 0 is reserved for fetcher.ip)."""
    fid = normalize_fetcher_id(fetcher_id)
    if fid == "fetcher.ip":
        raise ValueError("Mandatory fetcher 'fetcher.ip' must remain at index 0.")
    selected: List[str] = list(project.get("selected_fetchers", ["fetcher.ip"]))
    if fid not in selected:
        raise ValueError(f"Fetcher '{fid}' is not currently selected.")
    if new_index < 1 or new_index >= len(selected):
        raise ValueError(f"Target index must be between 1 and {len(selected) - 1}.")
    selected.remove(fid)
    selected.insert(new_index, fid)
    project["selected_fetchers"] = selected
    return list(selected)


def get_fetcher_prefs(project: Dict[str, Any], fetcher_id: Optional[str] = None) -> Dict[str, Any]:
    """Return fetcher-specific preferences (all or for a single fetcher)."""
    all_prefs = project.get("fetcher_prefs", {})
    if fetcher_id is None:
        return copy.deepcopy(all_prefs)
    fid = normalize_fetcher_id(fetcher_id)
    node = FETCHER_CATALOG[fid]["pref_node"]
    if not node:
        return {}
    return copy.deepcopy(all_prefs.get(node, {}))


def set_fetcher_pref(project: Dict[str, Any], fetcher_id: str, key: str, value: Any) -> Dict[str, Any]:
    """Set a fetcher-specific preference key (e.g., ``mac`` separator or ``webDetect`` regex)."""
    fid = normalize_fetcher_id(fetcher_id)
    node = FETCHER_CATALOG[fid]["pref_node"]
    if not node:
        raise ValueError(f"Fetcher '{fid}' has no configurable preferences.")

    valid_keys = {
        "mac": {"separator"},
        "webDetect": {"textToSend", "matchingRegexp", "extractGroup"},
        "httpSender": {"textToSend", "matchingRegexp", "extractGroup"},
        "httpProxy": {"textToSend", "matchingRegexp", "extractGroup"},
    }
    if key not in valid_keys.get(node, set()):
        allowed = ", ".join(sorted(valid_keys.get(node, set())))
        raise ValueError(f"Invalid preference key '{key}' for {fid}. Allowed keys: {allowed}")

    if key == "extractGroup":
        value = int(value)
        if value < 0:
            raise ValueError("extractGroup must be >= 0")

    prefs = project.setdefault("fetcher_prefs", {})
    node_prefs = prefs.setdefault(node, {})
    node_prefs[key] = value
    return copy.deepcopy(node_prefs)
