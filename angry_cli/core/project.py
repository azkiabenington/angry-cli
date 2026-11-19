"""Project lifecycle and scan profile management for Angry IP Scanner CLI."""

import copy
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from angry_cli.core.session import _locked_save_json


SCHEMA_VERSION = "1.0.0"

DEFAULT_PINGER = "pinger.windows" if sys.platform == "win32" else "pinger.java"

DEFAULT_SCANNER_CONFIG: Dict[str, Any] = {
    "max_threads": 100,
    "thread_delay": 20,
    "scan_dead_hosts": False,
    "selected_pinger": DEFAULT_PINGER,
    "ping_timeout": 2000,
    "ping_count": 3,
    "skip_broadcast_addresses": True,
    "port_timeout": 2000,
    "adapt_port_timeout": True,
    "min_port_timeout": 100,
    "port_string": "80,443,8080",
    "use_requested_ports": True,
    "not_available_text": "[n/a]",
    "not_scanned_text": "[n/s]",
}

DEFAULT_FETCHERS: List[str] = [
    "fetcher.ip",
    "fetcher.ping",
    "fetcher.hostname",
    "fetcher.ports",
    "fetcher.mac",
    "fetcher.mac.vendor",
    "fetcher.comment",
]

DEFAULT_FETCHER_PREFS: Dict[str, Dict[str, Any]] = {
    "mac": {"separator": ":"},
    "webDetect": {
        "textToSend": "HEAD /robots.txt HTTP/1.0\r\n\r\n",
        "matchingRegexp": "^[Ss]erver:\\s+(.*)$",
        "extractGroup": 1,
    },
    "httpSender": {
        "textToSend": "HEAD / HTTP/1.0\r\n\r\n",
        "matchingRegexp": "Date: (.*)$",
        "extractGroup": 1,
    },
    "httpProxy": {
        "textToSend": "HEAD http://www.google.com HTTP/1.0\r\n\r\n",
        "matchingRegexp": "^(HTTP/[\\d\\.]+ [23].*)$",
        "extractGroup": 1,
    },
}

DEFAULT_OPENERS: Dict[str, Dict[str, Any]] = {
    "Web Browser": {"exec_string": "http://${fetcher.hostname}/", "in_terminal": False, "working_dir": None},
    "FTP": {"exec_string": "ftp://${fetcher.hostname}/", "in_terminal": False, "working_dir": None},
    "Ping": {"exec_string": "ping ${fetcher.ip}", "in_terminal": True, "working_dir": None},
    "SSH": {"exec_string": "ssh ${fetcher.ip}", "in_terminal": True, "working_dir": None},
    "Traceroute": {
        "exec_string": ("tracert ${fetcher.ip}" if sys.platform == "win32" else "traceroute ${fetcher.ip}"),
        "in_terminal": True,
        "working_dir": None,
    },
}

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "default": {
        "description": "Standard Angry IP Scanner defaults (IP, Ping, Hostname, Ports, MAC, Vendor, Comments)",
        "selected_fetchers": list(DEFAULT_FETCHERS),
        "scanner_config": dict(DEFAULT_SCANNER_CONFIG),
    },
    "quick-ping": {
        "description": "Fast host discovery with IP, Ping, TTL, and Hostname (no port scanning)",
        "selected_fetchers": [
            "fetcher.ip",
            "fetcher.ping",
            "fetcher.ping.ttl",
            "fetcher.hostname",
        ],
        "scanner_config": {
            **DEFAULT_SCANNER_CONFIG,
            "ping_count": 2,
            "ping_timeout": 1000,
            "max_threads": 150,
            "thread_delay": 5,
        },
    },
    "lan-audit": {
        "description": "Local network inventory (IP, Ping, Hostname, Ports, MAC, MAC Vendor, NetBIOS, Comments)",
        "selected_fetchers": [
            "fetcher.ip",
            "fetcher.ping",
            "fetcher.hostname",
            "fetcher.ports",
            "fetcher.mac",
            "fetcher.mac.vendor",
            "fetcher.netbios",
            "fetcher.comment",
        ],
        "scanner_config": {
            **DEFAULT_SCANNER_CONFIG,
            "port_string": "22,80,139,443,445,3389,8080",
            "ping_timeout": 1500,
            "port_timeout": 1500,
        },
    },
    "web-discovery": {
        "description": "HTTP/HTTPS web server and proxy discovery (IP, Ping, Hostname, Ports, Web Detect, HTTP Proxy)",
        "selected_fetchers": [
            "fetcher.ip",
            "fetcher.ping",
            "fetcher.hostname",
            "fetcher.ports",
            "fetcher.webDetect",
            "fetcher.httpProxy",
        ],
        "scanner_config": {
            **DEFAULT_SCANNER_CONFIG,
            "port_string": "80,443,3128,8000,8080,8443",
            "port_timeout": 2000,
        },
    },
    "full-audit": {
        "description": "Comprehensive scan with all 14 Angry IP Scanner fetchers enabled",
        "selected_fetchers": [
            "fetcher.ip",
            "fetcher.ping",
            "fetcher.ping.ttl",
            "fetcher.packetloss",
            "fetcher.hostname",
            "fetcher.ports",
            "fetcher.ports.filtered",
            "fetcher.mac",
            "fetcher.mac.vendor",
            "fetcher.netbios",
            "fetcher.webDetect",
            "fetcher.httpSender",
            "fetcher.httpProxy",
            "fetcher.comment",
        ],
        "scanner_config": {
            **DEFAULT_SCANNER_CONFIG,
            "port_string": "21,22,23,25,53,80,110,139,143,443,445,3128,3389,8080,8443",
            "ping_count": 3,
        },
    },
}


def _now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def list_profiles() -> List[Dict[str, Any]]:
    """Return all built-in scan profiles with metadata."""
    out: List[Dict[str, Any]] = []
    for name, spec in SCAN_PROFILES.items():
        out.append({
            "name": name,
            "description": spec["description"],
            "fetchers": list(spec["selected_fetchers"]),
            "ports": spec["scanner_config"]["port_string"],
            "pinger": spec["scanner_config"]["selected_pinger"],
        })
    return out


def create_project(
    name: str = "Untitled Scan",
    profile: str = "default",
    start_ip: str = "127.0.0.1",
    end_ip: str = "127.0.0.1",
) -> Dict[str, Any]:
    """Create a new Angry IP Scanner project dictionary.

    Args:
        name: Human-friendly project name.
        profile: Profile key from ``SCAN_PROFILES``.
        start_ip: Initial range feeder start IP.
        end_ip: Initial range feeder end IP.

    Returns:
        Newly initialized project state dictionary.
    """
    if profile not in SCAN_PROFILES:
        valid = ", ".join(SCAN_PROFILES.keys())
        raise ValueError(f"Unknown profile '{profile}'. Valid profiles: {valid}")

    spec = SCAN_PROFILES[profile]
    now = _now_iso()
    return {
        "schema_version": SCHEMA_VERSION,
        "name": name,
        "profile": profile,
        "created_at": now,
        "modified_at": now,
        "target": {
            "feeder": "range",
            "start_ip": start_ip,
            "end_ip": end_ip,
        },
        "scanner_config": copy.deepcopy(spec["scanner_config"]),
        "selected_fetchers": list(spec["selected_fetchers"]),
        "fetcher_prefs": copy.deepcopy(DEFAULT_FETCHER_PREFS),
        "comments": {},
        "favorites": {},
        "openers": copy.deepcopy(DEFAULT_OPENERS),
        "last_scan": None,
        "scan_history": [],
    }


def open_project(path: str) -> Dict[str, Any]:
    """Load and validate a project JSON file from disk."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Project file not found: {path}")

    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or "scanner_config" not in data or "selected_fetchers" not in data:
        raise ValueError(f"Invalid Angry IP Scanner project file: {path}")

    # Backfill optional fields cleanly
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("name", p.stem)
    data.setdefault("profile", "default")
    data.setdefault("target", {"feeder": "range", "start_ip": "127.0.0.1", "end_ip": "127.0.0.1"})
    data.setdefault("fetcher_prefs", copy.deepcopy(DEFAULT_FETCHER_PREFS))
    data.setdefault("comments", {})
    data.setdefault("favorites", {})
    data.setdefault("openers", copy.deepcopy(DEFAULT_OPENERS))
    data.setdefault("last_scan", None)
    data.setdefault("scan_history", [])
    return data


def save_project(project: Dict[str, Any], path: str) -> str:
    """Persist a project dictionary atomically to disk using file locking."""
    project["modified_at"] = _now_iso()
    abs_path = os.path.abspath(path)
    _locked_save_json(abs_path, project, indent=2, ensure_ascii=False)
    return abs_path


def get_project_info(project: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """Return a concise summary of a project's configuration and latest scan."""
    last_scan = project.get("last_scan")
    scan_summary = None
    if isinstance(last_scan, dict):
        stats = last_scan.get("stats", {})
        scan_summary = {
            "timestamp": last_scan.get("timestamp"),
            "engine": last_scan.get("engine"),
            "feeder_info": last_scan.get("feeder_info"),
            "host_count": stats.get("host_count", 0),
            "alive_count": stats.get("alive_count", 0),
            "with_ports_count": stats.get("with_ports_count", 0),
            "dead_count": stats.get("dead_count", 0),
            "scan_time_ms": stats.get("scan_time_ms", 0),
        }

    return {
        "name": project.get("name"),
        "profile": project.get("profile"),
        "schema_version": project.get("schema_version"),
        "path": os.path.abspath(path) if path else None,
        "created_at": project.get("created_at"),
        "modified_at": project.get("modified_at"),
        "target": copy.deepcopy(project.get("target")),
        "pinger": project.get("scanner_config", {}).get("selected_pinger"),
        "ports": project.get("scanner_config", {}).get("port_string"),
        "max_threads": project.get("scanner_config", {}).get("max_threads"),
        "selected_fetchers": list(project.get("selected_fetchers", [])),
        "comment_count": len(project.get("comments", {})),
        "favorite_count": len(project.get("favorites", {})),
        "opener_count": len(project.get("openers", {})),
        "scan_history_count": len(project.get("scan_history", [])),
        "last_scan": scan_summary,
    }
