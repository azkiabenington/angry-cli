"""Scan orchestration invoking the real Angry IP Scanner Java backend."""

import copy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from angry_cli.utils import backend as ipscan_backend


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_bridge_request(
    project: Dict[str, Any],
    target_override: Optional[Dict[str, Any]] = None,
    export_spec: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a HeadlessBridge scan request payload from a project dictionary."""
    target = copy.deepcopy(target_override if target_override is not None else project.get("target"))
    if not target or "feeder" not in target:
        raise ValueError("Project has no valid scan target configured.")

    req: Dict[str, Any] = {
        "target": target,
        "scanner_config": copy.deepcopy(project.get("scanner_config", {})),
        "selected_fetchers": list(project.get("selected_fetchers", ["fetcher.ip"])),
        "fetcher_prefs": copy.deepcopy(project.get("fetcher_prefs", {})),
        "comments": copy.deepcopy(project.get("comments", {})),
    }
    if export_spec is not None:
        req["export"] = copy.deepcopy(export_spec)
    return req


def execute_scan(
    project: Dict[str, Any],
    target_override: Optional[Dict[str, Any]] = None,
    export_spec: Optional[Dict[str, Any]] = None,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Execute a real Angry IP Scanner scan and store results on the project.

    Args:
        project: Active project dictionary (mutated in place with ``last_scan`` and ``scan_history``).
        target_override: Optional temporary feeder target overriding ``project['target']``.
        export_spec: Optional native export dict (``output_path``, ``append``, ``filter``).
        timeout: Subprocess timeout in seconds.

    Returns:
        Structured scan record stored in ``project['last_scan']``.
    """
    req = build_bridge_request(project, target_override=target_override, export_spec=export_spec)
    raw = ipscan_backend.run_scan(req, timeout=timeout)

    scan_record: Dict[str, Any] = {
        "timestamp": _now_iso(),
        "engine": raw.get("engine"),
        "feeder_name": raw.get("feeder_name"),
        "feeder_info": raw.get("feeder_info"),
        "target": req["target"],
        "pinger": raw.get("pinger"),
        "fetchers": raw.get("fetchers", []),
        "stats": raw.get("stats", {}),
        "results": raw.get("results", []),
    }
    if "export" in raw:
        scan_record["export"] = raw["export"]

    project["last_scan"] = scan_record
    history = project.setdefault("scan_history", [])
    history.append({
        "timestamp": scan_record["timestamp"],
        "feeder_name": scan_record["feeder_name"],
        "feeder_info": scan_record["feeder_info"],
        "pinger": scan_record["pinger"],
        "stats": copy.deepcopy(scan_record["stats"]),
    })
    if len(history) > 100:
        del history[:-100]

    return scan_record


def execute_rescan(
    project: Dict[str, Any],
    ips: Optional[List[str]] = None,
    only_alive: bool = False,
    timeout: int = 300,
) -> Dict[str, Any]:
    """Rescan specific IP addresses using Angry IP Scanner's real RescanFeeder."""
    target_ips: List[str] = []
    if ips:
        target_ips = [ip.strip() for ip in ips if ip.strip()]
    else:
        last_scan = project.get("last_scan")
        if not isinstance(last_scan, dict) or not last_scan.get("results"):
            raise ValueError("No previous scan results to rescan. Provide explicit IPs or run `scan run` first.")
        for row in last_scan["results"]:
            if only_alive and row.get("type") not in ("ALIVE", "WITH_PORTS"):
                continue
            target_ips.append(row["ip"])

    if not target_ips:
        raise ValueError("No matching IP addresses found to rescan.")

    rescan_target = {
        "feeder": "rescan",
        "ips": target_ips,
    }
    return execute_scan(project, target_override=rescan_target, timeout=timeout)


def get_scan_status(project: Dict[str, Any]) -> Dict[str, Any]:
    """Return summary of the latest scan and historical scan runs in this project."""
    last_scan = project.get("last_scan")
    if not isinstance(last_scan, dict):
        return {
            "has_results": False,
            "target": copy.deepcopy(project.get("target")),
            "history_count": len(project.get("scan_history", [])),
            "last_scan": None,
        }

    return {
        "has_results": True,
        "target": copy.deepcopy(project.get("target")),
        "history_count": len(project.get("scan_history", [])),
        "last_scan": {
            "timestamp": last_scan.get("timestamp"),
            "engine": last_scan.get("engine"),
            "feeder_name": last_scan.get("feeder_name"),
            "feeder_info": last_scan.get("feeder_info"),
            "pinger": last_scan.get("pinger"),
            "stats": copy.deepcopy(last_scan.get("stats", {})),
            "result_count": len(last_scan.get("results", [])),
        },
    }
