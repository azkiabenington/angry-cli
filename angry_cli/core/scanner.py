"""Scan orchestration invoking the real Angry IP Scanner Java backend."""

from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from angry_cli.utils import backend as ipscan_backend


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_hostname_fetcher(selected_fetchers: List[str]) -> List[str]:
    """Ensure ``fetcher.hostname`` is always included in every scan."""
    fetchers = list(selected_fetchers)
    if "fetcher.hostname" in fetchers:
        return fetchers
    if "fetcher.ping" in fetchers:
        idx = fetchers.index("fetcher.ping") + 1
    elif "fetcher.ip" in fetchers:
        idx = fetchers.index("fetcher.ip") + 1
    else:
        idx = 0
    fetchers.insert(idx, "fetcher.hostname")
    return fetchers


def _resolve_avahi_hostnames(ips: List[str], timeout: float = 1.5) -> Dict[str, str]:
    """Resolve LAN ``.local`` mDNS hostnames in parallel via ``avahi-resolve -a``."""
    avahi_bin = shutil.which("avahi-resolve")
    if not avahi_bin or not ips:
        return {}

    def _query(ip: str) -> Optional[str]:
        try:
            proc = subprocess.run(
                [avahi_bin, "-a", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
            )
            if proc.returncode != 0:
                return None
            out = (proc.stdout or "").strip()
            if not out:
                return None
            parts = out.split()
            name = parts[-1].strip() if parts else ""
            if name and name != ip:
                return name
        except (subprocess.TimeoutExpired, OSError):
            pass
        return None

    resolved: Dict[str, str] = {}
    workers = min(48, len(ips))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, name in zip(ips, pool.map(_query, ips)):
            if name:
                resolved[ip] = name
    return resolved


def _extract_netbios_hostname(netbios_value: Any) -> Optional[str]:
    """Extract computer name from a NetBIOS string like ``DOMAIN\\HOST [MAC]``."""
    if not netbios_value:
        return None
    text = str(netbios_value).strip()
    if "\\" not in text:
        return None
    host_part = text.split("\\", 1)[1]
    host_part = re.sub(r"\s*\[[^\]]*\]\s*$", "", host_part).strip()
    return host_part or None


def _enrich_hostnames(results: List[Dict[str, Any]], scanner_config: Dict[str, Any]) -> None:
    """Fill missing ``fetcher.hostname`` values on alive hosts using NetBIOS and Avahi mDNS."""
    na_text = str(scanner_config.get("not_available_text", "[n/a]"))
    ns_text = str(scanner_config.get("not_scanned_text", "[n/s]"))
    empty_markers = {"", na_text, ns_text}

    unresolved_rows: List[Dict[str, Any]] = []
    for row in results:
        if row.get("type") not in ("ALIVE", "WITH_PORTS"):
            continue
        ip = row.get("ip", "")
        values = row.setdefault("values", {})
        cur = values.get("fetcher.hostname")
        cur_str = "" if cur is None else str(cur).strip()
        if cur_str in empty_markers or cur_str == ip:
            nb_host = _extract_netbios_hostname(values.get("fetcher.netbios"))
            if nb_host:
                values["fetcher.hostname"] = nb_host
            else:
                unresolved_rows.append(row)

    if not unresolved_rows:
        return

    avahi_map = _resolve_avahi_hostnames([row["ip"] for row in unresolved_rows if row.get("ip")])
    for row in unresolved_rows:
        ip = row.get("ip", "")
        if ip in avahi_map:
            row["values"]["fetcher.hostname"] = avahi_map[ip]


def build_bridge_request(
    project: Dict[str, Any],
    target_override: Optional[Dict[str, Any]] = None,
    export_spec: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a HeadlessBridge scan request payload from a project dictionary."""
    target = copy.deepcopy(target_override if target_override is not None else project.get("target"))
    if not target or "feeder" not in target:
        raise ValueError("Project has no valid scan target configured.")

    selected = _ensure_hostname_fetcher(project.get("selected_fetchers", ["fetcher.ip"]))
    req: Dict[str, Any] = {
        "target": target,
        "scanner_config": copy.deepcopy(project.get("scanner_config", {})),
        "selected_fetchers": selected,
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
    req = build_bridge_request(project, target_override=target_override, export_spec=None)
    raw = ipscan_backend.run_scan(req, timeout=timeout)

    results = raw.get("results", [])
    _enrich_hostnames(results, req["scanner_config"])

    scan_record: Dict[str, Any] = {
        "timestamp": _now_iso(),
        "engine": raw.get("engine"),
        "feeder_name": raw.get("feeder_name"),
        "feeder_info": raw.get("feeder_info"),
        "target": req["target"],
        "pinger": raw.get("pinger"),
        "fetchers": raw.get("fetchers", []),
        "stats": raw.get("stats", {}),
        "results": results,
    }
    if export_spec is not None:
        used_fetcher_ids = [f["id"] for f in scan_record["fetchers"] if "id" in f] or list(req["selected_fetchers"])
        exp_res = ipscan_backend.run_export({
            "scanner_config": copy.deepcopy(req["scanner_config"]),
            "selected_fetchers": used_fetcher_ids,
            "fetcher_prefs": copy.deepcopy(req["fetcher_prefs"]),
            "feeder_name": scan_record["feeder_name"] or "IP Range",
            "feeder_info": scan_record["feeder_info"] or "CLI Export",
            "results": results,
            "export": copy.deepcopy(export_spec),
        })
        scan_record["export"] = exp_res["export"]

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
