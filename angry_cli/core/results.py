"""Result inspection, filtering, searching, sorting, and statistics for scan results."""

from __future__ import annotations

import copy
import ipaddress
from typing import Any, Optional

from angry_cli.core.fetchers import normalize_fetcher_id


def _require_last_scan(project: dict[str, Any]) -> dict[str, Any]:
    last_scan = project.get("last_scan")
    if not isinstance(last_scan, dict):
        raise RuntimeError("No scan results available in project. Run `scan run` first.")
    return last_scan


def list_results(
    project: dict[str, Any],
    limit: Optional[int] = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Return scan result rows with fetcher column metadata."""
    scan = _require_last_scan(project)
    rows = scan.get("results", [])
    sliced = rows[offset : (offset + limit if limit is not None else None)]
    return {
        "total": len(rows),
        "offset": offset,
        "returned": len(sliced),
        "fetchers": copy.deepcopy(scan.get("fetchers", [])),
        "results": copy.deepcopy(sliced),
    }


def get_host_detail(project: dict[str, Any], ip: str) -> dict[str, Any]:
    """Return full fetcher details for a single scanned IP address."""
    scan = _require_last_scan(project)
    target = ip.strip()
    for row in scan.get("results", []):
        if row.get("ip") == target:
            return copy.deepcopy(row)
    raise KeyError(f"IP address '{target}' not found in latest scan results.")


def filter_results(
    project: dict[str, Any],
    status: str = "all",
    port: Optional[int] = None,
    has_mac: bool = False,
) -> list[dict[str, Any]]:
    """Filter scan results by host status, open port, or MAC availability."""
    scan = _require_last_scan(project)
    mode = status.strip().lower()
    valid_modes = {"all", "alive", "dead", "with_ports", "ports"}
    if mode not in valid_modes:
        raise ValueError(f"Invalid status filter '{status}'. Valid values: {', '.join(sorted(valid_modes))}")

    matched: list[dict[str, Any]] = []
    for row in scan.get("results", []):
        rtype = row.get("type", "UNKNOWN")
        if mode == "alive" and rtype not in ("ALIVE", "WITH_PORTS"):
            continue
        if mode in ("with_ports", "ports") and rtype != "WITH_PORTS":
            continue
        if mode == "dead" and rtype not in ("DEAD", "UNKNOWN"):
            continue

        vals = row.get("values", {})
        if port is not None:
            ports_val = str(vals.get("fetcher.ports", "") or "")
            if not _port_present(ports_val, port):
                continue

        if has_mac:
            mac_val = row.get("mac") or vals.get("fetcher.mac")
            if not mac_val or str(mac_val).startswith("["):
                continue

        matched.append(copy.deepcopy(row))
    return matched


def _port_present(ports_text: str, target_port: int) -> bool:
    """Return True if target_port is listed inside an Angry IP Scanner port range string."""
    if not ports_text or ports_text.startswith("["):
        return False
    for part in ports_text.split(","):
        token = part.strip()
        if "-" in token:
            bounds = token.split("-", 1)
            if bounds[0].isdigit() and bounds[1].isdigit():
                if int(bounds[0]) <= target_port <= int(bounds[1]):
                    return True
        elif token.isdigit() and int(token) == target_port:
            return True
    return False


def search_results(project: dict[str, Any], query: str) -> list[dict[str, Any]]:
    """Case-insensitive substring search across all fetcher values (mirrors ScanningResultList.findText)."""
    scan = _require_last_scan(project)
    needle = query.strip().lower()
    if not needle:
        raise ValueError("Search query cannot be empty.")

    matched: list[dict[str, Any]] = []
    for row in scan.get("results", []):
        if needle in str(row.get("ip", "")).lower():
            matched.append(copy.deepcopy(row))
            continue
        vals = row.get("values", {})
        if any(needle in str(v).lower() for v in vals.values() if v is not None):
            matched.append(copy.deepcopy(row))
    return matched


def sort_results(project: dict[str, Any], by: str = "fetcher.ip", descending: bool = False) -> list[dict[str, Any]]:
    """Sort stored scan results in place by any fetcher column (mirrors ScanningResultList.sort)."""
    scan = _require_last_scan(project)
    fid = normalize_fetcher_id(by)
    rows = scan.get("results", [])

    def _sort_key(row: dict[str, Any]) -> tuple[int, Any]:
        if fid == "fetcher.ip":
            try:
                return (0, int(ipaddress.ip_address(row["ip"])))
            except ValueError:
                return (1, row.get("ip", ""))
        val = row.get("values", {}).get(fid)
        if val is None or str(val).startswith("["):
            return (1, "")
        text = str(val)
        # Numeric extraction for ping ms / TTL / packet loss
        if fid == "fetcher.ping" and text.endswith(" ms"):
            try:
                return (0, float(text[:-3].strip()))
            except ValueError:
                pass
        if text.isdigit():
            return (0, int(text))
        return (0, text.lower())

    rows.sort(key=_sort_key, reverse=descending)
    return copy.deepcopy(rows)


def get_result_stats(project: dict[str, Any]) -> dict[str, Any]:
    """Compute aggregate statistics over the latest scan results."""
    scan = _require_last_scan(project)
    rows = scan.get("results", [])
    alive = sum(1 for r in rows if r.get("type") in ("ALIVE", "WITH_PORTS"))
    with_ports = sum(1 for r in rows if r.get("type") == "WITH_PORTS")
    dead = sum(1 for r in rows if r.get("type") in ("DEAD", "UNKNOWN"))

    open_port_counts: dict[int, int] = {}
    for row in rows:
        ports_text = str(row.get("values", {}).get("fetcher.ports", "") or "")
        if ports_text and not ports_text.startswith("["):
            for part in ports_text.split(","):
                tok = part.strip()
                if "-" in tok:
                    b = tok.split("-", 1)
                    if b[0].isdigit() and b[1].isdigit():
                        for p in range(int(b[0]), int(b[1]) + 1):
                            open_port_counts[p] = open_port_counts.get(p, 0) + 1
                elif tok.isdigit():
                    p = int(tok)
                    open_port_counts[p] = open_port_counts.get(p, 0) + 1

    base_stats = scan.get("stats", {})
    return {
        "total_hosts": len(rows),
        "alive_hosts": alive,
        "with_ports_hosts": with_ports,
        "dead_hosts": dead,
        "scan_time_ms": base_stats.get("scan_time_ms", 0),
        "feeder_info": scan.get("feeder_info"),
        "pinger": scan.get("pinger"),
        "top_open_ports": sorted(
            [{"port": p, "count": c} for p, c in open_port_counts.items()],
            key=lambda x: (-x["count"], x["port"]),
        ),
    }


def clear_results(project: dict[str, Any]) -> dict[str, Any]:
    """Clear the latest scan results from the project."""
    prev = len(project.get("last_scan", {}).get("results", [])) if isinstance(project.get("last_scan"), dict) else 0
    project["last_scan"] = None
    return {"cleared_rows": prev}
