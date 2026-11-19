"""Export pipeline delegating to Angry IP Scanner's real ExporterRegistry & ExportProcessor."""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from angry_cli.core.results import _require_last_scan, filter_results
from angry_cli.utils import backend as ipscan_backend


EXPORT_PRESETS: dict[str, dict[str, Any]] = {
    "csv": {
        "extension": "csv",
        "exporter_id": "exporter.csv",
        "native_backend": True,
        "supports_append": True,
        "description": "RFC 4180 comma-separated values via Angry IP Scanner CSVExporter.",
    },
    "txt": {
        "extension": "txt",
        "exporter_id": "exporter.txt",
        "native_backend": True,
        "supports_append": True,
        "description": "Fixed-width aligned text report via Angry IP Scanner TXTExporter (re-importable).",
    },
    "xml": {
        "extension": "xml",
        "exporter_id": "exporter.xml",
        "native_backend": True,
        "supports_append": False,
        "description": "XML scanning_report document via Angry IP Scanner XMLExporter.",
    },
    "lst": {
        "extension": "lst",
        "exporter_id": "exporter.ipList",
        "native_backend": True,
        "supports_append": True,
        "description": "IP:Port list (one pair per line) via Angry IP Scanner IPListExporter.",
    },
    "sql": {
        "extension": "sql",
        "exporter_id": "exporter.sql",
        "native_backend": True,
        "supports_append": True,
        "description": "SQL CREATE TABLE + INSERT statements via Angry IP Scanner SQLExporter.",
    },
    "json": {
        "extension": "json",
        "exporter_id": "angry_cli.json",
        "native_backend": False,
        "supports_append": False,
        "description": "Agent-native structured JSON export containing metadata, stats, and host rows.",
    },
}


def list_export_presets() -> list[dict[str, Any]]:
    """Return all supported export formats and their capabilities."""
    return [{"name": k, **v} for k, v in EXPORT_PRESETS.items()]


def _infer_preset(output_path: str, preset: Optional[str]) -> str:
    if preset:
        key = preset.strip().lower().lstrip(".")
        if key not in EXPORT_PRESETS:
            valid = ", ".join(EXPORT_PRESETS.keys())
            raise ValueError(f"Unknown export preset '{preset}'. Valid presets: {valid}")
        return key
    ext = Path(output_path).suffix.lower().lstrip(".")
    if ext in EXPORT_PRESETS:
        return ext
    valid = ", ".join(EXPORT_PRESETS.keys())
    raise ValueError(
        f"Cannot infer export preset from extension '.{ext}' in '{output_path}'. "
        f"Specify --preset ({valid}) or use a matching file extension."
    )


def render(
    project: dict[str, Any],
    output_path: str,
    preset: Optional[str] = None,
    filter_mode: str = "all",
    append: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export project scan results via Angry IP Scanner's real exporters (or JSON).

    For ``csv``, ``txt``, ``xml``, ``lst``, and ``sql``, this delegates directly
    to Angry IP Scanner's real ``ExportProcessor`` + ``ExporterRegistry`` inside
    the Java engine so output matches Angry IP Scanner byte-for-format.

    Args:
        project: Active project dictionary containing ``last_scan``.
        output_path: Destination output file path.
        preset: Export preset name (``csv``, ``txt``, ``xml``, ``lst``, ``sql``, ``json``).
        filter_mode: Row filter (``all``, ``alive``, ``with_ports``, ``dead``).
        append: Append to an existing file (not supported for ``xml`` or ``json``).
        overwrite: Overwrite existing file if ``append`` is False.

    Returns:
        Structured export metadata including absolute output path and file size.
    """
    scan = _require_last_scan(project)
    fmt = _infer_preset(output_path, preset)
    spec = EXPORT_PRESETS[fmt]

    abs_out = os.path.abspath(output_path)
    if os.path.exists(abs_out) and not overwrite and not append:
        raise FileExistsError(
            f"Output file already exists: {abs_out}. Pass --overwrite or --append."
        )
    if append and not spec["supports_append"]:
        raise ValueError(f"Export format '{fmt}' does not support --append.")

    # Ensure extension matches Angry IP Scanner ExporterRegistry when native
    expected_ext = f".{spec['extension']}"
    if spec["native_backend"] and not abs_out.lower().endswith(expected_ext):
        raise ValueError(
            f"Angry IP Scanner's {spec['exporter_id']} requires output filename ending with '{expected_ext}' "
            f"(got '{output_path}')."
        )

    if not spec["native_backend"]:
        # Agent-native JSON export
        parent = os.path.dirname(abs_out)
        if parent:
            os.makedirs(parent, exist_ok=True)
        rows = filter_results(project, status=filter_mode)
        payload = {
            "project": project.get("name"),
            "engine": scan.get("engine"),
            "timestamp": scan.get("timestamp"),
            "feeder_name": scan.get("feeder_name"),
            "feeder_info": scan.get("feeder_info"),
            "pinger": scan.get("pinger"),
            "filter": filter_mode,
            "fetchers": scan.get("fetchers", []),
            "stats": scan.get("stats", {}),
            "exported_rows": len(rows),
            "results": rows,
        }
        with open(abs_out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return {
            "output": abs_out,
            "format": "json",
            "exporter_id": spec["exporter_id"],
            "method": "angry-cli-json",
            "filter": filter_mode,
            "append": False,
            "exported_rows": len(rows),
            "file_size": os.path.getsize(abs_out),
        }

    # Delegate to the REAL Angry IP Scanner ExportProcessor + ExporterRegistry
    used_fetcher_ids = [f["id"] for f in scan.get("fetchers", []) if "id" in f]
    if not used_fetcher_ids:
        used_fetcher_ids = list(project.get("selected_fetchers", ["fetcher.ip"]))

    if fmt == "lst" and "fetcher.ports" not in used_fetcher_ids:
        raise ValueError(
            "Angry IP Scanner's IPListExporter (.lst) requires 'fetcher.ports' to be included in the scan."
        )

    bridge_req = {
        "scanner_config": copy.deepcopy(project.get("scanner_config", {})),
        "selected_fetchers": used_fetcher_ids,
        "fetcher_prefs": copy.deepcopy(project.get("fetcher_prefs", {})),
        "feeder_name": scan.get("feeder_name", "IP Range"),
        "feeder_info": scan.get("feeder_info", "CLI Export"),
        "results": scan.get("results", []),
        "export": {
            "output_path": abs_out,
            "append": bool(append),
            "filter": filter_mode,
        },
    }
    res = ipscan_backend.run_export(bridge_req)
    exp = res["export"]
    return {
        "output": exp["output_path"],
        "format": exp["format"],
        "exporter_id": exp["exporter_id"],
        "method": "angry-ip-scanner-native",
        "engine": res.get("engine"),
        "filter": exp["filter"],
        "append": exp["append"],
        "exported_rows": exp["exported_rows"],
        "file_size": exp["file_size"],
    }


def import_txt_results(project: dict[str, Any], txt_path: str) -> dict[str, Any]:
    """Import an Angry IP Scanner ``.txt`` export file back into project results.

    Mirrors ``net.azib.ipscan.exporters.TXTExporter.importResults()``.
    """
    p = Path(txt_path)
    if not p.is_file():
        raise FileNotFoundError(f"TXT export file not found: {txt_path}")

    label_to_id = {
        "IP": "fetcher.ip",
        "Ping": "fetcher.ping",
        "TTL": "fetcher.ping.ttl",
        "Packet Loss": "fetcher.packetloss",
        "Hostname": "fetcher.hostname",
        "Ports": "fetcher.ports",
        "Filtered Ports": "fetcher.ports.filtered",
        "MAC Address": "fetcher.mac",
        "MAC Vendor": "fetcher.mac.vendor",
        "Comments": "fetcher.comment",
        "Web detect": "fetcher.webDetect",
        "HTTP Sender": "fetcher.httpSender",
        "HTTP Proxy": "fetcher.httpProxy",
        "NetBIOS Info": "fetcher.netbios",
    }

    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    feeder_info = str(p.name)
    columns: list[str] = []
    fetcher_ids: list[str] = []
    rows: list[dict[str, Any]] = []
    header_found = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Scanned "):
            feeder_info = stripped[len("Scanned "):].strip()
            continue
        if not header_found:
            if stripped.startswith("IP"):
                parts = [c.strip() for c in re.split(r"\s{2,}", stripped) if c.strip()]
                if parts and parts[0] == "IP":
                    columns = parts
                    fetcher_ids = [label_to_id.get(c, c) for c in columns]
                    header_found = True
            continue

        parts = [c.strip() for c in re.split(r"\s{2,}", line.rstrip()) if c.strip()]
        if len(parts) < len(columns):
            continue
        ip_str = parts[0]
        values_map = {fetcher_ids[i]: parts[i] for i in range(len(columns))}
        ping_val = values_map.get("fetcher.ping", "")
        ports_val = values_map.get("fetcher.ports", "")
        if ports_val and re.match(r"^\d", ports_val):
            rtype = "WITH_PORTS"
        elif ping_val and re.match(r"^\d", ping_val):
            rtype = "ALIVE"
        else:
            rtype = "DEAD"

        mac_val = values_map.get("fetcher.mac")
        if mac_val and mac_val.startswith("["):
            mac_val = None

        rows.append({
            "ip": ip_str,
            "type": rtype,
            "mac": mac_val,
            "values": values_map,
        })

    if not header_found:
        raise ValueError(f"Could not find Angry IP Scanner TXT column header in: {txt_path}")

    alive_count = sum(1 for r in rows if r["type"] in ("ALIVE", "WITH_PORTS"))
    ports_count = sum(1 for r in rows if r["type"] == "WITH_PORTS")
    project["last_scan"] = {
        "timestamp": None,
        "engine": "Imported from Angry IP Scanner TXT",
        "feeder_name": "TXT Import",
        "feeder_info": feeder_info,
        "target": copy.deepcopy(project.get("target")),
        "pinger": project.get("scanner_config", {}).get("selected_pinger"),
        "fetchers": [{"id": fid, "name": col, "full_name": col} for fid, col in zip(fetcher_ids, columns)],
        "stats": {
            "host_count": len(rows),
            "alive_count": alive_count,
            "with_ports_count": ports_count,
            "dead_count": len(rows) - alive_count,
            "scan_time_ms": 0,
            "completed_normally": True,
        },
        "results": rows,
    }
    return {
        "source": str(p.resolve()),
        "feeder_info": feeder_info,
        "columns": columns,
        "imported_rows": len(rows),
        "alive_count": alive_count,
        "with_ports_count": ports_count,
    }
