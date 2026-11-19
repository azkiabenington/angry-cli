"""Main Click CLI and interactive REPL for angry-cli (ipscan)."""

import functools
import json
import os
import shlex
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import click

from angry_cli import __version__
from angry_cli.core import config as config_mod
from angry_cli.core import export as export_mod
from angry_cli.core import fetchers as fetchers_mod
from angry_cli.core import metadata as metadata_mod
from angry_cli.core import project as project_mod
from angry_cli.core import results as results_mod
from angry_cli.core import scanner as scanner_mod
from angry_cli.core import targets as targets_mod
from angry_cli.core.session import Session
from angry_cli.utils import backend as ipscan_backend
from angry_cli.utils.repl_skin import ReplSkin


_session = Session()
_json_output: bool = False
_repl_mode: bool = False


def get_session() -> Session:
    """Return the global CLI session singleton."""
    return _session


def _emit(data: Any, human_lines: Optional[List[str]] = None) -> None:
    """Emit structured JSON when --json is active, else human-readable output."""
    if _json_output:
        click.echo(json.dumps(data, indent=2, ensure_ascii=False))
        return
    if human_lines is not None:
        for line in human_lines:
            click.echo(line)
    else:
        click.echo(json.dumps(data, indent=2, ensure_ascii=False))


def _format_table(headers: List[str], rows: List[List[str]]) -> List[str]:
    """Render a compact aligned text table."""
    if not rows:
        return ["(no rows)"]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    lines = [
        "  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))),
        "  ".join("-" * widths[i] for i in range(len(headers))),
    ]
    for row in rows:
        padded = [
            (row[i] if i < len(row) else "").ljust(widths[i])
            for i in range(len(headers))
        ]
        lines.append("  ".join(padded))
    return lines


def _format_scan_table(fetchers: List[Dict[str, Any]], rows: List[Dict[str, Any]]) -> List[str]:
    """Format Angry IP Scanner scan rows using their selected fetcher headers."""
    if not fetchers:
        headers = ["IP", "Status"]
        table_rows = [[r.get("ip", ""), r.get("type", "")] for r in rows]
        return _format_table(headers, table_rows)

    headers = [f.get("name") or f.get("id", "") for f in fetchers] + ["Status"]
    table_rows = []
    for r in rows:
        vals = r.get("values", {})
        line = [str(vals.get(f["id"], "")) for f in fetchers]
        line.append(str(r.get("type", "")))
        table_rows.append(line)
    return _format_table(headers, table_rows)


def handle_error(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Consistent error handling decorator for all CLI subcommands."""
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if _json_output:
                click.echo(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
            else:
                click.echo(f"Error: {exc}", err=True)
            if not _repl_mode:
                sys.exit(1)
            return None
    return wrapper


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="ipscan")
@click.option("--json", "use_json", is_flag=True, default=False, help="Output structured JSON for agents.")
@click.option("--project", "project_path", type=str, default=None, help="Path to an Angry IP Scanner project file.")
@click.option("--dry-run", "dry_run", is_flag=True, default=False, help="Run without auto-saving changes to disk.")
@click.pass_context
def cli(ctx: click.Context, use_json: bool, project_path: Optional[str], dry_run: bool) -> None:
    """Headless CLI and interactive REPL powered by the real Angry IP Scanner Java engine."""
    global _json_output
    _json_output = use_json
    ctx.ensure_object(dict)
    ctx.obj["use_json"] = use_json
    ctx.obj["project_path"] = project_path
    ctx.obj["dry_run"] = dry_run

    if project_path and not _repl_mode:
        try:
            proj = project_mod.open_project(project_path)
            get_session().set_project(proj, path=project_path, modified=False)
        except Exception as exc:
            if _json_output:
                click.echo(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
            else:
                click.echo(f"Error: {exc}", err=True)
            sys.exit(1)

    if ctx.invoked_subcommand is None:
        ctx.invoke(repl, project_path=project_path)


_cli_result_callback = getattr(cli, "result_callback", None) or getattr(cli, "resultcallback")


@_cli_result_callback()
def auto_save_on_exit(
    result: Any,
    use_json: bool,
    project_path: Optional[str],
    dry_run: bool,
    **kwargs: Any,
) -> None:
    """Auto-save modified projects after one-shot mutations unless --dry-run is active."""
    if _repl_mode or dry_run:
        return
    sess = get_session()
    if sess.has_project() and sess._modified and sess.project_path:
        try:
            sess.save_session()
        except Exception as exc:
            click.echo(f"Warning: Auto-save failed: {exc}", err=True)


# =============================================================================
# PROJECT GROUP
# =============================================================================

@cli.group()
def project() -> None:
    """Create, open, save, and inspect scan projects and profiles."""


@project.command("new")
@click.option("-o", "--output", "output_path", type=str, default=None, help="Save new project to file path.")
@click.option("-n", "--name", type=str, default="Untitled Scan", help="Project name.")
@click.option("-p", "--profile", type=str, default="default", help="Scan profile preset (see `project profiles`).")
@click.option("--start-ip", type=str, default="127.0.0.1", help="Initial start IP address.")
@click.option("--end-ip", type=str, default="127.0.0.1", help="Initial end IP address.")
@click.option("--cidr", type=str, default=None, help="Optional initial CIDR subnet (overrides start/end IP).")
@handle_error
def project_new(
    output_path: Optional[str],
    name: str,
    profile: str,
    start_ip: str,
    end_ip: str,
    cidr: Optional[str],
) -> None:
    """Create a new Angry IP Scanner scan project."""
    proj = project_mod.create_project(name=name, profile=profile, start_ip=start_ip, end_ip=end_ip)
    if cidr:
        targets_mod.set_cidr_target(proj, cidr)
    else:
        targets_mod.set_range_target(proj, start_ip, end_ip)

    sess = get_session()
    saved_path: Optional[str] = None
    if output_path:
        saved_path = project_mod.save_project(proj, output_path)
        sess.set_project(proj, path=saved_path, modified=False)
    else:
        sess.set_project(proj, path=None, modified=True)

    info = project_mod.get_project_info(proj, path=saved_path)
    _emit(
        {"ok": True, "project": info},
        [
            f"Created project '{info['name']}' (profile: {info['profile']})",
            f"  Target:   {info['target']}",
            f"  Pinger:   {info['pinger']}",
            f"  Ports:    {info['ports']}",
            f"  Fetchers: {', '.join(info['selected_fetchers'])}",
            f"  Path:     {saved_path or '(in-memory)'}",
        ],
    )


@project.command("open")
@click.argument("path", type=str)
@handle_error
def project_open(path: str) -> None:
    """Open an existing scan project JSON file."""
    proj = project_mod.open_project(path)
    abs_path = os.path.abspath(path)
    get_session().set_project(proj, path=abs_path, modified=False)
    info = project_mod.get_project_info(proj, path=abs_path)
    _emit(
        {"ok": True, "project": info},
        [
            f"Opened project '{info['name']}' from {abs_path}",
            f"  Target:   {info['target']}",
            f"  Fetchers: {len(info['selected_fetchers'])} selected",
        ],
    )


@project.command("save")
@click.argument("path", type=str, required=False, default=None)
@handle_error
def project_save(path: Optional[str]) -> None:
    """Save the active scan project to disk."""
    saved = get_session().save_session(path=path)
    _emit(
        {"ok": True, "path": saved},
        [f"Saved project to {saved}"],
    )


@project.command("info")
@handle_error
def project_info() -> None:
    """Display summary information for the active project."""
    sess = get_session()
    info = project_mod.get_project_info(sess.get_project(), path=sess.project_path)
    lines = [
        f"Project:  {info['name']} (profile: {info['profile']})",
        f"Path:     {info['path'] or '(unsaved)'}",
        f"Target:   {json.dumps(info['target'])}",
        f"Pinger:   {info['pinger']} | Threads: {info['max_threads']} | Ports: {info['ports']}",
        f"Fetchers: {', '.join(info['selected_fetchers'])}",
        f"Comments: {info['comment_count']} | Favorites: {info['favorite_count']} | Openers: {info['opener_count']}",
    ]
    if info["last_scan"]:
        ls = info["last_scan"]
        lines.append(
            f"Last scan: {ls['host_count']} scanned, {ls['alive_count']} alive, "
            f"{ls['with_ports_count']} with open ports ({ls['scan_time_ms']} ms)"
        )
    _emit({"ok": True, "project": info}, lines)


@project.command("profiles")
@handle_error
def project_profiles() -> None:
    """List built-in scan profiles."""
    profiles = project_mod.list_profiles()
    rows = [[p["name"], str(len(p["fetchers"])), p["ports"], p["description"]] for p in profiles]
    _emit({"ok": True, "profiles": profiles}, _format_table(["Profile", "Fetchers", "Ports", "Description"], rows))


# =============================================================================
# TARGET GROUP (FEEDERS)
# =============================================================================

@cli.group()
def target() -> None:
    """Configure Angry IP Scanner target feeders (range, CIDR, random, file)."""


@target.command("range")
@click.argument("start_ip", type=str)
@click.argument("end_ip", type=str)
@handle_error
def target_range(start_ip: str, end_ip: str) -> None:
    """Set an IP Range feeder (feeder.range)."""
    sess = get_session()
    sess.snapshot(f"target range {start_ip}..{end_ip}")
    tgt = targets_mod.set_range_target(sess.get_project(), start_ip, end_ip)
    _emit(
        {"ok": True, "target": tgt},
        [f"Target set to IP range {tgt['start_ip']} - {tgt['end_ip']} ({tgt['address_count']} addresses)"],
    )


@target.command("cidr")
@click.argument("cidr", type=str)
@click.option("--include-network-broadcast", is_flag=True, default=False, help="Include network and broadcast IPs.")
@handle_error
def target_cidr(cidr: str, include_network_broadcast: bool) -> None:
    """Set an IP Range feeder expanded from CIDR notation."""
    sess = get_session()
    sess.snapshot(f"target cidr {cidr}")
    tgt = targets_mod.set_cidr_target(
        sess.get_project(),
        cidr,
        include_network_broadcast=include_network_broadcast,
    )
    _emit(
        {"ok": True, "target": tgt},
        [f"Target set to CIDR {tgt['cidr']} ({tgt['start_ip']} - {tgt['end_ip']}, {tgt['address_count']} addresses)"],
    )


@target.command("random")
@click.argument("base_ip", type=str)
@click.argument("mask", type=str)
@click.argument("count", type=int)
@handle_error
def target_random(base_ip: str, mask: str, count: int) -> None:
    """Set a Random IP feeder (feeder.random)."""
    sess = get_session()
    sess.snapshot(f"target random {base_ip}/{mask} x{count}")
    tgt = targets_mod.set_random_target(sess.get_project(), base_ip, mask, count)
    _emit(
        {"ok": True, "target": tgt},
        [f"Target set to random feeder: {tgt['count']} hosts under {tgt['base_ip']} / {tgt['mask']}"],
    )


@target.command("file")
@click.argument("file_path", type=str)
@handle_error
def target_file(file_path: str) -> None:
    """Set a Text File feeder (feeder.file) supporting hostnames and host:port entries."""
    sess = get_session()
    sess.snapshot(f"target file {file_path}")
    tgt = targets_mod.set_file_target(sess.get_project(), file_path)
    _emit(
        {"ok": True, "target": tgt},
        [f"Target set to file feeder: {tgt['file_path']}"],
    )


@target.command("show")
@handle_error
def target_show() -> None:
    """Show the active target feeder configuration."""
    tgt = targets_mod.get_target(get_session().get_project())
    lines = [f"{k}: {v}" for k, v in tgt.items()]
    _emit({"ok": True, "target": tgt}, lines)


# =============================================================================
# CONFIG GROUP (SCANNER CONFIG & PINGERS)
# =============================================================================

@cli.group()
def config() -> None:
    """Inspect and modify Angry IP Scanner ScannerConfig settings and pingers."""


@config.command("show")
@handle_error
def config_show() -> None:
    """Display current ScannerConfig settings."""
    cfg = config_mod.get_scanner_config(get_session().get_project())
    rows = [[k, str(v)] for k, v in cfg.items()]
    _emit({"ok": True, "scanner_config": cfg}, _format_table(["Setting", "Value"], rows))


@config.command("set")
@click.option("--pinger", type=str, default=None, help="Pinger ID or alias (windows, java, tcp, udp, combined, arp).")
@click.option("--ports", type=str, default=None, help="TCP ports to scan (e.g. '22,80,443,8000-8080' or '').")
@click.option("--threads", type=int, default=None, help="Max scanning threads (0 = Java virtual threads).")
@click.option("--thread-delay", type=int, default=None, help="Delay between thread launches in ms.")
@click.option("--ping-timeout", type=int, default=None, help="Ping timeout in ms.")
@click.option("--ping-count", type=int, default=None, help="Number of ping probes per host.")
@click.option("--port-timeout", type=int, default=None, help="TCP port connect timeout in ms.")
@click.option("--min-port-timeout", type=int, default=None, help="Minimum adapted port timeout in ms.")
@click.option("--adapt-port-timeout", type=str, default=None, help="Adapt port timeout based on ping RTT (true/false).")
@click.option("--scan-dead-hosts", type=str, default=None, help="Run fetchers even on dead hosts (true/false).")
@click.option("--skip-broadcast", type=str, default=None, help="Skip likely broadcast addresses (true/false).")
@click.option("--use-requested-ports", type=str, default=None, help="Scan host:port entries from file feeder (true/false).")
@click.option("--not-available-text", type=str, default=None, help="Display string for unavailable values.")
@click.option("--not-scanned-text", type=str, default=None, help="Display string for skipped/not-scanned values.")
@handle_error
def config_set(**kwargs: Any) -> None:
    """Update one or more ScannerConfig fields."""
    updates = {k: v for k, v in kwargs.items() if v is not None}
    if not updates:
        raise ValueError("Provide at least one configuration option to update.")
    sess = get_session()
    sess.snapshot(f"config set {', '.join(sorted(updates.keys()))}")
    applied = config_mod.set_scanner_config(sess.get_project(), updates)
    rows = [[k, str(v)] for k, v in applied.items()]
    _emit({"ok": True, "updated": applied, "scanner_config": sess.get_project()["scanner_config"]}, _format_table(["Updated Setting", "Value"], rows))


@config.command("pingers")
@handle_error
def config_pingers() -> None:
    """List all Angry IP Scanner pinger backends."""
    pingers = config_mod.list_pingers()
    rows = [[p["id"], p["name"], p["platform"], p["description"]] for p in pingers]
    _emit({"ok": True, "pingers": pingers}, _format_table(["ID", "Name", "Platform", "Description"], rows))


@config.command("reset")
@handle_error
def config_reset() -> None:
    """Reset ScannerConfig to Angry IP Scanner defaults."""
    sess = get_session()
    sess.snapshot("config reset")
    cfg = config_mod.reset_scanner_config(sess.get_project())
    _emit({"ok": True, "scanner_config": cfg}, ["Reset ScannerConfig to defaults."])


# =============================================================================
# FETCHER GROUP
# =============================================================================

@cli.group()
def fetcher() -> None:
    """Manage Angry IP Scanner fetchers (columns) and per-fetcher preferences."""


@fetcher.command("list")
@handle_error
def fetcher_list() -> None:
    """List currently selected fetchers in scan order."""
    items = fetchers_mod.list_selected_fetchers(get_session().get_project())
    rows = [[str(i["index"]), i["id"], i["name"], "yes" if i["mandatory"] else "no"] for i in items]
    _emit({"ok": True, "selected_fetchers": items}, _format_table(["#", "Fetcher ID", "Column", "Mandatory"], rows))


@fetcher.command("available")
@handle_error
def fetcher_available() -> None:
    """List all 14 Angry IP Scanner fetchers."""
    items = fetchers_mod.list_available_fetchers()
    rows = [[i["id"], i["name"], i["pref_node"] or "-", i["description"]] for i in items]
    _emit({"ok": True, "fetchers": items}, _format_table(["Fetcher ID", "Column", "Prefs", "Description"], rows))


@fetcher.command("select")
@click.argument("fetcher_ids", nargs=-1, required=True)
@handle_error
def fetcher_select(fetcher_ids: Tuple[str, ...]) -> None:
    """Replace selected fetchers (comma-separated or multiple args; fetcher.ip is kept first)."""
    flat: List[str] = []
    for item in fetcher_ids:
        flat.extend(part.strip() for part in item.split(",") if part.strip())
    sess = get_session()
    sess.snapshot(f"fetcher select {','.join(flat)}")
    selected = fetchers_mod.select_fetchers(sess.get_project(), flat)
    _emit({"ok": True, "selected_fetchers": selected}, [f"Selected fetchers: {', '.join(selected)}"])


@fetcher.command("add")
@click.argument("fetcher_id", type=str)
@click.option("--position", type=int, default=None, help="Column index (1..N; 0 is reserved for fetcher.ip).")
@handle_error
def fetcher_add(fetcher_id: str, position: Optional[int]) -> None:
    """Add a fetcher to the selected list."""
    sess = get_session()
    sess.snapshot(f"fetcher add {fetcher_id}")
    selected = fetchers_mod.add_fetcher(sess.get_project(), fetcher_id, position=position)
    _emit({"ok": True, "selected_fetchers": selected}, [f"Selected fetchers: {', '.join(selected)}"])


@fetcher.command("remove")
@click.argument("fetcher_id", type=str)
@handle_error
def fetcher_remove(fetcher_id: str) -> None:
    """Remove a non-mandatory fetcher from the selected list."""
    sess = get_session()
    sess.snapshot(f"fetcher remove {fetcher_id}")
    selected = fetchers_mod.remove_fetcher(sess.get_project(), fetcher_id)
    _emit({"ok": True, "selected_fetchers": selected}, [f"Selected fetchers: {', '.join(selected)}"])


@fetcher.command("move")
@click.argument("fetcher_id", type=str)
@click.argument("new_index", type=int)
@handle_error
def fetcher_move(fetcher_id: str, new_index: int) -> None:
    """Move a selected fetcher to a new column index."""
    sess = get_session()
    sess.snapshot(f"fetcher move {fetcher_id} -> {new_index}")
    selected = fetchers_mod.move_fetcher(sess.get_project(), fetcher_id, new_index)
    _emit({"ok": True, "selected_fetchers": selected}, [f"Selected fetchers: {', '.join(selected)}"])


@fetcher.command("prefs")
@click.argument("fetcher_id", type=str, required=False, default=None)
@click.option("--set", "kv_pairs", multiple=True, help="Set key=value preference (e.g. --set separator=-).")
@handle_error
def fetcher_prefs(fetcher_id: Optional[str], kv_pairs: Tuple[str, ...]) -> None:
    """Inspect or set fetcher-specific preferences (mac, webDetect, httpSender, httpProxy)."""
    sess = get_session()
    proj = sess.get_project()
    if kv_pairs:
        if not fetcher_id:
            raise ValueError("Specify a fetcher_id when using --set (e.g. `fetcher prefs mac --set separator=-`).")
        sess.snapshot(f"fetcher prefs {fetcher_id}")
        updated: Dict[str, Any] = {}
        for pair in kv_pairs:
            if "=" not in pair:
                raise ValueError(f"Preference must be in key=value format: '{pair}'")
            k, v = pair.split("=", 1)
            updated = fetchers_mod.set_fetcher_pref(proj, fetcher_id, k.strip(), v)
        _emit({"ok": True, "fetcher": fetcher_id, "prefs": updated}, [f"Updated {fetcher_id} prefs: {json.dumps(updated)}"])
        return

    prefs = fetchers_mod.get_fetcher_prefs(proj, fetcher_id=fetcher_id)
    _emit({"ok": True, "fetcher": fetcher_id or "all", "prefs": prefs}, [json.dumps(prefs, indent=2)])


# =============================================================================
# SCAN GROUP (REAL ANGRY IP SCANNER EXECUTION)
# =============================================================================

@cli.group()
def scan() -> None:
    """Execute real network scans using the Angry IP Scanner Java engine."""


@scan.command("run")
@click.option("-o", "--export", "export_path", type=str, default=None, help="Optionally export immediately via native exporter (.csv/.txt/.xml/.lst/.sql).")
@click.option("--filter", "export_filter", type=click.Choice(["all", "alive", "with_ports", "dead"]), default="all", help="Filter applied if --export is provided.")
@click.option("--append", is_flag=True, default=False, help="Append to export file if --export is provided.")
@click.option("--timeout", type=int, default=300, help="Maximum scan timeout in seconds.")
@handle_error
def scan_run(export_path: Optional[str], export_filter: str, append: bool, timeout: int) -> None:
    """Run the active project's scan through Angry IP Scanner's real scanning engine."""
    sess = get_session()
    proj = sess.get_project()
    sess.snapshot("scan run")

    export_spec = None
    if export_path:
        export_spec = {
            "output_path": os.path.abspath(export_path),
            "append": append,
            "filter": export_filter,
        }

    record = scanner_mod.execute_scan(proj, export_spec=export_spec, timeout=timeout)
    stats = record["stats"]
    lines = [
        f"Scan completed via {record['engine']} ({record['pinger']})",
        f"  Feeder: {record['feeder_name']} — {record['feeder_info']}",
        f"  Hosts:  {stats['host_count']} scanned | {stats['alive_count']} alive | "
        f"{stats['with_ports_count']} with open ports | {stats['scan_time_ms']} ms",
        "",
    ]
    lines.extend(_format_scan_table(record["fetchers"], record["results"]))
    if "export" in record:
        exp = record["export"]
        lines.append("")
        lines.append(f"Exported {exp['exported_rows']} rows to {exp['output_path']} ({exp['file_size']} bytes)")
    _emit({"ok": True, "scan": record}, lines)


@scan.command("quick")
@click.argument("target_spec", type=str)
@click.option("-p", "--profile", type=str, default="default", help="Scan profile preset.")
@click.option("--ports", type=str, default=None, help="Override scanned TCP ports.")
@click.option("--pinger", type=str, default=None, help="Override pinger (windows, java, tcp, udp, combined, arp).")
@click.option("--fetchers", type=str, default=None, help="Override comma-separated fetcher IDs/aliases.")
@click.option("--threads", type=int, default=None, help="Override max threads.")
@click.option("--ping-timeout", type=int, default=None, help="Override ping timeout in ms.")
@click.option("--port-timeout", type=int, default=None, help="Override port timeout in ms.")
@click.option("--alive-only", is_flag=True, default=False, help="Display only alive hosts in human table output.")
@click.option("-o", "--output", "output_path", type=str, default=None, help="Optional export output path (.csv/.txt/.xml/.lst/.sql/.json).")
@click.option("--save-project", "save_proj_path", type=str, default=None, help="Optional path to save resulting project JSON.")
@click.option("--timeout", type=int, default=300, help="Maximum scan timeout in seconds.")
@handle_error
def scan_quick(
    target_spec: str,
    profile: str,
    ports: Optional[str],
    pinger: Optional[str],
    fetchers: Optional[str],
    threads: Optional[int],
    ping_timeout: Optional[int],
    port_timeout: Optional[int],
    alive_only: bool,
    output_path: Optional[str],
    save_proj_path: Optional[str],
    timeout: int,
) -> None:
    """One-shot real Angry IP Scanner scan for a single IP, CIDR, range (a-b), or file path."""
    proj = project_mod.create_project(name=f"Quick Scan {target_spec}", profile=profile)
    spec = target_spec.strip()
    if os.path.isfile(spec):
        targets_mod.set_file_target(proj, spec)
    elif "/" in spec:
        targets_mod.set_cidr_target(proj, spec)
    elif "-" in spec:
        parts = [p.strip() for p in spec.split("-", 1)]
        if "." not in parts[1] and "." in parts[0]:
            prefix = parts[0].rsplit(".", 1)[0]
            parts[1] = f"{prefix}.{parts[1]}"
        targets_mod.set_range_target(proj, parts[0], parts[1])
    else:
        targets_mod.set_range_target(proj, spec, spec)

    cfg_updates: Dict[str, Any] = {}
    if ports is not None:
        cfg_updates["port_string"] = ports
    if pinger is not None:
        cfg_updates["selected_pinger"] = pinger
    if threads is not None:
        cfg_updates["max_threads"] = threads
    if ping_timeout is not None:
        cfg_updates["ping_timeout"] = ping_timeout
    if port_timeout is not None:
        cfg_updates["port_timeout"] = port_timeout
    if cfg_updates:
        config_mod.set_scanner_config(proj, cfg_updates)

    if fetchers is not None:
        f_list = [f.strip() for f in fetchers.split(",") if f.strip()]
        fetchers_mod.select_fetchers(proj, f_list)

    record = scanner_mod.execute_scan(proj, timeout=timeout)
    export_result = None
    if output_path:
        export_result = export_mod.render(
            proj,
            output_path,
            filter_mode="alive" if alive_only else "all",
            overwrite=True,
        )

    if save_proj_path:
        project_mod.save_project(proj, save_proj_path)

    rows = record["results"]
    if alive_only:
        rows = [r for r in rows if r.get("type") in ("ALIVE", "WITH_PORTS")]

    stats = record["stats"]
    lines = [
        f"Quick scan completed via {record['engine']} ({record['pinger']})",
        f"  Feeder: {record['feeder_name']} — {record['feeder_info']}",
        f"  Hosts:  {stats['host_count']} scanned | {stats['alive_count']} alive | "
        f"{stats['with_ports_count']} with open ports | {stats['scan_time_ms']} ms",
        "",
    ]
    lines.extend(_format_scan_table(record["fetchers"], rows))
    if export_result:
        lines.append("")
        lines.append(f"Exported {export_result['exported_rows']} rows -> {export_result['output']} ({export_result['file_size']} bytes)")

    payload: Dict[str, Any] = {"ok": True, "scan": record}
    if export_result:
        payload["export"] = export_result
    _emit(payload, lines)


@scan.command("rescan")
@click.argument("ips", nargs=-1)
@click.option("--alive-only", is_flag=True, default=False, help="Rescan only hosts that were alive in the last scan.")
@click.option("--timeout", type=int, default=300, help="Maximum scan timeout in seconds.")
@handle_error
def scan_rescan(ips: Tuple[str, ...], alive_only: bool, timeout: int) -> None:
    """Rescan specific IP addresses (or previous results) using Angry IP Scanner's RescanFeeder."""
    sess = get_session()
    proj = sess.get_project()
    sess.snapshot("scan rescan")
    record = scanner_mod.execute_rescan(
        proj,
        ips=list(ips) if ips else None,
        only_alive=alive_only,
        timeout=timeout,
    )
    stats = record["stats"]
    lines = [
        f"Rescan completed: {stats['host_count']} hosts | {stats['alive_count']} alive | {stats['scan_time_ms']} ms",
        "",
    ]
    lines.extend(_format_scan_table(record["fetchers"], record["results"]))
    _emit({"ok": True, "scan": record}, lines)


@scan.command("status")
@handle_error
def scan_status() -> None:
    """Show latest scan metadata and history count for the active project."""
    st = scanner_mod.get_scan_status(get_session().get_project())
    if not st["has_results"]:
        lines = [f"No scan results yet. Active target: {json.dumps(st['target'])}"]
    else:
        ls = st["last_scan"]
        s = ls["stats"]
        lines = [
            f"Last scan: {ls['timestamp']} via {ls['engine']}",
            f"  Feeder:  {ls['feeder_name']} ({ls['feeder_info']})",
            f"  Pinger:  {ls['pinger']}",
            f"  Summary: {s['host_count']} total | {s['alive_count']} alive | {s['with_ports_count']} with ports | {s['scan_time_ms']} ms",
            f"  History: {st['history_count']} recorded scan(s)",
        ]
    _emit({"ok": True, **st}, lines)


# =============================================================================
# RESULT GROUP
# =============================================================================

@cli.group()
def result() -> None:
    """Inspect, filter, search, sort, and summarize stored scan results."""


@result.command("list")
@click.option("--limit", type=int, default=None, help="Maximum number of rows to return.")
@click.option("--offset", type=int, default=0, help="Starting row offset.")
@handle_error
def result_list(limit: Optional[int], offset: int) -> None:
    """List scan result rows."""
    res = results_mod.list_results(get_session().get_project(), limit=limit, offset=offset)
    _emit({"ok": True, **res}, _format_scan_table(res["fetchers"], res["results"]))


@result.command("show")
@click.argument("ip", type=str)
@handle_error
def result_show(ip: str) -> None:
    """Show detailed fetcher results for a single scanned IP (IP Details)."""
    row = results_mod.get_host_detail(get_session().get_project(), ip)
    lines = [f"IP: {row['ip']}  (Status: {row['type']})"]
    if row.get("mac"):
        lines.append(f"MAC: {row['mac']}")
    for k, v in row.get("values", {}).items():
        lines.append(f"  {k}: {v}")
    _emit({"ok": True, "host": row}, lines)


@result.command("filter")
@click.option("--status", type=click.Choice(["all", "alive", "dead", "with_ports", "ports"]), default="alive", help="Host status filter.")
@click.option("--port", type=int, default=None, help="Filter hosts having this open TCP port.")
@click.option("--has-mac", is_flag=True, default=False, help="Keep only hosts with a resolved MAC address.")
@handle_error
def result_filter(status: str, port: Optional[int], has_mac: bool) -> None:
    """Filter scan results by status, open port, or MAC availability."""
    proj = get_session().get_project()
    rows = results_mod.filter_results(proj, status=status, port=port, has_mac=has_mac)
    fetchers = proj["last_scan"].get("fetchers", [])
    _emit(
        {"ok": True, "count": len(rows), "filter": {"status": status, "port": port, "has_mac": has_mac}, "results": rows},
        _format_scan_table(fetchers, rows),
    )


@result.command("search")
@click.argument("query", type=str)
@handle_error
def result_search(query: str) -> None:
    """Case-insensitive substring search across all fetcher columns."""
    proj = get_session().get_project()
    rows = results_mod.search_results(proj, query)
    fetchers = proj["last_scan"].get("fetchers", [])
    _emit({"ok": True, "query": query, "count": len(rows), "results": rows}, _format_scan_table(fetchers, rows))


@result.command("sort")
@click.option("--by", type=str, default="fetcher.ip", help="Fetcher ID or alias to sort by.")
@click.option("--desc", is_flag=True, default=False, help="Sort in descending order.")
@handle_error
def result_sort(by: str, desc: bool) -> None:
    """Sort stored scan results by a fetcher column."""
    sess = get_session()
    proj = sess.get_project()
    sess.snapshot(f"result sort by {by}")
    rows = results_mod.sort_results(proj, by=by, descending=desc)
    fetchers = proj["last_scan"].get("fetchers", [])
    _emit({"ok": True, "sorted_by": by, "descending": desc, "count": len(rows), "results": rows}, _format_scan_table(fetchers, rows))


@result.command("stats")
@handle_error
def result_stats() -> None:
    """Display aggregate statistics and open-port distribution for the latest scan."""
    st = results_mod.get_result_stats(get_session().get_project())
    lines = [
        f"Feeder:     {st['feeder_info']} (pinger: {st['pinger']})",
        f"Total:      {st['total_hosts']}",
        f"Alive:      {st['alive_hosts']}",
        f"With Ports: {st['with_ports_hosts']}",
        f"Dead:       {st['dead_hosts']}",
        f"Duration:   {st['scan_time_ms']} ms",
    ]
    if st["top_open_ports"]:
        ports_str = ", ".join(f"{p['port']}({p['count']})" for p in st["top_open_ports"][:15])
        lines.append(f"Open Ports: {ports_str}")
    _emit({"ok": True, "stats": st}, lines)


@result.command("clear")
@handle_error
def result_clear() -> None:
    """Clear stored scan results from the project."""
    sess = get_session()
    sess.snapshot("result clear")
    info = results_mod.clear_results(sess.get_project())
    _emit({"ok": True, **info}, [f"Cleared {info['cleared_rows']} scan result row(s)."])


# =============================================================================
# EXPORT GROUP (REAL ANGRY IP SCANNER EXPORTERS)
# =============================================================================

@cli.group()
def export() -> None:
    """Export scan results via Angry IP Scanner's native exporters (CSV, TXT, XML, LST, SQL) or JSON."""


@export.command("render")
@click.argument("output_path", type=str)
@click.option("-p", "--preset", type=str, default=None, help="Format preset: csv, txt, xml, lst, sql, json (inferred from extension if omitted).")
@click.option("--filter", "filter_mode", type=click.Choice(["all", "alive", "with_ports", "dead"]), default="all", help="Which hosts to export.")
@click.option("--append", is_flag=True, default=False, help="Append to existing output file (unsupported for xml/json).")
@click.option("--overwrite", is_flag=True, default=False, help="Overwrite existing output file.")
@handle_error
def export_render(
    output_path: str,
    preset: Optional[str],
    filter_mode: str,
    append: bool,
    overwrite: bool,
) -> None:
    """Export scan results using Angry IP Scanner's real ExportProcessor."""
    res = export_mod.render(
        get_session().get_project(),
        output_path=output_path,
        preset=preset,
        filter_mode=filter_mode,
        append=append,
        overwrite=overwrite,
    )
    _emit(
        {"ok": True, "export": res},
        [
            f"Exported {res['exported_rows']} rows via {res['exporter_id']} ({res['method']})",
            f"  Output: {res['output']} ({res['file_size']:,} bytes)",
        ],
    )


@export.command("presets")
@handle_error
def export_presets() -> None:
    """List all supported export formats and Angry IP Scanner exporter IDs."""
    presets = export_mod.list_export_presets()
    rows = [
        [p["name"], p["exporter_id"], "native" if p["native_backend"] else "json", "yes" if p["supports_append"] else "no", p["description"]]
        for p in presets
    ]
    _emit({"ok": True, "presets": presets}, _format_table(["Preset", "Exporter ID", "Backend", "Append", "Description"], rows))


@export.command("import-txt")
@click.argument("txt_path", type=str)
@handle_error
def export_import_txt(txt_path: str) -> None:
    """Import an Angry IP Scanner .txt export report back into the active project."""
    sess = get_session()
    sess.snapshot(f"export import-txt {txt_path}")
    info = export_mod.import_txt_results(sess.get_project(), txt_path)
    _emit(
        {"ok": True, "import": info},
        [
            f"Imported {info['imported_rows']} rows ({info['alive_count']} alive) from {info['source']}",
            f"  Feeder:  {info['feeder_info']}",
            f"  Columns: {', '.join(info['columns'])}",
        ],
    )


# =============================================================================
# COMMENT GROUP
# =============================================================================

@cli.group()
def comment() -> None:
    """Manage persistent host comments (CommentsConfig / CommentFetcher)."""


@comment.command("list")
@handle_error
def comment_list() -> None:
    """List all IP/MAC comments stored in the project."""
    comments = metadata_mod.list_comments(get_session().get_project())
    rows = [[k, v] for k, v in comments.items()]
    _emit({"ok": True, "comments": comments}, _format_table(["IP / MAC", "Comment"], rows))


@comment.command("set")
@click.argument("key", type=str)
@click.argument("text", type=str)
@handle_error
def comment_set(key: str, text: str) -> None:
    """Set a persistent comment for an IP or MAC address."""
    sess = get_session()
    sess.snapshot(f"comment set {key}")
    res = metadata_mod.set_comment(sess.get_project(), key, text)
    _emit({"ok": True, **res}, [f"Comment set for {res['key']}: {res['comment']}"])


@comment.command("remove")
@click.argument("key", type=str)
@handle_error
def comment_remove(key: str) -> None:
    """Remove a comment for an IP or MAC address."""
    sess = get_session()
    sess.snapshot(f"comment remove {key}")
    res = metadata_mod.remove_comment(sess.get_project(), key)
    _emit({"ok": True, **res}, [f"Removed comment for {res['removed']}"])


# =============================================================================
# FAVORITE GROUP
# =============================================================================

@cli.group()
def favorite() -> None:
    """Manage saved favorite scan targets (FavoritesConfig)."""


@favorite.command("list")
@handle_error
def favorite_list() -> None:
    """List saved favorite targets."""
    favs = metadata_mod.list_favorites(get_session().get_project())
    rows = [[name, json.dumps(spec)] for name, spec in favs.items()]
    _emit({"ok": True, "favorites": favs}, _format_table(["Name", "Target"], rows))


@favorite.command("add")
@click.argument("name", type=str)
@handle_error
def favorite_add(name: str) -> None:
    """Save the project's active target feeder as a named favorite."""
    sess = get_session()
    sess.snapshot(f"favorite add {name}")
    res = metadata_mod.add_favorite(sess.get_project(), name)
    _emit({"ok": True, **res}, [f"Saved favorite '{res['name']}': {json.dumps(res['target'])}"])


@favorite.command("remove")
@click.argument("name", type=str)
@handle_error
def favorite_remove(name: str) -> None:
    """Remove a saved favorite target."""
    sess = get_session()
    sess.snapshot(f"favorite remove {name}")
    res = metadata_mod.remove_favorite(sess.get_project(), name)
    _emit({"ok": True, **res}, [f"Removed favorite '{res['removed']}'"])


@favorite.command("use")
@click.argument("name", type=str)
@handle_error
def favorite_use(name: str) -> None:
    """Switch the active target feeder to a saved favorite."""
    sess = get_session()
    sess.snapshot(f"favorite use {name}")
    tgt = metadata_mod.use_favorite(sess.get_project(), name)
    _emit({"ok": True, "favorite": name, "target": tgt}, [f"Active target switched to favorite '{name}': {json.dumps(tgt)}"])


# =============================================================================
# OPENER GROUP
# =============================================================================

@cli.group()
def opener() -> None:
    """Manage and expand host openers (OpenersConfig)."""


@opener.command("list")
@handle_error
def opener_list() -> None:
    """List all configured openers."""
    openers = metadata_mod.list_openers(get_session().get_project())
    rows = [[k, v["exec_string"], "yes" if v.get("in_terminal") else "no"] for k, v in openers.items()]
    _emit({"ok": True, "openers": openers}, _format_table(["Name", "Command Template", "Terminal"], rows))


@opener.command("add")
@click.argument("name", type=str)
@click.argument("exec_string", type=str)
@click.option("--terminal", is_flag=True, default=False, help="Mark opener as terminal command.")
@click.option("--working-dir", type=str, default=None, help="Optional working directory.")
@handle_error
def opener_add(name: str, exec_string: str, terminal: bool, working_dir: Optional[str]) -> None:
    """Add or update an opener template."""
    sess = get_session()
    sess.snapshot(f"opener add {name}")
    res = metadata_mod.add_opener(sess.get_project(), name, exec_string, in_terminal=terminal, working_dir=working_dir)
    _emit({"ok": True, "opener": res}, [f"Added opener '{res['name']}': {res['exec_string']}"])


@opener.command("remove")
@click.argument("name", type=str)
@handle_error
def opener_remove(name: str) -> None:
    """Delete an opener by name."""
    sess = get_session()
    sess.snapshot(f"opener remove {name}")
    res = metadata_mod.remove_opener(sess.get_project(), name)
    _emit({"ok": True, **res}, [f"Removed opener '{res['removed']}'"])


@opener.command("render")
@click.argument("name", type=str)
@click.argument("ip", type=str)
@handle_error
def opener_render(name: str, ip: str) -> None:
    """Expand an opener template against a scanned host's fetcher values."""
    res = metadata_mod.render_opener(get_session().get_project(), name, ip)
    _emit({"ok": True, **res}, [f"{res['name']} ({res['ip']}): {res['command']}"])


# =============================================================================
# SESSION GROUP
# =============================================================================

@cli.group()
def session() -> None:
    """Inspect session status, history, and perform undo/redo."""


@session.command("status")
@handle_error
def session_status() -> None:
    """Show current session status."""
    st = get_session().status()
    rows = [[k, str(v)] for k, v in st.items()]
    _emit({"ok": True, "session": st}, _format_table(["Field", "Value"], rows))


@session.command("undo")
@handle_error
def session_undo() -> None:
    """Undo the last project mutation."""
    res = get_session().undo()
    _emit({"ok": True, **res}, [f"Undone: {res['undone']} (remaining undo: {res['undo_remaining']})"])


@session.command("redo")
@handle_error
def session_redo() -> None:
    """Redo the most recently undone mutation."""
    res = get_session().redo()
    _emit({"ok": True, **res}, [f"Redone: {res['redone']} (remaining redo: {res['redo_remaining']})"])


@session.command("history")
@handle_error
def session_history() -> None:
    """Show mutation history for the current session."""
    hist = get_session().history()
    rows = [[str(i + 1), h["timestamp"], h["action"]] for i, h in enumerate(hist)]
    _emit({"ok": True, "history": hist}, _format_table(["#", "Timestamp", "Action"], rows))


# =============================================================================
# BACKEND GROUP
# =============================================================================

@cli.group()
def backend() -> None:
    """Inspect and verify the real Angry IP Scanner Java backend."""


@backend.command("info")
@handle_error
def backend_info() -> None:
    """Query live Angry IP Scanner version, runtime, pingers, fetchers, and exporters."""
    info = ipscan_backend.get_backend_info()
    rt = info["runtime"]
    lines = [
        f"Engine:   {info['full_name']} ({info['website']})",
        f"Java:     {rt['java']} (Java {rt['java_major']})",
        f"Artifact: {rt['artifact']} (source: {rt['artifact_source']}, JNA: {rt['has_jna']})",
        f"Pingers:  {', '.join(p['id'] for p in info['pingers'])}",
        f"Fetchers: {len(info['fetchers'])} registered",
        f"Exporters:{', '.join(e['extension'] for e in info['exporters'])}",
    ]
    _emit(info, lines)


@backend.command("verify")
@handle_error
def backend_verify() -> None:
    """Verify Java 11+, Angry IP Scanner artifact, HeadlessBridge compilation, and loopback probe."""
    info = ipscan_backend.get_backend_info()
    proj = project_mod.create_project(name="Backend Verify", profile="quick-ping", start_ip="127.0.0.1", end_ip="127.0.0.1")
    proj["scanner_config"]["ping_count"] = 1
    proj["scanner_config"]["ping_timeout"] = 1000
    scan_res = scanner_mod.execute_scan(proj, timeout=30)
    alive = scan_res["stats"]["alive_count"]
    payload = {
        "ok": True,
        "engine": info["full_name"],
        "runtime": info["runtime"],
        "loopback_alive": alive >= 1,
        "loopback_result": scan_res["results"][0] if scan_res["results"] else None,
    }
    _emit(
        payload,
        [
            f"Verified real Angry IP Scanner backend: {info['full_name']}",
            f"  Java:     {info['runtime']['java']} (Java {info['runtime']['java_major']})",
            f"  Artifact: {info['runtime']['artifact']}",
            f"  Loopback 127.0.0.1 alive: {payload['loopback_alive']}",
        ],
    )


@backend.command("native-cli")
@click.option("--feeder", type=click.Choice(["range", "random", "file"]), required=True, help="Native -f:<feeder> type.")
@click.option("--arg", "feeder_args", multiple=True, required=True, help="Feeder positional arguments (repeatable).")
@click.option("-o", "--output", "output_path", type=str, required=True, help="Output file path for native -o.")
@click.option("--append", is_flag=True, default=False, help="Pass -a append flag.")
@click.option("--timeout", type=int, default=180, help="Subprocess timeout in seconds.")
@handle_error
def backend_native_cli(
    feeder: str,
    feeder_args: Tuple[str, ...],
    output_path: str,
    append: bool,
    timeout: int,
) -> None:
    """Invoke Angry IP Scanner's original CommandLineProcessor (-s -q -f:... -o ...)."""
    res = ipscan_backend.run_native_cli(
        feeder_flag=feeder,
        feeder_args=list(feeder_args),
        output_path=output_path,
        auto_start=True,
        auto_quit=True,
        append=append,
        timeout=timeout,
    )
    _emit(
        res,
        [
            f"Native CLI exited with code {res['returncode']}",
            f"  Output: {res['output_path']} (exists={res['output_exists']})",
        ],
    )


# =============================================================================
# INTERACTIVE REPL
# =============================================================================

@cli.command("repl")
@click.option("--project", "project_path", type=str, default=None, help="Optional project file to load on startup.")
def repl(project_path: Optional[str]) -> None:
    """Launch the interactive stateful Angry IP Scanner REPL."""
    global _repl_mode
    _repl_mode = True
    skin = ReplSkin("ipscan", version=__version__)
    skin.print_banner()

    if project_path:
        try:
            proj = project_mod.open_project(project_path)
            get_session().set_project(proj, path=project_path, modified=False)
            skin.success(f"Loaded project: {proj['name']} ({project_path})")
        except Exception as exc:
            skin.error(str(exc))

    commands_help = {
        "project new|open|save|info|profiles": "Manage scan projects and profiles",
        "target range|cidr|random|file|show": "Configure Angry IP Scanner feeders",
        "config show|set|pingers|reset": "Tune pinger, ports, threads, timeouts",
        "fetcher list|available|select|add|remove|move|prefs": "Manage scan columns & fetcher prefs",
        "scan run|quick|rescan|status": "Execute real Angry IP Scanner scans",
        "result list|show|filter|search|sort|stats|clear": "Query and analyze scan results",
        "export render|presets|import-txt": "Export via native CSV/TXT/XML/LST/SQL or JSON",
        "comment list|set|remove": "Manage persistent per-IP/MAC comments",
        "favorite list|add|remove|use": "Manage saved favorite target feeders",
        "opener list|add|remove|render": "Manage and expand host opener templates",
        "session status|undo|redo|history": "Inspect state and undo/redo mutations",
        "backend info|verify|native-cli": "Inspect and verify Angry IP Scanner engine",
        "help": "Show this help",
        "quit / exit": "Exit REPL",
    }

    pt_session = None
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            pt_session = skin.create_prompt_session()
        except Exception:
            pt_session = None
    try:
        while True:
            sess = get_session()
            proj_name = sess.get_project().get("name", "") if sess.has_project() else ""
            try:
                line = skin.get_input(pt_session, project_name=proj_name, modified=sess._modified)
            except (EOFError, KeyboardInterrupt):
                break

            stripped = line.strip()
            if not stripped:
                continue
            if stripped in ("quit", "exit", "q"):
                break
            if stripped in ("help", "?"):
                skin.help(commands_help)
                continue

            try:
                tokens = shlex.split(stripped)
            except ValueError as exc:
                skin.error(f"Parse error: {exc}")
                continue

            if tokens[0] == "repl":
                skin.warning("Already inside REPL.")
                continue

            try:
                cli.main(args=tokens, prog_name="ipscan", standalone_mode=False)
            except click.ClickException as exc:
                skin.error(exc.format_message())
            except SystemExit:
                pass
            except Exception as exc:
                skin.error(str(exc))
    finally:
        _repl_mode = False
        skin.print_goodbye()


# Top-level shortcut: ipscan quick <target> -> ipscan scan quick <target>
cli.add_command(scan_quick, name="quick")


def main() -> None:
    """Console script entry point for ``ipscan``."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    cli(prog_name="ipscan")


if __name__ == "__main__":
    main()
