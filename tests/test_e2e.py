"""End-to-end tests invoking the REAL Angry IP Scanner Java engine and installed CLI."""

from __future__ import annotations

import csv
import http.server
import json
import os
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

import pytest

from angry_cli.core import config as config_mod
from angry_cli.core import export as export_mod
from angry_cli.core import fetchers as fetchers_mod
from angry_cli.core import metadata as metadata_mod
from angry_cli.core import project as project_mod
from angry_cli.core import scanner as scanner_mod
from angry_cli.core import targets as targets_mod
from angry_cli.utils import backend as ipscan_backend


def _resolve_cli(name: str) -> list[str]:
    """Resolve installed CLI command; falls back to python -m for dev.

    Set env IPSCAN_FORCE_INSTALLED=1 to require the installed command.
    """
    force = os.environ.get("IPSCAN_FORCE_INSTALLED", "").strip() == "1"
    path = shutil.which(name)
    if path:
        print(f"[_resolve_cli] Using installed command: {path}")
        return [path]
    if force:
        raise RuntimeError(f"{name} not found in PATH. Install with: pip install -e .")
    module = "angry_cli"
    print(f"[_resolve_cli] Falling back to: {sys.executable} -m {module}")
    return [sys.executable, "-m", module]


class _BannerHTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AngryCLI-TestServer/1.0"
    sys_version = ""

    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format: str, *args: object) -> None:
        pass


class _QuietTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

    def handle_error(self, request: object, client_address: object) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


@pytest.fixture(scope="module")
def local_http_port() -> Iterator[int]:
    """Start a real ephemeral TCP/HTTP server on 127.0.0.1 for Angry IP Scanner to probe."""
    server = _QuietTCPServer(("127.0.0.1", 0), _BannerHTTPHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()


# =============================================================================
# REAL ANGRY IP SCANNER BACKEND TESTS
# =============================================================================

class TestRealBackendEngine:
    def test_backend_info_real_engine(self):
        info = ipscan_backend.get_backend_info()
        assert info["ok"] is True
        assert "Angry IP Scanner" in info["full_name"]
        assert info["runtime"]["java_major"] >= 11
        assert os.path.isfile(info["runtime"]["artifact"])

        pinger_ids = {p["id"] for p in info["pingers"]}
        assert {"pinger.java", "pinger.tcp", "pinger.udp", "pinger.combined", "pinger.arp"}.issubset(pinger_ids)

        fetcher_ids = {f["id"] for f in info["fetchers"]}
        assert len(fetcher_ids) == 14
        assert {"fetcher.ip", "fetcher.ping", "fetcher.ports", "fetcher.webDetect", "fetcher.mac.vendor"}.issubset(fetcher_ids)

        exporter_exts = {e["extension"] for e in info["exporters"]}
        assert exporter_exts == {"txt", "csv", "xml", "lst", "sql"}

    def test_real_loopback_scan_with_open_port_and_comment(self, local_http_port: int):
        proj = project_mod.create_project(name="Loopback Real Scan", profile="default")
        targets_mod.set_range_target(proj, "127.0.0.1", "127.0.0.1")
        config_mod.set_scanner_config(proj, {
            "port_string": str(local_http_port),
            "ping_count": 1,
            "ping_timeout": 1000,
            "port_timeout": 1000,
            "adapt_port_timeout": False,
        })
        fetchers_mod.select_fetchers(proj, ["ip", "ping", "hostname", "ports", "comment"])
        metadata_mod.set_comment(proj, "127.0.0.1", "AngryCLI Loopback Node")

        record = scanner_mod.execute_scan(proj, timeout=60)
        assert record["stats"]["host_count"] == 1
        assert record["stats"]["alive_count"] == 1
        assert record["stats"]["with_ports_count"] == 1
        assert record["stats"]["completed_normally"] is True

        row = record["results"][0]
        assert row["ip"] == "127.0.0.1"
        assert row["type"] == "WITH_PORTS"
        assert row["values"]["fetcher.ports"] == str(local_http_port)
        assert row["values"]["fetcher.comment"] == "AngryCLI Loopback Node"
        assert "ms" in row["values"]["fetcher.ping"]

    def test_real_file_feeder_with_requested_port_and_web_detect(self, tmp_path: Path, local_http_port: int):
        hosts_file = tmp_path / "targets.txt"
        hosts_file.write_text(f"127.0.0.1:{local_http_port}\n", encoding="utf-8")

        proj = project_mod.create_project(name="File Feeder Web Detect", profile="web-discovery")
        targets_mod.set_file_target(proj, str(hosts_file))
        config_mod.set_scanner_config(proj, {
            "port_string": "",
            "use_requested_ports": True,
            "ping_count": 1,
            "ping_timeout": 1000,
            "port_timeout": 1500,
            "adapt_port_timeout": False,
        })
        fetchers_mod.select_fetchers(proj, ["ip", "ping", "ports", "webDetect"])

        record = scanner_mod.execute_scan(proj, timeout=60)
        assert record["stats"]["alive_count"] == 1
        row = record["results"][0]
        assert row["ip"] == "127.0.0.1"
        assert row["values"]["fetcher.ports"] == str(local_http_port)
        assert "AngryCLI-TestServer/1.0" in str(row["values"]["fetcher.webDetect"])

    def test_real_rescan_and_java_pinger(self):
        proj = project_mod.create_project(name="Java Pinger & Rescan", profile="quick-ping")
        config_mod.set_scanner_config(proj, {
            "selected_pinger": "pinger.java",
            "ping_count": 1,
            "ping_timeout": 1000,
        })
        res = scanner_mod.execute_rescan(proj, ips=["127.0.0.1"], timeout=60)
        assert res["pinger"] == "pinger.java"
        assert res["stats"]["alive_count"] == 1
        assert res["results"][0]["ip"] == "127.0.0.1"


# =============================================================================
# REAL ANGRY IP SCANNER NATIVE EXPORTERS TESTS
# =============================================================================

class TestRealNativeExporters:
    def test_all_five_native_exporters_and_roundtrip(self, tmp_path: Path, local_http_port: int):
        proj = project_mod.create_project(name="Full Export Verification", profile="default")
        targets_mod.set_range_target(proj, "127.0.0.1", "127.0.0.1")
        config_mod.set_scanner_config(proj, {
            "port_string": str(local_http_port),
            "ping_count": 1,
            "ping_timeout": 1000,
            "port_timeout": 1000,
            "adapt_port_timeout": False,
        })
        fetchers_mod.select_fetchers(proj, ["ip", "ping", "hostname", "ports", "comment"])
        metadata_mod.set_comment(proj, "127.0.0.1", "Verified Export Host")
        scanner_mod.execute_scan(proj, timeout=60)

        # 1. Native CSVExporter
        csv_path = tmp_path / "report.csv"
        csv_res = export_mod.render(proj, str(csv_path), overwrite=True)
        assert csv_res["method"] == "angry-ip-scanner-native"
        assert csv_res["exporter_id"] == "exporter.csv"
        assert csv_res["file_size"] > 0
        with csv_path.open("r", encoding="utf-8") as f:
            csv_rows = list(csv.reader(f))
        assert csv_rows[0] == ["IP", "Ping", "Hostname", "Ports", "Comments"]
        assert csv_rows[1][0] == "127.0.0.1"
        assert csv_rows[1][3] == str(local_http_port)
        assert csv_rows[1][4] == "Verified Export Host"
        print(f"\n  CSV: {csv_path} ({csv_res['file_size']:,} bytes)")

        # CSV Append test (must not duplicate header)
        export_mod.render(proj, str(csv_path), append=True)
        with csv_path.open("r", encoding="utf-8") as f:
            appended_rows = list(csv.reader(f))
        assert len(appended_rows) == 3

        # 2. Native XMLExporter
        xml_path = tmp_path / "report.xml"
        xml_res = export_mod.render(proj, str(xml_path), overwrite=True)
        assert xml_res["exporter_id"] == "exporter.xml"
        xml_bytes = xml_path.read_bytes()
        assert xml_bytes.startswith(b"<?xml")
        root = ET.fromstring(xml_bytes)
        assert root.tag == "scanning_report"
        hosts = root.findall("./hosts/host")
        assert len(hosts) == 1
        assert hosts[0].attrib["address"] == "127.0.0.1"
        result_map = {el.attrib["name"]: (el.text or "") for el in hosts[0].findall("result")}
        assert result_map["Ports"] == str(local_http_port)
        assert result_map["Comments"] == "Verified Export Host"
        print(f"  XML: {xml_path} ({xml_res['file_size']:,} bytes)")

        # 3. Native TXTExporter + Round-trip import
        txt_path = tmp_path / "report.txt"
        txt_res = export_mod.render(proj, str(txt_path), overwrite=True)
        assert txt_res["exporter_id"] == "exporter.txt"
        txt_text = txt_path.read_text(encoding="utf-8")
        assert "Generated by" in txt_text
        assert "127.0.0.1" in txt_text
        print(f"  TXT: {txt_path} ({txt_res['file_size']:,} bytes)")

        reimport_proj = project_mod.create_project(name="Reimport")
        imp = export_mod.import_txt_results(reimport_proj, str(txt_path))
        assert imp["imported_rows"] == 1
        assert reimport_proj["last_scan"]["results"][0]["ip"] == "127.0.0.1"
        assert reimport_proj["last_scan"]["results"][0]["values"]["fetcher.ports"] == str(local_http_port)

        # 4. Native IPListExporter (.lst)
        lst_path = tmp_path / "open_ports.lst"
        lst_res = export_mod.render(proj, str(lst_path), overwrite=True)
        assert lst_res["exporter_id"] == "exporter.ipList"
        lst_lines = [ln.strip() for ln in lst_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert lst_lines == [f"127.0.0.1:{local_http_port}"]
        print(f"  LST: {lst_path} ({lst_res['file_size']:,} bytes)")

        # 5. Native SQLExporter (.sql) — execute real SQL in SQLite!
        sql_path = tmp_path / "report.sql"
        sql_res = export_mod.render(proj, str(sql_path), overwrite=True)
        assert sql_res["exporter_id"] == "exporter.sql"
        sql_script = sql_path.read_text(encoding="utf-8")
        assert "CREATE TABLE scan" in sql_script
        assert "INSERT INTO scan VALUES" in sql_script
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(sql_script)
            rows = conn.execute("SELECT IP, Ports, Comments FROM scan").fetchall()
            assert rows == [("127.0.0.1", str(local_http_port), "Verified Export Host")]
        finally:
            conn.close()
        print(f"  SQL: {sql_path} ({sql_res['file_size']:,} bytes)")


# =============================================================================
# CLI SUBPROCESS E2E TESTS
# =============================================================================

class TestCLISubprocess:
    CLI_BASE = _resolve_cli("ipscan")

    def _run(
        self,
        args: list[str],
        check: bool = True,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.CLI_BASE + args,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
        )

    def test_help_and_version(self):
        r_help = self._run(["--help"])
        assert r_help.returncode == 0
        assert "Angry IP Scanner" in r_help.stdout

        r_ver = self._run(["--version"])
        assert r_ver.returncode == 0
        assert "ipscan" in r_ver.stdout

    def test_backend_info_and_verify_json(self):
        r_info = self._run(["--json", "backend", "info"])
        assert r_info.returncode == 0
        data = json.loads(r_info.stdout)
        assert data["ok"] is True
        assert len(data["fetchers"]) == 14

        r_ver = self._run(["--json", "backend", "verify"])
        assert r_ver.returncode == 0
        vdata = json.loads(r_ver.stdout)
        assert vdata["ok"] is True
        assert vdata["loopback_alive"] is True

    def test_full_stateful_workflow_dry_run_and_exports(self, tmp_path: Path, local_http_port: int):
        proj_file = str(tmp_path / "workflow.json")
        csv_file = str(tmp_path / "workflow.csv")
        xml_file = str(tmp_path / "workflow.xml")
        lst_file = str(tmp_path / "workflow.lst")
        sql_file = str(tmp_path / "workflow.sql")

        r1 = self._run(["--json", "project", "new", "-o", proj_file, "-n", "E2E Workflow", "--start-ip", "127.0.0.1", "--end-ip", "127.0.0.1"])
        assert json.loads(r1.stdout)["ok"] is True

        r2 = self._run([
            "--json", "--project", proj_file, "config", "set",
            "--ports", str(local_http_port),
            "--ping-count", "1",
            "--ping-timeout", "1000",
            "--port-timeout", "1000",
            "--adapt-port-timeout", "false",
        ])
        assert json.loads(r2.stdout)["ok"] is True

        # Verify --dry-run does NOT persist mutations
        r_dry = self._run(["--json", "--project", proj_file, "--dry-run", "config", "set", "--threads", "7"])
        assert json.loads(r_dry.stdout)["updated"]["max_threads"] == 7
        disk_after_dry = json.loads(Path(proj_file).read_text(encoding="utf-8"))
        assert disk_after_dry["scanner_config"]["max_threads"] != 7

        self._run(["--json", "--project", proj_file, "fetcher", "select", "ip", "ping", "hostname", "ports", "comment"])
        self._run(["--json", "--project", proj_file, "comment", "set", "127.0.0.1", "Subprocess E2E Host"])

        r_scan = self._run(["--json", "--project", proj_file, "scan", "run"])
        scan_data = json.loads(r_scan.stdout)
        assert scan_data["ok"] is True
        assert scan_data["scan"]["stats"]["with_ports_count"] == 1

        r_filt = self._run(["--json", "--project", proj_file, "result", "filter", "--status", "with_ports", "--port", str(local_http_port)])
        filt_data = json.loads(r_filt.stdout)
        assert filt_data["count"] == 1
        assert filt_data["results"][0]["ip"] == "127.0.0.1"

        for target_path in (csv_file, xml_file, lst_file, sql_file):
            r_exp = self._run(["--json", "--project", proj_file, "export", "render", target_path, "--overwrite"])
            exp_data = json.loads(r_exp.stdout)
            assert exp_data["ok"] is True
            assert exp_data["export"]["method"] == "angry-ip-scanner-native"
            assert os.path.isfile(target_path) and os.path.getsize(target_path) > 0

        assert Path(lst_file).read_text(encoding="utf-8").strip() == f"127.0.0.1:{local_http_port}"
        assert "Subprocess E2E Host" in Path(csv_file).read_text(encoding="utf-8")
        print(f"\n  Subprocess E2E artifacts: {csv_file}, {xml_file}, {lst_file}, {sql_file}")

    def test_quick_scan_subprocess(self, tmp_path: Path, local_http_port: int):
        out_csv = str(tmp_path / "quick.csv")
        r = self._run([
            "--json", "quick", "127.0.0.1",
            "--ports", str(local_http_port),
            "--fetchers", "ip,ping,ports",
            "--ping-timeout", "1000",
            "--port-timeout", "1000",
            "-o", out_csv,
        ])
        data = json.loads(r.stdout)
        assert data["ok"] is True
        assert data["scan"]["stats"]["with_ports_count"] == 1
        assert os.path.isfile(out_csv) and os.path.getsize(out_csv) > 0
        print(f"\n  Quick scan CSV: {out_csv} ({os.path.getsize(out_csv):,} bytes)")

    def test_repl_undo_redo_subprocess(self):
        repl_script = (
            "project new -n ReplDemo\n"
            "config set --threads 42\n"
            "session undo\n"
            "session redo\n"
            "session status\n"
            "quit\n"
        )
        r = self._run(["repl"], input_text=repl_script)
        assert r.returncode == 0
        assert "Created project 'ReplDemo'" in r.stdout
        assert "Undone:" in r.stdout
        assert "Redone:" in r.stdout
