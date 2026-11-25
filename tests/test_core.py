"""Unit tests for ipscan core modules (synthetic data, zero external deps)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from angry_cli.core import config as config_mod
from angry_cli.core import export as export_mod
from angry_cli.core import fetchers as fetchers_mod
from angry_cli.core import metadata as metadata_mod
from angry_cli.core import project as project_mod
from angry_cli.core import results as results_mod
from angry_cli.core import scanner as scanner_mod
from angry_cli.core import targets as targets_mod
from angry_cli.core.session import Session


def _sample_project_with_results() -> dict[str, Any]:
    proj = project_mod.create_project(name="Synthetic Audit", profile="lan-audit")
    proj["last_scan"] = {
        "timestamp": "2026-11-19T10:00:00Z",
        "engine": "Angry IP Scanner 3.12.2",
        "feeder_name": "IP Range",
        "feeder_info": "192.168.1.1 - 192.168.1.10",
        "target": {"feeder": "range", "start_ip": "192.168.1.1", "end_ip": "192.168.1.10"},
        "pinger": "pinger.tcp",
        "fetchers": [
            {"id": "fetcher.ip", "name": "IP", "full_name": "IP"},
            {"id": "fetcher.ping", "name": "Ping", "full_name": "Ping"},
            {"id": "fetcher.hostname", "name": "Hostname", "full_name": "Hostname"},
            {"id": "fetcher.ports", "name": "Ports", "full_name": "Ports [3+]"},
            {"id": "fetcher.mac", "name": "MAC Address", "full_name": "MAC Address"},
            {"id": "fetcher.comment", "name": "Comments", "full_name": "Comments"},
        ],
        "stats": {
            "host_count": 4,
            "alive_count": 3,
            "with_ports_count": 2,
            "dead_count": 1,
            "scan_time_ms": 420,
            "completed_normally": True,
        },
        "results": [
            {
                "ip": "192.168.1.10",
                "type": "WITH_PORTS",
                "mac": "AA:BB:CC:00:00:10",
                "values": {
                    "fetcher.ip": "192.168.1.10",
                    "fetcher.ping": "12 ms",
                    "fetcher.hostname": "web-node.local",
                    "fetcher.ports": "80,443,8080-8082",
                    "fetcher.mac": "AA:BB:CC:00:00:10",
                    "fetcher.comment": "Web Server",
                },
            },
            {
                "ip": "192.168.1.1",
                "type": "WITH_PORTS",
                "mac": "AA:BB:CC:00:00:01",
                "values": {
                    "fetcher.ip": "192.168.1.1",
                    "fetcher.ping": "2 ms",
                    "fetcher.hostname": "gateway.local",
                    "fetcher.ports": "22,80",
                    "fetcher.mac": "AA:BB:CC:00:00:01",
                    "fetcher.comment": "Core Router",
                },
            },
            {
                "ip": "192.168.1.5",
                "type": "ALIVE",
                "mac": None,
                "values": {
                    "fetcher.ip": "192.168.1.5",
                    "fetcher.ping": "5 ms",
                    "fetcher.hostname": "[n/a]",
                    "fetcher.ports": "[n/a]",
                    "fetcher.mac": "[n/a]",
                    "fetcher.comment": "[n/a]",
                },
            },
            {
                "ip": "192.168.1.2",
                "type": "DEAD",
                "mac": None,
                "values": {
                    "fetcher.ip": "192.168.1.2",
                    "fetcher.ping": "[n/a]",
                    "fetcher.hostname": "[n/s]",
                    "fetcher.ports": "[n/s]",
                    "fetcher.mac": "[n/s]",
                    "fetcher.comment": "[n/s]",
                },
            },
        ],
    }
    return proj


# =============================================================================
# PROJECT TESTS
# =============================================================================

class TestProject:
    def test_create_project_default(self):
        proj = project_mod.create_project()
        assert proj["name"] == "Untitled Scan"
        assert proj["profile"] == "default"
        assert proj["selected_fetchers"][0] == "fetcher.ip"
        assert proj["scanner_config"]["port_string"] == "80,443,8080"

    @pytest.mark.parametrize("profile", list(project_mod.SCAN_PROFILES.keys()))
    def test_create_project_all_profiles(self, profile: str):
        proj = project_mod.create_project(name=f"P-{profile}", profile=profile)
        assert proj["profile"] == profile
        assert "fetcher.ip" in proj["selected_fetchers"]

    def test_create_project_invalid_profile(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            project_mod.create_project(profile="nonexistent")

    def test_save_and_open_roundtrip(self, tmp_path: Path):
        proj = project_mod.create_project(name="Roundtrip", profile="web-discovery")
        proj["comments"]["10.0.0.1"] = "Gateway"
        out = tmp_path / "scan.ipscan.json"
        saved = project_mod.save_project(proj, str(out))
        assert os.path.isfile(saved)

        loaded = project_mod.open_project(saved)
        assert loaded["name"] == "Roundtrip"
        assert loaded["profile"] == "web-discovery"
        assert loaded["comments"]["10.0.0.1"] == "Gateway"

    def test_open_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            project_mod.open_project(str(tmp_path / "missing.json"))

    def test_open_invalid_schema_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text('{"foo": "bar"}', encoding="utf-8")
        with pytest.raises(ValueError, match="Invalid Angry IP Scanner project"):
            project_mod.open_project(str(bad))

    def test_get_project_info_and_list_profiles(self):
        proj = _sample_project_with_results()
        info = project_mod.get_project_info(proj)
        assert info["name"] == "Synthetic Audit"
        assert info["last_scan"]["alive_count"] == 3
        profiles = project_mod.list_profiles()
        assert len(profiles) >= 5
        assert any(p["name"] == "lan-audit" for p in profiles)


# =============================================================================
# SESSION & UNDO/REDO TESTS
# =============================================================================

class TestSession:
    def test_empty_session_guards(self):
        sess = Session()
        assert not sess.has_project()
        with pytest.raises(RuntimeError, match="No project"):
            sess.get_project()
        with pytest.raises(RuntimeError, match="Nothing to undo"):
            sess.undo()
        with pytest.raises(RuntimeError, match="Nothing to redo"):
            sess.redo()

    def test_snapshot_undo_redo_cycle(self):
        sess = Session()
        proj = project_mod.create_project(name="UndoTest")
        sess.set_project(proj)

        sess.snapshot("change threads to 50")
        sess.get_project()["scanner_config"]["max_threads"] = 50
        assert sess.get_project()["scanner_config"]["max_threads"] == 50

        sess.snapshot("change threads to 25")
        sess.get_project()["scanner_config"]["max_threads"] = 25
        assert sess.get_project()["scanner_config"]["max_threads"] == 25

        u1 = sess.undo()
        assert u1["undone"] == "change threads to 25"
        assert sess.get_project()["scanner_config"]["max_threads"] == 50

        u2 = sess.undo()
        assert u2["undone"] == "change threads to 50"
        assert sess.get_project()["scanner_config"]["max_threads"] == 100

        r1 = sess.redo()
        assert r1["redone"] == "change threads to 50"
        assert sess.get_project()["scanner_config"]["max_threads"] == 50

    def test_new_snapshot_clears_redo(self):
        sess = Session()
        sess.set_project(project_mod.create_project())
        sess.snapshot("step 1")
        sess.get_project()["name"] = "Step 1"
        sess.undo()
        assert sess.status()["redo_depth"] == 1
        sess.snapshot("branch")
        sess.get_project()["name"] = "Branch"
        assert sess.status()["redo_depth"] == 0

    def test_max_history_limit(self):
        sess = Session(max_history=3)
        sess.set_project(project_mod.create_project())
        for i in range(6):
            sess.snapshot(f"step {i}")
            sess.get_project()["name"] = f"Name {i}"
        assert sess.status()["undo_depth"] == 3

    def test_save_session_writes_locked_json(self, tmp_path: Path):
        sess = Session()
        sess.set_project(project_mod.create_project(name="Persisted"), modified=True)
        out = tmp_path / "persisted.json"
        saved = sess.save_session(str(out))
        assert saved == str(out.resolve())
        assert not sess._modified
        assert json.loads(out.read_text(encoding="utf-8"))["name"] == "Persisted"
        sess.snapshot("rename")
        sess.get_project()["name"] = "Renamed"
        sess.save_session()
        assert json.loads(out.read_text(encoding="utf-8"))["name"] == "Renamed"


# =============================================================================
# CONFIG & PINGER TESTS
# =============================================================================

class TestConfig:
    def test_list_pingers(self):
        pingers = config_mod.list_pingers()
        ids = {p["id"] for p in pingers}
        assert ids == {
            "pinger.windows",
            "pinger.java",
            "pinger.udp",
            "pinger.tcp",
            "pinger.combined",
            "pinger.arp",
        }

    def test_normalize_pinger_aliases(self):
        assert config_mod.normalize_pinger_id("tcp") == "pinger.tcp"
        assert config_mod.normalize_pinger_id("PINGER.JAVA") == "pinger.java"
        assert config_mod.normalize_pinger_id("windows") == "pinger.windows"
        with pytest.raises(ValueError, match="Unknown pinger"):
            config_mod.normalize_pinger_id("invalid-pinger")

    def test_validate_port_string_valid(self):
        assert config_mod.validate_port_string("") == []
        assert config_mod.validate_port_string("80") == [80]
        assert config_mod.validate_port_string("22,80,443,8000-8002") == [22, 80, 443, 8000, 8001, 8002]

    @pytest.mark.parametrize("bad", ["0", "70000", "100-50", "abc", "80,foo", "80-"])
    def test_validate_port_string_invalid(self, bad: str):
        with pytest.raises(ValueError):
            config_mod.validate_port_string(bad)

    def test_set_and_reset_scanner_config(self):
        proj = project_mod.create_project()
        applied = config_mod.set_scanner_config(proj, {
            "pinger": "tcp",
            "ports": "22,80,443",
            "threads": 64,
            "scan_dead_hosts": "true",
            "ping_timeout": 1500,
        })
        assert applied["selected_pinger"] == "pinger.tcp"
        assert applied["port_string"] == "22,80,443"
        assert applied["max_threads"] == 64
        assert applied["scan_dead_hosts"] is True
        assert applied["ping_timeout"] == 1500

        reset = config_mod.reset_scanner_config(proj)
        assert reset["port_string"] == "80,443,8080"
        assert reset["max_threads"] == 100

    def test_set_scanner_config_rejects_bad_values(self):
        proj = project_mod.create_project()
        with pytest.raises(ValueError, match="Unknown config key"):
            config_mod.set_scanner_config(proj, {"bogus": 1})
        with pytest.raises(ValueError, match="max_threads"):
            config_mod.set_scanner_config(proj, {"max_threads": -5})
        with pytest.raises(ValueError, match="ping_count"):
            config_mod.set_scanner_config(proj, {"ping_count": 0})


# =============================================================================
# FETCHER TESTS
# =============================================================================

class TestFetchers:
    def test_available_fetchers_count(self):
        all_f = fetchers_mod.list_available_fetchers()
        assert len(all_f) == 14
        assert any(f["id"] == "fetcher.mac.vendor" for f in all_f)
        assert any(f["id"] == "fetcher.netbios" for f in all_f)

    def test_normalize_fetcher_aliases(self):
        assert fetchers_mod.normalize_fetcher_id("ttl") == "fetcher.ping.ttl"
        assert fetchers_mod.normalize_fetcher_id("web-detect") == "fetcher.webDetect"
        assert fetchers_mod.normalize_fetcher_id("mac-vendor") == "fetcher.mac.vendor"
        with pytest.raises(ValueError, match="Unknown fetcher"):
            fetchers_mod.normalize_fetcher_id("does-not-exist")

    def test_select_keeps_ip_first_and_deduplicates(self):
        proj = project_mod.create_project()
        sel = fetchers_mod.select_fetchers(proj, ["ping", "hostname", "ip", "ping"])
        assert sel == ["fetcher.ip", "fetcher.ping", "fetcher.hostname"]

    def test_add_remove_move_fetcher(self):
        proj = project_mod.create_project()
        fetchers_mod.select_fetchers(proj, ["ip", "ping", "hostname"])
        fetchers_mod.add_fetcher(proj, "webDetect", position=1)
        assert proj["selected_fetchers"] == ["fetcher.ip", "fetcher.webDetect", "fetcher.ping", "fetcher.hostname"]

        fetchers_mod.move_fetcher(proj, "webDetect", 3)
        assert proj["selected_fetchers"] == ["fetcher.ip", "fetcher.ping", "fetcher.hostname", "fetcher.webDetect"]

        fetchers_mod.remove_fetcher(proj, "webDetect")
        assert "fetcher.webDetect" not in proj["selected_fetchers"]

    def test_cannot_remove_or_move_ip_fetcher(self):
        proj = project_mod.create_project()
        with pytest.raises(ValueError, match="mandatory"):
            fetchers_mod.remove_fetcher(proj, "ip")
        with pytest.raises(ValueError, match="index 0"):
            fetchers_mod.move_fetcher(proj, "ip", 1)

    def test_fetcher_prefs(self):
        proj = project_mod.create_project()
        updated = fetchers_mod.set_fetcher_pref(proj, "mac", "separator", "-")
        assert updated["separator"] == "-"
        assert fetchers_mod.get_fetcher_prefs(proj, "mac")["separator"] == "-"

        updated_wd = fetchers_mod.set_fetcher_pref(proj, "webDetect", "extractGroup", "2")
        assert updated_wd["extractGroup"] == 2

        with pytest.raises(ValueError, match="no configurable preferences"):
            fetchers_mod.set_fetcher_pref(proj, "ping", "foo", "bar")
        with pytest.raises(ValueError, match="Invalid preference key"):
            fetchers_mod.set_fetcher_pref(proj, "mac", "unknownKey", "x")


# =============================================================================
# TARGET FEEDER TESTS
# =============================================================================

class TestTargets:
    def test_expand_cidr(self):
        assert targets_mod.expand_cidr_to_range("192.168.1.0/24") == ("192.168.1.1", "192.168.1.254", 254)
        assert targets_mod.expand_cidr_to_range("192.168.1.0/24", include_network_broadcast=True) == ("192.168.1.0", "192.168.1.255", 256)
        assert targets_mod.expand_cidr_to_range("10.0.0.5/32") == ("10.0.0.5", "10.0.0.5", 1)

    def test_set_range_and_protocol_mismatch(self):
        proj = project_mod.create_project()
        tgt = targets_mod.set_range_target(proj, "10.0.0.1", "10.0.0.10")
        assert tgt["feeder"] == "range"
        assert tgt["address_count"] == 10
        with pytest.raises(ValueError, match="same IP protocol"):
            targets_mod.set_range_target(proj, "127.0.0.1", "::1")

    def test_set_random_target(self):
        proj = project_mod.create_project()
        tgt = targets_mod.set_random_target(proj, "192.168.1.0", "255.255.255.0", 25)
        assert tgt["feeder"] == "random"
        assert tgt["count"] == 25
        with pytest.raises(ValueError, match="positive integer"):
            targets_mod.set_random_target(proj, "192.168.1.0", "255.255.255.0", 0)

    def test_set_file_target(self, tmp_path: Path):
        proj = project_mod.create_project()
        hosts = tmp_path / "hosts.txt"
        hosts.write_text("127.0.0.1:80\n", encoding="utf-8")
        tgt = targets_mod.set_file_target(proj, str(hosts))
        assert tgt["feeder"] == "file"
        assert tgt["file_path"] == str(hosts.resolve())
        with pytest.raises(FileNotFoundError):
            targets_mod.set_file_target(proj, str(tmp_path / "nope.txt"))


# =============================================================================
# RESULTS TESTS
# =============================================================================

class TestResults:
    def test_list_and_host_detail(self):
        proj = _sample_project_with_results()
        page = results_mod.list_results(proj, limit=2, offset=1)
        assert page["total"] == 4
        assert page["returned"] == 2
        assert page["results"][0]["ip"] == "192.168.1.1"

        host = results_mod.get_host_detail(proj, "192.168.1.1")
        assert host["values"]["fetcher.comment"] == "Core Router"
        with pytest.raises(KeyError):
            results_mod.get_host_detail(proj, "10.99.99.99")

    def test_filter_results(self):
        proj = _sample_project_with_results()
        assert len(results_mod.filter_results(proj, status="alive")) == 3
        assert len(results_mod.filter_results(proj, status="with_ports")) == 2
        assert len(results_mod.filter_results(proj, status="dead")) == 1
        p8081 = results_mod.filter_results(proj, status="all", port=8081)
        assert [r["ip"] for r in p8081] == ["192.168.1.10"]
        macs = results_mod.filter_results(proj, status="all", has_mac=True)
        assert len(macs) == 2

    def test_search_and_sort_results(self):
        proj = _sample_project_with_results()
        found = results_mod.search_results(proj, "router")
        assert [r["ip"] for r in found] == ["192.168.1.1"]

        sorted_ip = results_mod.sort_results(proj, by="ip")
        assert [r["ip"] for r in sorted_ip] == ["192.168.1.1", "192.168.1.2", "192.168.1.5", "192.168.1.10"]

        sorted_ping = results_mod.sort_results(proj, by="ping")
        assert sorted_ping[0]["ip"] == "192.168.1.1"
        assert sorted_ping[1]["ip"] == "192.168.1.5"
        assert sorted_ping[2]["ip"] == "192.168.1.10"

    def test_stats_and_clear(self):
        proj = _sample_project_with_results()
        stats = results_mod.get_result_stats(proj)
        assert stats["total_hosts"] == 4
        assert stats["alive_hosts"] == 3
        assert stats["with_ports_hosts"] == 2
        assert stats["top_open_ports"][0] == {"port": 80, "count": 2}

        cleared = results_mod.clear_results(proj)
        assert cleared["cleared_rows"] == 4
        assert proj["last_scan"] is None


# =============================================================================
# METADATA & EXPORT UNIT TESTS
# =============================================================================

class TestMetadataAndExportUnit:
    def test_comments_crud(self):
        proj = project_mod.create_project()
        metadata_mod.set_comment(proj, "192.168.1.1", "MikroTik GW")
        assert metadata_mod.list_comments(proj) == {"192.168.1.1": "MikroTik GW"}
        metadata_mod.remove_comment(proj, "192.168.1.1")
        assert metadata_mod.list_comments(proj) == {}

    def test_favorites_crud_and_use(self):
        proj = project_mod.create_project()
        targets_mod.set_range_target(proj, "10.10.0.1", "10.10.0.50")
        metadata_mod.add_favorite(proj, "branch-a")
        targets_mod.set_range_target(proj, "127.0.0.1", "127.0.0.1")
        restored = metadata_mod.use_favorite(proj, "branch-a")
        assert restored["start_ip"] == "10.10.0.1"
        assert restored["end_ip"] == "10.10.0.50"
        metadata_mod.remove_favorite(proj, "branch-a")
        assert "branch-a" not in metadata_mod.list_favorites(proj)

    def test_openers_crud_and_render(self):
        proj = _sample_project_with_results()
        metadata_mod.add_opener(proj, "Admin SSH", "ssh admin@${fetcher.ip}", in_terminal=True)
        rendered = metadata_mod.render_opener(proj, "Admin SSH", "192.168.1.1")
        assert rendered["command"] == "ssh admin@192.168.1.1"
        web_fallback = metadata_mod.render_opener(proj, "Web Browser", "192.168.1.5")
        assert web_fallback["command"] == "http://192.168.1.5/"
        metadata_mod.remove_opener(proj, "Admin SSH")
        assert "Admin SSH" not in metadata_mod.list_openers(proj)

    def test_export_json_and_guards(self, tmp_path: Path):
        proj = _sample_project_with_results()
        out = tmp_path / "results.json"
        res = export_mod.render(proj, str(out), filter_mode="alive")
        assert res["exported_rows"] == 3
        assert os.path.isfile(res["output"])
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["exported_rows"] == 3

        with pytest.raises(FileExistsError):
            export_mod.render(proj, str(out), overwrite=False)
        with pytest.raises(ValueError, match="does not support --append"):
            export_mod.render(proj, str(tmp_path / "x.xml"), append=True)

    def test_import_txt_results_parser(self, tmp_path: Path):
        txt = tmp_path / "sample.txt"
        txt.write_text(
            "Generated by Angry IP Scanner 3.12.2\n"
            "https://angryip.org\n\n"
            "Scanned 192.168.1.1 - 192.168.1.2\n"
            "Nov 19, 2026, 10:00:00 AM\n\n"
            "IP              Ping            Hostname                Ports           \n"
            "192.168.1.1     2 ms            gateway.local           22,80           \n"
            "192.168.1.2     [n/a]           [n/s]                   [n/s]           \n",
            encoding="utf-8",
        )
        proj = project_mod.create_project()
        info = export_mod.import_txt_results(proj, str(txt))
        assert info["imported_rows"] == 2
        assert info["alive_count"] == 1
        assert info["with_ports_count"] == 1
        assert proj["last_scan"]["results"][0]["ip"] == "192.168.1.1"
        assert proj["last_scan"]["results"][0]["values"]["fetcher.ports"] == "22,80"


# =============================================================================
# MANDATORY HOSTNAME & MDNS / NETBIOS ENRICHMENT TESTS
# =============================================================================

class TestMandatoryHostname:
    def test_build_bridge_request_always_includes_hostname(self):
        proj = project_mod.create_project()
        fetchers_mod.select_fetchers(proj, ["ip", "ping", "ports"])
        req = scanner_mod.build_bridge_request(proj)
        assert req["selected_fetchers"] == [
            "fetcher.ip",
            "fetcher.ping",
            "fetcher.hostname",
            "fetcher.ports",
        ]

    def test_enrich_hostnames_netbios_and_avahi_fallback(self, monkeypatch):
        import subprocess
        from types import SimpleNamespace

        monkeypatch.setattr(scanner_mod.shutil, "which", lambda cmd: "/usr/bin/avahi-resolve" if cmd == "avahi-resolve" else None)

        def fake_run(cmd, **kwargs):
            ip = cmd[-1]
            if ip == "111.0.8.83":
                return SimpleNamespace(returncode=0, stdout="111.0.8.83\tpm3-lulu-00u.local\n", stderr="")
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1.5))

        monkeypatch.setattr(scanner_mod.subprocess, "run", fake_run)

        rows = [
            {
                "ip": "111.0.8.83",
                "type": "WITH_PORTS",
                "values": {"fetcher.ip": "111.0.8.83", "fetcher.hostname": "[n/a]", "fetcher.netbios": "[n/a]"},
            },
            {
                "ip": "111.0.8.77",
                "type": "WITH_PORTS",
                "values": {
                    "fetcher.ip": "111.0.8.77",
                    "fetcher.hostname": "[n/a]",
                    "fetcher.netbios": "WORKGROUP\\DESKTOP-57G7NBQ [E0-D5-5E-FB-FE-B4]",
                },
            },
            {
                "ip": "111.0.8.57",
                "type": "WITH_PORTS",
                "values": {"fetcher.ip": "111.0.8.57", "fetcher.hostname": "[n/a]"},
            },
            {
                "ip": "111.0.8.99",
                "type": "DEAD",
                "values": {"fetcher.ip": "111.0.8.99", "fetcher.hostname": "[n/s]"},
            },
        ]

        scanner_mod._enrich_hostnames(rows, {"not_available_text": "[n/a]", "not_scanned_text": "[n/s]"})
        assert rows[0]["values"]["fetcher.hostname"] == "pm3-lulu-00u.local"
        assert rows[1]["values"]["fetcher.hostname"] == "DESKTOP-57G7NBQ"
        assert rows[2]["values"]["fetcher.hostname"] == "[n/a]"
        assert rows[3]["values"]["fetcher.hostname"] == "[n/s]"
