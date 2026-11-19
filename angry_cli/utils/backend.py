"""Backend integration for the real Angry IP Scanner Java engine.

This module locates a real Java 21+ runtime and a real Angry IP Scanner binary
(either built from the source repository via Gradle or installed on the system),
compiles the thin HeadlessBridge if needed, and invokes Angry IP Scanner's
actual DI container, Pingers, Fetchers, Feeders, ScannerDispatcherThread, and
Exporters headlessly with isolated in-memory preferences.

No network scanning or native export format is reimplemented in Python.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Optional


_BRIDGE_MAIN_CLASS = "org.angrycli.bridge.HeadlessBridge"
_PREFS_FACTORY_CLASS = "org.angrycli.bridge.InMemoryPreferencesFactory"


def _package_dir() -> Path:
    """Return the angry_cli package directory."""
    return Path(__file__).resolve().parent.parent


def _bridge_source_dir() -> Path:
    """Return the directory containing HeadlessBridge Java sources."""
    return _package_dir() / "bridge"


def _repo_root_candidates() -> list[Path]:
    """Return candidate Angry IP Scanner source/deployment root directories."""
    pkg = _package_dir()
    candidates: list[Path] = []
    # Standard layout: <repo>/agent-harness/angry_cli
    harness_parent = pkg.parent.parent.parent
    if (harness_parent / "build.gradle").is_file() or (harness_parent / "build" / "libs").is_dir():
        candidates.append(harness_parent)
    cwd = Path.cwd()
    if (cwd / "build.gradle").is_file() or (cwd / "build" / "libs").is_dir():
        candidates.append(cwd)
    if (cwd / "ipscan" / "build.gradle").is_file() or (cwd / "ipscan" / "build" / "libs").is_dir():
        candidates.append(cwd / "ipscan")
    return candidates


def _parse_java_major(java_exe: str) -> Optional[int]:
    """Return the major Java version for a java executable, or None on error."""
    try:
        proc = subprocess.run(
            [java_exe, "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (proc.stderr or "") + "\n" + (proc.stdout or "")
        match = re.search(r'version\s+"(\d+)(?:\.(\d+))?', output)
        if not match:
            return None
        major = int(match.group(1))
        if major == 1 and match.group(2):
            return int(match.group(2))
        return major
    except (OSError, subprocess.SubprocessError):
        return None


def _candidate_java_homes() -> list[Path]:
    """Collect candidate JDK/JRE home directories across Windows, Linux, macOS."""
    homes: list[Path] = []
    env_home = os.environ.get("JAVA_HOME")
    if env_home:
        homes.append(Path(env_home))

    if sys.platform == "win32":
        pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        # Angry IP Scanner bundled JRE (Java 21)
        homes.append(pf / "Angry IP Scanner" / "jre")
        homes.append(pf86 / "Angry IP Scanner" / "jre")
        for vendor_dir in (
            pf / "Eclipse Adoptium",
            pf / "Java",
            pf / "BellSoft",
            pf / "Zulu",
            pf / "Microsoft",
            Path.home() / ".jdks",
        ):
            if vendor_dir.is_dir():
                for child in sorted(vendor_dir.iterdir(), reverse=True):
                    if child.is_dir():
                        homes.append(child)
    elif sys.platform == "darwin":
        homes.append(Path("/Applications/Angry IP Scanner.app/Contents/MacOS/jre"))
        jvm_root = Path("/Library/Java/JavaVirtualMachines")
        if jvm_root.is_dir():
            for child in sorted(jvm_root.iterdir(), reverse=True):
                homes.append(child / "Contents" / "Home")
    else:
        jvm_root = Path("/usr/lib/jvm")
        if jvm_root.is_dir():
            for child in sorted(jvm_root.iterdir(), reverse=True):
                if child.is_dir():
                    homes.append(child)

    return homes


def find_java(min_major: int = 21, require_javac: bool = False) -> dict[str, Any]:
    """Locate a Java 21+ runtime (and optionally javac compiler).

    Args:
        min_major: Minimum required Java major version (Angry IP Scanner needs 21+).
        require_javac: If True, only return a JDK that also provides javac.

    Returns:
        Dict with ``java``, ``javac`` (optional), and ``major_version``.

    Raises:
        RuntimeError: If no suitable Java runtime is installed.
    """
    exe_suffix = ".exe" if sys.platform == "win32" else ""
    seen: set[str] = set()
    candidates: list[Path] = []

    env_java = os.environ.get("IPSCAN_JAVA")
    if env_java:
        candidates.append(Path(env_java))

    for home in _candidate_java_homes():
        candidates.append(home / "bin" / f"java{exe_suffix}")

    which_java = shutil.which("java")
    if which_java:
        candidates.append(Path(which_java))

    best: Optional[dict[str, Any]] = None
    for cand in candidates:
        try:
            resolved = str(cand.resolve())
        except OSError:
            resolved = str(cand)
        if resolved in seen or not cand.is_file():
            continue
        seen.add(resolved)

        major = _parse_java_major(str(cand))
        if major is None or major < min_major:
            continue

        javac_cand = cand.parent / f"javac{exe_suffix}"
        javac_path = str(javac_cand) if javac_cand.is_file() else None
        if require_javac and not javac_path:
            continue

        info = {
            "java": str(cand),
            "javac": javac_path,
            "major_version": major,
        }
        # Prefer Java 21 LTS (or JDK with javac) when available
        if best is None:
            best = info
        elif info["javac"] and not best["javac"]:
            best = info
        elif major == 21 and best["major_version"] != 21 and bool(info["javac"]) == bool(best["javac"]):
            best = info

    if best is not None:
        return best

    kind = "JDK" if require_javac else "Java"
    raise RuntimeError(
        f"Angry IP Scanner requires {kind} {min_major}+, which was not found.\n"
        f"Install Java {min_major}+ with:\n"
        f"  Ubuntu/Debian: sudo apt install openjdk-21-jdk\n"
        f"  Windows:       winget install EclipseAdoptium.Temurin.21.JDK\n"
        f"  macOS:         brew install openjdk@21\n"
        f"Or set IPSCAN_JAVA=/path/to/java."
    )


def _jar_has_entry(jar_path: Path, entry_prefix: str) -> bool:
    """Return True if a JAR/ZIP archive contains an entry starting with prefix."""
    try:
        with zipfile.ZipFile(jar_path, "r") as zf:
            return any(name.startswith(entry_prefix) for name in zf.namelist())
    except (OSError, zipfile.BadZipFile):
        return False


def _find_jna_jar() -> Optional[Path]:
    """Locate JNA jar (needed on Windows for WindowsPinger and WinMACFetcher)."""
    env_jna = os.environ.get("IPSCAN_JNA_JAR")
    if env_jna and Path(env_jna).is_file():
        return Path(env_jna)

    gradle_jna = Path.home() / ".gradle" / "caches" / "modules-2" / "files-2.1" / "net.java.dev.jna" / "jna"
    if gradle_jna.is_dir():
        matches = sorted(gradle_jna.rglob("jna-5.*.jar"), reverse=True)
        for m in matches:
            if not m.name.endswith(("-sources.jar", "-javadoc.jar")):
                return m

    for sys_path in ("/usr/share/java/jna.jar", "/usr/share/java/jna-5.jar"):
        if Path(sys_path).is_file():
            return Path(sys_path)

    return None


def find_ipscan_artifact() -> dict[str, Any]:
    """Locate the real Angry IP Scanner JAR/executable and companion classpath.

    Search order:
      1. ``IPSCAN_JAR`` environment variable
      2. Local Angry IP Scanner source build (``build/libs/ipscan-*.jar`` or
         ``build/installer/*/ipscan.jar``)
      3. System-installed Angry IP Scanner (Windows ``ipscan.exe``, Linux
         ``/usr/lib/ipscan/ipscan-*.jar``, macOS ``Angry IP Scanner.app``)

    Returns:
        Dict with ``artifact``, ``source``, ``classpath`` (list of entries),
        and ``native_executable`` (optional).

    Raises:
        RuntimeError: If Angry IP Scanner is not built or installed.
    """
    candidates: list[tuple[str, Path]] = []

    env_jar = os.environ.get("IPSCAN_JAR")
    if env_jar:
        candidates.append(("env", Path(env_jar)))

    # Bundled Angry IP Scanner JAR shipped inside angry_cli/libs/
    bundled_libs = _package_dir() / "libs"
    if bundled_libs.is_dir():
        for jar_file in sorted(bundled_libs.glob("ipscan-*.jar"), reverse=True):
            candidates.append(("bundled", jar_file))

    # Prefer local source repository builds
    for repo in _repo_root_candidates():
        libs_dir = repo / "build" / "libs"
        if libs_dir.is_dir():
            for jar_file in sorted(libs_dir.glob("ipscan-*.jar"), reverse=True):
                if not jar_file.name.endswith(("-sources.jar", "-javadoc.jar")):
                    candidates.append(("source-build", jar_file))
        installer_jar = repo / "build" / "installer" / "win" / "ipscan.jar"
        if installer_jar.is_file():
            candidates.append(("source-build", installer_jar))

    # System-installed Angry IP Scanner
    if sys.platform == "win32":
        pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
        local_app = Path(os.environ.get("LOCALAPPDATA", ""))
        for base in (pf / "Angry IP Scanner", pf86 / "Angry IP Scanner", local_app / "Programs" / "Angry IP Scanner"):
            for name in ("ipscan.jar", "ipscan.exe"):
                p = base / name
                if p.is_file():
                    candidates.append(("system-install", p))
    elif sys.platform == "darwin":
        mac_dir = Path("/Applications/Angry IP Scanner.app/Contents/MacOS")
        if mac_dir.is_dir():
            for jar_file in sorted(mac_dir.glob("ipscan*.jar"), reverse=True):
                candidates.append(("system-install", jar_file))
    else:
        for base in (
            Path.home() / ".local" / "share" / "angry-cli",
            Path("/usr/lib/ipscan"),
            Path("/usr/share/ipscan"),
            Path("/opt/ipscan"),
        ):
            if base.is_dir():
                for jar_file in sorted(base.glob("ipscan*.jar"), reverse=True):
                    candidates.append(("system-install", jar_file))

    native_exe: Optional[str] = None
    which_ipscan = shutil.which("ipscan")
    if which_ipscan:
        native_exe = which_ipscan
        if _jar_has_entry(Path(which_ipscan), "net/azib/ipscan/"):
            candidates.append(("path", Path(which_ipscan)))

    for source_kind, artifact in candidates:
        if not artifact.is_file():
            continue
        if not _jar_has_entry(artifact, "net/azib/ipscan/"):
            continue

        cp: list[str] = [str(artifact)]
        has_jna = _jar_has_entry(artifact, "com/sun/jna/")
        if not has_jna:
            jna_jar = _find_jna_jar()
            if jna_jar is not None:
                cp.append(str(jna_jar))
                has_jna = True

        if native_exe is None and artifact.suffix.lower() == ".exe":
            native_exe = str(artifact)
        elif native_exe is None and sys.platform == "win32":
            sys_exe = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Angry IP Scanner" / "ipscan.exe"
            if sys_exe.is_file():
                native_exe = str(sys_exe)

        return {
            "artifact": str(artifact),
            "source": source_kind,
            "classpath": cp,
            "has_jna": has_jna,
            "native_executable": native_exe,
        }

    raise RuntimeError(
        "Angry IP Scanner binary/JAR was not found.\n"
        "Build from source or install Angry IP Scanner:\n"
        "  From source:   cd ipscan && ./gradlew jar\n"
        "  Ubuntu/Debian: Download .deb from https://angryip.org/download/ and run `sudo dpkg -i ipscan_*.deb`\n"
        "  Windows:       Install from https://angryip.org/download/ (or `winget install angryziber.AngryIPScanner`)\n"
        "  macOS:         brew install --cask angry-ip-scanner\n"
        "Or set IPSCAN_JAR=/path/to/ipscan.jar."
    )


def _compute_bridge_source_hash(src_dir: Path) -> str:
    """Compute cross-platform LF-normalized SHA-256 digest of bridge Java sources."""
    hasher = hashlib.sha256()
    for name in ("InMemoryPreferencesFactory.java", "HeadlessBridge.java"):
        p = src_dir / name
        hasher.update(name.encode("utf-8"))
        normalized = p.read_bytes().replace(b"\r\n", b"\n")
        hasher.update(normalized)
    return hasher.hexdigest()


def _classes_valid(classes_dir: Path, expected_hash: str) -> bool:
    """Check whether compiled bridge classes exist and match source hash."""
    bridge_cls = classes_dir / "org" / "angrycli" / "bridge" / "HeadlessBridge.class"
    prefs_cls = classes_dir / "org" / "angrycli" / "bridge" / "InMemoryPreferencesFactory.class"
    stamp = classes_dir / ".bridge_hash"
    if not (bridge_cls.is_file() and prefs_cls.is_file()):
        return False
    if stamp.is_file():
        return stamp.read_text(encoding="utf-8").strip() == expected_hash
    # Accept pre-compiled package classes if newer than sources
    src_dir = _bridge_source_dir()
    src_mtime = max(
        (src_dir / "HeadlessBridge.java").stat().st_mtime,
        (src_dir / "InMemoryPreferencesFactory.java").stat().st_mtime,
    )
    return bridge_cls.stat().st_mtime >= src_mtime


def ensure_bridge_compiled(ipscan_classpath: list[str]) -> str:
    """Ensure HeadlessBridge Java classes are compiled and up to date.

    Returns:
        Path to the directory containing compiled bridge ``.class`` files.
    """
    src_dir = _bridge_source_dir()
    expected_hash = _compute_bridge_source_hash(src_dir)

    pkg_classes = src_dir / "classes"
    if _classes_valid(pkg_classes, expected_hash):
        return str(pkg_classes)

    cache_classes = Path.home() / ".cache" / "angry-cli" / "bridge-classes"
    if _classes_valid(cache_classes, expected_hash):
        return str(cache_classes)

    # Compile into package classes dir if writable, else user cache dir
    target_dir = pkg_classes
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        probe = target_dir / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
    except OSError:
        target_dir = cache_classes
        target_dir.mkdir(parents=True, exist_ok=True)

    jdk = find_java(min_major=21, require_javac=True)
    cp_str = os.pathsep.join(ipscan_classpath)
    cmd = [
        jdk["javac"],
        "--release", "21",
        "-cp", cp_str,
        "-d", str(target_dir),
        str(src_dir / "InMemoryPreferencesFactory.java"),
        str(src_dir / "HeadlessBridge.java"),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Failed to compile Angry IP Scanner HeadlessBridge:\n"
            f"{proc.stderr or proc.stdout}"
        )
    (target_dir / ".bridge_hash").write_text(expected_hash, encoding="utf-8")
    return str(target_dir)


def _invoke_bridge(action: str, payload: Optional[dict[str, Any]] = None, timeout: int = 300) -> dict[str, Any]:
    """Execute HeadlessBridge with the real Angry IP Scanner engine."""
    java_info = find_java(min_major=21, require_javac=False)
    artifact_info = find_ipscan_artifact()
    bridge_classes = ensure_bridge_compiled(artifact_info["classpath"])

    cp_entries = [bridge_classes] + artifact_info["classpath"]
    cp_str = os.pathsep.join(cp_entries)

    tmp_req: Optional[Path] = None
    try:
        cmd = [
            java_info["java"],
            "--add-opens", "java.base/java.net=ALL-UNNAMED",
            f"-Djava.util.prefs.PreferencesFactory={_PREFS_FACTORY_CLASS}",
            "-cp", cp_str,
            _BRIDGE_MAIN_CLASS,
            action,
        ]
        if payload is not None:
            fd, tmp_name = tempfile.mkstemp(prefix="ipscan_req_", suffix=".json")
            os.close(fd)
            tmp_req = Path(tmp_name)
            tmp_req.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            cmd.append(str(tmp_req))

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )

        stdout = (proc.stdout or "").strip()
        # Parse last JSON line in stdout in case any JVM notice preceded it
        parsed: Optional[dict[str, Any]] = None
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    parsed = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        if parsed is None:
            raise RuntimeError(
                f"Angry IP Scanner bridge returned non-JSON output (exit {proc.returncode}):\n"
                f"STDOUT: {stdout}\nSTDERR: {(proc.stderr or '').strip()}"
            )

        if not parsed.get("ok"):
            err_msg = parsed.get("error") or "Unknown Angry IP Scanner backend error"
            exc_name = parsed.get("exception")
            detail = f" ({exc_name})" if exc_name else ""
            raise RuntimeError(f"Angry IP Scanner engine error{detail}: {err_msg}")

        return parsed
    finally:
        if tmp_req is not None and tmp_req.exists():
            try:
                tmp_req.unlink()
            except OSError:
                pass


def get_backend_info() -> dict[str, Any]:
    """Query the real Angry IP Scanner engine for version, pingers, fetchers, exporters."""
    java_info = find_java(min_major=21)
    artifact_info = find_ipscan_artifact()
    bridge_info = _invoke_bridge("info", timeout=60)
    bridge_info["runtime"] = {
        "java": java_info["java"],
        "java_major": java_info["major_version"],
        "javac": java_info["javac"],
        "artifact": artifact_info["artifact"],
        "artifact_source": artifact_info["source"],
        "has_jna": artifact_info["has_jna"],
        "native_executable": artifact_info["native_executable"],
    }
    return bridge_info


def run_scan(request: dict[str, Any], timeout: int = 300) -> dict[str, Any]:
    """Execute a real network scan through Angry IP Scanner's engine."""
    return _invoke_bridge("scan", payload=request, timeout=timeout)


def run_export(request: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    """Export scan results via Angry IP Scanner's real ExportProcessor and Exporters."""
    return _invoke_bridge("export", payload=request, timeout=timeout)


def run_native_cli(
    feeder_flag: str,
    feeder_args: list[str],
    output_path: Optional[str] = None,
    auto_start: bool = True,
    auto_quit: bool = True,
    append: bool = False,
    timeout: int = 180,
) -> dict[str, Any]:
    """Invoke Angry IP Scanner's original CommandLineProcessor directly.

    Note: Angry IP Scanner's native CLI initializes SWT MainWindow even with
    ``-s -q`` and therefore requires a desktop display (or Xvfb on Linux).
    Prefer headless ``scan run`` / ``export render`` for server/agent workflows.
    """
    artifact_info = find_ipscan_artifact()
    java_info = find_java(min_major=21)

    flags = ""
    if auto_start:
        flags += "s"
    if auto_quit:
        flags += "q"
    if append:
        flags += "a"

    cli_args: list[str] = []
    if flags:
        cli_args.append(f"-{flags}")
    cli_args.append(f"-f:{feeder_flag}")
    cli_args.extend(feeder_args)
    if output_path:
        cli_args.extend(["-o", output_path])

    if artifact_info.get("native_executable"):
        cmd = [artifact_info["native_executable"]] + cli_args
    else:
        cmd = [
            java_info["java"],
            "--add-opens", "java.base/java.net=ALL-UNNAMED",
            "-jar", artifact_info["artifact"],
        ] + cli_args

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "command": cmd,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
        "output_path": os.path.abspath(output_path) if output_path else None,
        "output_exists": bool(output_path and os.path.isfile(output_path)),
    }
