import os
import platform
import re
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any

COMMAND_TIMEOUT = 5


def run_command(
    args: list[str],
    *,
    timeout: int = COMMAND_TIMEOUT,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "command": args,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except FileNotFoundError:
        return {
            "command": args,
            "returncode": None,
            "stdout": "",
            "stderr": "command not found",
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": args,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": f"command timed out after {timeout}s",
        }
    except Exception as exc:
        return {
            "command": args,
            "returncode": None,
            "stdout": "",
            "stderr": repr(exc),
        }


def command_info(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    result = {
        "name": name,
        "path": path,
        "exists": path is not None,
    }
    if path:
        try:
            result["realpath"] = os.path.realpath(path)
            result["is_symlink"] = os.path.islink(path)
        except OSError:
            pass
        result["file"] = run_command(["file", "-L", path])
    return result


def list_directory(
    directory: str,
    *,
    pattern: str | None = None,
) -> dict[str, Any]:
    path = Path(directory)
    result: dict[str, Any] = {
        "path": directory,
        "exists": path.exists(),
        "is_directory": path.is_dir(),
        "entries": [],
    }
    if not path.is_dir():
        return result
    try:
        for entry in sorted(path.iterdir(), key=lambda p: p.name):
            if pattern and not re.search(pattern, entry.name):
                continue
            try:
                result["entries"].append(
                    {
                        "name": entry.name,
                        "path": str(entry),
                        "type": (
                            "symlink"
                            if entry.is_symlink()
                            else "directory"
                            if entry.is_dir()
                            else "file"
                            if entry.is_file()
                            else "other"
                        ),
                        "realpath": os.path.realpath(entry),
                    }
                )
            except OSError:
                result["entries"].append(
                    {
                        "name": entry.name,
                        "path": str(entry),
                        "type": "unreadable",
                    }
                )
    except OSError as exc:
        result["error"] = repr(exc)
    return result


def read_text_file(path: str, max_bytes: int = 64 * 1024) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": path,
        "exists": os.path.exists(path),
    }
    if not result["exists"]:
        return result
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        result["content"] = data.decode("utf-8", errors="replace")
    except Exception as exc:
        result["error"] = repr(exc)
    return result


GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+){0,2}(?:rc\d+)?")
GO_MODULE_RE = re.compile(rb"[a-zA-Z0-9._/-]+@v\d+\.\d+\.\d+[a-zA-Z0-9._+-]*")


def scan_go_buildinfo(path: str, max_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    """Fingerprint a binary as Go-built without `go version`/`readelf`/`nm` -
    none of which exist in this image. Go embeds a "Go buildinf:" magic
    header (used internally by `go version <binary>`) plus literal
    "go1.x.y" and module@version strings in the binary itself, so a raw
    byte scan finds the same signal those tools would report."""
    result: dict[str, Any] = {"path": path}
    try:
        size = os.path.getsize(path)
        result["size_bytes"] = size
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except OSError as exc:
        result["error"] = repr(exc)
        return result

    result["truncated"] = size > len(data)
    result["has_go_buildinf_magic"] = b"Go buildinf:" in data

    versions = sorted({m.decode() for m in GO_VERSION_RE.findall(data)})
    result["go_version_strings"] = versions

    modules = sorted({m.decode() for m in GO_MODULE_RE.findall(data)})
    result["go_module_paths_sample"] = modules[:50]

    result["is_go_binary"] = bool(result["has_go_buildinf_magic"] or versions)
    return result


def find_executables(root: str, *, name_pattern: str | None = None, max_entries: int = 60) -> list[dict[str, Any]]:
    """Walk `root` looking for executable files, optionally filtered by
    filename regex. Bounded by max_entries so this can't run away inside a
    large tree like /cnb/buildpacks."""
    results: list[dict[str, Any]] = []
    root_path = Path(root)
    if not root_path.is_dir():
        return results
    name_re = re.compile(name_pattern) if name_pattern else None
    for dirpath, _dirnames, filenames in os.walk(root_path):
        for filename in filenames:
            if len(results) >= max_entries:
                return results
            if name_re and not name_re.search(filename):
                continue
            full_path = Path(dirpath) / filename
            try:
                if full_path.is_symlink() or not full_path.is_file():
                    continue
                if not os.access(full_path, os.X_OK):
                    continue
            except OSError:
                continue
            results.append(
                {
                    "path": str(full_path),
                    "file": run_command(["file", "-L", str(full_path)]),
                    "go_buildinfo": scan_go_buildinfo(str(full_path)),
                }
            )
    return results


def go_binary_scan() -> dict[str, Any]:
    """Since there's no `go`/`readelf`/`nm` in this run image, the only way
    to find Go's fingerprints is to fingerprint binaries directly. CNB
    lifecycle (detector/builder/exporter/restorer/launcher) and the
    per-buildpack bin/detect + bin/build executables are historically
    Go-compiled, so those are the most likely places to actually find Go's
    footprint even though the `go` toolchain package itself isn't here."""
    return {
        "cnb_lifecycle_binaries": find_executables("/cnb/lifecycle", max_entries=20),
        "cnb_buildpack_bin_binaries": find_executables(
            "/cnb/buildpacks", name_pattern=r"^(detect|build|main)$", max_entries=60
        ),
    }


def survey_binaries(
    directories: tuple[str, ...],
    *,
    max_entries: int = 150,
) -> list[dict[str, Any]]:
    """Broad sweep of every executable in the given directories (deduped by
    realpath, since /bin, /sbin etc. are symlinks into /usr/*), each
    fingerprinted with `file` and the Go buildinfo scanner. This is the
    general "what's actually installed and shellable" inventory - not just
    the Go-specific angle."""
    seen_realpaths: set[str] = set()
    results: list[dict[str, Any]] = []
    for directory in directories:
        if len(results) >= max_entries:
            break
        dir_path = Path(directory)
        if not dir_path.is_dir():
            continue
        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if len(results) >= max_entries:
                break
            try:
                if not entry.is_file() or not os.access(entry, os.X_OK):
                    continue
                real = os.path.realpath(entry)
            except OSError:
                continue
            if real in seen_realpaths:
                continue
            seen_realpaths.add(real)
            results.append(
                {
                    "path": str(entry),
                    "realpath": real,
                    "file": run_command(["file", "-L", str(entry)]),
                    "go_buildinfo": scan_go_buildinfo(real),
                }
            )
    return results


def entrypoint_binaries_info() -> dict[str, Any]:
    """filesystem.root shows /start -> /usr/bin/pid1 and /serve ->
    /usr/bin/serve - those, not /cnb/lifecycle/launcher, are what actually
    boots and serves this function. Fingerprint them directly since the
    generic binary_survey directory list may not include /usr/bin's full
    contents if max_entries is hit first."""
    result: dict[str, Any] = {}
    for name, path in (("pid1", "/usr/bin/pid1"), ("serve", "/usr/bin/serve")):
        entry: dict[str, Any] = {"path": path, "exists": os.path.exists(path)}
        if entry["exists"]:
            entry["file"] = run_command(["file", "-L", path])
            entry["go_buildinfo"] = scan_go_buildinfo(path)
        result[name] = entry
    return result


def installed_python_packages() -> list[dict[str, str]]:
    """What's actually importable right now - the real answer to "what can
    this Python environment do", as opposed to inferring it from shelling
    out to OS-level tools."""
    packages: dict[str, str] = {}
    for dist in importlib_metadata.distributions():
        name = dist.metadata.get("Name")
        if not name:
            continue
        packages[name] = dist.version
    return [
        {"name": name, "version": version}
        for name, version in sorted(packages.items(), key=lambda kv: kv[0].lower())
    ]


def resource_info() -> dict[str, Any]:
    result: dict[str, Any] = {"cpu_count": os.cpu_count()}

    for label, path in (("tmp", "/tmp"), ("workspace", "/workspace")):
        try:
            usage = shutil.disk_usage(path)
            result[f"disk_usage_{label}"] = {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
            }
        except OSError as exc:
            result[f"disk_usage_{label}"] = {"error": repr(exc)}

    limits: dict[str, Any] = {}
    for name in ("RLIMIT_NOFILE", "RLIMIT_NPROC", "RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE"):
        rlimit = getattr(resource, name, None)
        if rlimit is None:
            continue
        try:
            soft, hard = resource.getrlimit(rlimit)
            limits[name] = {"soft": soft, "hard": hard}
        except (ValueError, OSError) as exc:
            limits[name] = {"error": repr(exc)}
    result["rlimits"] = limits

    for label, directory in (("tmp", "/tmp"), ("workspace", "/workspace")):
        try:
            with tempfile.NamedTemporaryFile(dir=directory) as tmp_file:
                tmp_file.write(b"probe")
                tmp_file.flush()
            result[f"{label}_writable"] = True
        except OSError as exc:
            result[f"{label}_writable"] = False
            result[f"{label}_write_error"] = repr(exc)

    return result


def network_info() -> dict[str, Any]:
    """Bare TCP connect + DNS lookup only - no TLS handshake, no HTTP
    request, no data sent - just enough to answer "can this function reach
    the outside world at all", which gates most creative uses of it."""
    result: dict[str, Any] = {}
    try:
        addresses = sorted({addr[4][0] for addr in socket.getaddrinfo("www.googleapis.com", 443)})
        result["dns_resolution"] = {"host": "www.googleapis.com", "addresses": addresses}
    except OSError as exc:
        result["dns_resolution"] = {"error": repr(exc)}

    try:
        with socket.create_connection(("www.googleapis.com", 443), timeout=3):
            result["outbound_tcp_443"] = True
    except OSError as exc:
        result["outbound_tcp_443"] = False
        result["outbound_tcp_443_error"] = repr(exc)

    return result


def cnb_info() -> dict[str, Any]:
    """Cloud Native Buildpacks metadata. K_SERVICE/CNB_STACK_ID etc in the
    environment dump indicate this function runs on a buildpacks-produced
    run image, not the flat apt/dpkg base image the runtime docs table
    describes - these files pin down exactly which stack/build that is."""
    return {
        "stack_toml": read_text_file("/cnb/stack.toml"),
        "order_toml": read_text_file("/cnb/order.toml"),
        "run_toml": read_text_file("/cnb/run.toml"),
        "buildpacks_dir": list_directory("/cnb/buildpacks"),
        "lifecycle_dir": list_directory("/cnb/lifecycle"),
    }


def layers_info() -> dict[str, Any]:
    return {
        "layers_root": list_directory("/layers"),
        "google_python_runtime": list_directory("/layers/google.python.runtime"),
        "google_python_pip": list_directory("/layers/google.python.pip"),
    }


def os_release_info() -> dict[str, Any]:
    return {
        "os_release": read_text_file("/etc/os-release"),
        "lsb_release": read_text_file("/etc/lsb-release"),
        "debian_version": read_text_file("/etc/debian_version"),
        "apt_sources_list": read_text_file("/etc/apt/sources.list"),
        "apt_sources_list_d": list_directory("/etc/apt/sources.list.d"),
        "sandboxed_gvisor": "gvisor" in platform.release().lower(),
    }


def package_info() -> dict[str, Any]:
    result: dict[str, Any] = {}
    result["dpkg_go"] = run_command(
        ["dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\n", "go"]
    )
    result["dpkg_go_packages"] = run_command(
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\\t${Version}\\n",
        ]
    )
    result["apt_policy_go"] = run_command(["apt-cache", "policy", "go"])
    return result


def go_info() -> dict[str, Any]:
    result: dict[str, Any] = {
        "resolved_commands": {},
        "which_a_go": run_command(["/bin/sh", "-c", "which -a go"]),
        "paths": {},
        "environment": {},
    }
    for command in (
        "go",
        "gofmt",
        "gccgo",
        "file",
        "readelf",
        "ldd",
        "dpkg",
        "dpkg-query",
        "apt",
    ):
        result["resolved_commands"][command] = command_info(command)

    go_path = shutil.which("go")
    if go_path:
        result["paths"]["go"] = go_path
        result["paths"]["go_realpath"] = os.path.realpath(go_path)
        result["version"] = run_command([go_path, "version"])
        result["env"] = run_command([go_path, "env", "-json"], timeout=10)
        result["toolchain"] = run_command(
            [go_path, "env", "GOTOOLDIR", "GOROOT", "GOPATH", "GOMODCACHE"]
        )
        result["go_binary_file"] = run_command(["file", "-L", go_path])
        result["go_binary_readelf"] = run_command(
            ["readelf", "-h", "-l", "-d", go_path],
            timeout=10,
        )
        result["go_binary_ldd"] = run_command(["ldd", go_path], timeout=10)

    for directory in (
        "/usr/bin",
        "/usr/local/bin",
        "/usr/lib/go",
        "/usr/local/go",
        "/usr/local/go/bin",
        "/opt",
    ):
        result.setdefault("directories", {})[directory] = list_directory(
            directory,
            pattern=r"^(go|gofmt|gccgo|go[0-9])",
        )
    return result


def environment_info() -> dict[str, Any]:
    sensitive_patterns = re.compile(
        r"(TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|"
        r"AUTH|API_KEY|ACCESS_KEY|SECRET_KEY)",
        re.IGNORECASE,
    )
    environment = {}
    for key, value in sorted(os.environ.items()):
        if sensitive_patterns.search(key):
            environment[key] = "<redacted>"
        else:
            environment[key] = value
    return environment


def filesystem_info() -> dict[str, Any]:
    return {
        "root": list_directory("/"),
        "usr": list_directory("/usr"),
        "usr_bin_go": list_directory(
            "/usr/bin",
            pattern=r"^(go|gofmt|gccgo|go[0-9])",
        ),
        "usr_local_bin_go": list_directory(
            "/usr/local/bin",
            pattern=r"^(go|gofmt|gccgo|go[0-9])",
        ),
        "go_directories": {
            path: list_directory(path)
            for path in (
                "/usr/lib/go",
                "/usr/local/go",
                "/opt/go",
            )
        },
    }


def process_info() -> dict[str, Any]:
    return {
        "pid": os.getpid(),
        "ppid": os.getppid(),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cmdline": read_text_file("/proc/1/cmdline"),
        "self_cmdline": read_text_file(f"/proc/{os.getpid()}/cmdline"),
        "status": read_text_file(f"/proc/{os.getpid()}/status"),
        "mounts": read_text_file("/proc/mounts"),
        "cpuinfo": read_text_file("/proc/cpuinfo"),
        "meminfo": read_text_file("/proc/meminfo"),
    }


def runtime_info() -> dict[str, Any]:
    return {
        "python": {
            "version": sys.version,
            "version_info": {
                "major": sys.version_info.major,
                "minor": sys.version_info.minor,
                "micro": sys.version_info.micro,
                "releaselevel": sys.version_info.releaselevel,
                "serial": sys.version_info.serial,
            },
            "executable": sys.executable,
            "prefix": sys.prefix,
            "base_prefix": sys.base_prefix,
            "path": sys.path,
        },
        "platform": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "architecture": platform.architecture(),
            "python_implementation": platform.python_implementation(),
        },
        "uname": {
            "sysname": os.uname().sysname,
            "nodename": os.uname().nodename,
            "release": os.uname().release,
            "version": os.uname().version,
            "machine": os.uname().machine,
        },
    }


def introspect() -> dict[str, Any]:
    return {
        "runtime": runtime_info(),
        "environment": environment_info(),
        "path": os.environ.get("PATH"),
        "commands": {
            command: command_info(command)
            for command in (
                "python3",
                "python3.12",
                "bash",
                "sh",
                "curl",
                "wget",
                "git",
                "ffmpeg",
                "convert",
                "go",
                "gofmt",
                "gccgo",
                "file",
                "readelf",
                "ldd",
                "dpkg",
                "dpkg-query",
                "apt",
                "apt-cache",
                "pid1",
                "serve",
                "gs",
                "perl",
                "openssl",
                "gunicorn",
            )
        },
        "go": go_info(),
        "go_binary_scan": go_binary_scan(),
        "entrypoint_binaries": entrypoint_binaries_info(),
        "binary_survey": survey_binaries(
            ("/usr/bin", "/usr/local/bin", "/usr/sbin", "/usr/local/sbin"),
            max_entries=150,
        ),
        "cnb": cnb_info(),
        "layers": layers_info(),
        "os_release": os_release_info(),
        "packages": package_info(),
        "filesystem": filesystem_info(),
        "process": process_info(),
        "python_packages": installed_python_packages(),
        "resources": resource_info(),
        "network": network_info(),
        "workspace": list_directory("/workspace"),
    }
