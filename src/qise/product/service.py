"""Local product state and service helpers."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.request import ProxyHandler, build_opener

DEFAULT_PROXY_PORT = 8822
DEFAULT_BRIDGE_PORT = 8823


def install_stop_handlers(loop: Any, stop_event: Any) -> None:
    """Install graceful shutdown on both Unix and Windows event loops."""
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop_event.set)
        except NotImplementedError:
            signal.signal(signum, lambda *_: loop.call_soon_threadsafe(stop_event.set))


@dataclass
class PortCheck:
    host: str
    port: int
    status: str
    detail: str = ""


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def qise_version() -> str:
    try:
        from qise import __version__

        return __version__
    except Exception:
        return "unknown"


def qise_home() -> Path:
    return Path(os.environ.get("QISE_HOME", "~/.qise")).expanduser()


def profile_id() -> str:
    """Identify the local profile without exposing its filesystem path."""
    return hashlib.sha256(str(qise_home().resolve()).encode()).hexdigest()[:24]


def ensure_qise_home() -> Path:
    home = qise_home()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    return home


def state_path() -> Path:
    return qise_home() / "state.json"


def events_path() -> Path:
    return qise_home() / "events.jsonl"


def backups_dir() -> Path:
    return qise_home() / "backups"


def logs_dir() -> Path:
    return qise_home() / "logs"


def read_json_file(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text())
    except Exception:
        return default


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    """Replace a complete file, keeping credentials private and avoiding torn writes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json_file(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


@contextmanager
def file_lock(path: Path):
    """Serialize short read/modify/write transactions across local processes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "r+b") as stream:
        if os.name == "nt":
            import msvcrt

            stream.write(b"\0")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _redact_command(command: str) -> str:
    return re.sub(r"(--(?:upstream-key|api-key))(?:=|\s+)(\S+)", r"\1 [REDACTED]", command)


def load_state() -> dict[str, Any]:
    state = read_json_file(state_path(), {})
    if not isinstance(state, dict):
        return {"services": {}, "protected_agents": {}}
    for key in ("services", "protected_agents"):
        if not isinstance(state.get(key), dict):
            state[key] = {}
    # Older builds persisted API keys as part of the service command. Never
    # display them, and remove them on the next state write.
    for meta in state.get("services", {}).values():
        if isinstance(meta, dict) and isinstance(meta.get("command"), str):
            meta["command"] = _redact_command(meta["command"])
    return state


def save_state(state: dict[str, Any]) -> None:
    for meta in state.get("services", {}).values():
        if isinstance(meta, dict) and isinstance(meta.get("command"), str):
            meta["command"] = _redact_command(meta["command"])
    state["updated_at"] = now_iso()
    state["qise_version"] = qise_version()
    write_json_file(state_path(), state)


def check_port(host: str, port: int) -> PortCheck:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.bind((host, port))
    except OSError as exc:
        detail = str(exc)
        if getattr(exc, "errno", None) in {errno.EADDRINUSE, 48, 10048}:
            return PortCheck(host, port, "in_use", detail)
        return PortCheck(host, port, "unavailable", detail)
    finally:
        sock.close()
    return PortCheck(host, port, "available")


def is_pid_running(pid: int | None) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if sys.platform == "win32":
        # os.kill(pid, 0) can terminate a process on Windows. Query its handle.
        import ctypes
        from ctypes import wintypes

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    if sys.platform.startswith("linux"):
        try:
            # A terminated child can remain a zombie until its parent reaps it.
            stat = Path(f"/proc/{pid}/stat").read_text()
            if stat.rsplit(")", 1)[1].split()[0] in {"Z", "X"}:
                return False
        except (OSError, IndexError):
            pass
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def service_health(name: str, port: int) -> dict[str, Any] | None:
    """Identify Qise itself, rather than treating an occupied port as protection."""
    if name not in {"proxy", "bridge"} or not isinstance(port, int) or not 0 < port <= 65535:
        return None
    path = "/_qise/health" if name == "proxy" else "/v1/bridge/health"
    try:
        with build_opener(ProxyHandler({})).open(f"http://127.0.0.1:{port}{path}", timeout=0.6) as response:
            data = json.loads(response.read(8192))
        if (isinstance(data, dict) and data.get("service") == f"qise-{name}"
                and type(data.get("pid")) is int and data["pid"] > 0):
            return data
    except (OSError, ValueError):
        pass
    return None


def _service_matches_record(name: str, meta: dict[str, Any]) -> bool:
    try:
        port = int(meta.get("port") or 0)
    except (ValueError, TypeError):
        return False
    health = service_health(name, port)
    if not health:
        return False
    if meta.get("pid") and health["pid"] != meta["pid"]:
        return False
    return not meta.get("instance_id") or health.get("instance_id") == meta["instance_id"]


def inspect_services(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return service records annotated with their current runtime state."""
    raw_services = state.get("services", {})
    if not isinstance(raw_services, dict):
        return {}

    inspected: dict[str, dict[str, Any]] = {}
    for name, raw_meta in raw_services.items():
        if not isinstance(raw_meta, dict):
            continue
        meta = dict(raw_meta)
        status = str(meta.get("status") or "")
        try:
            port = int(meta.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        port_status = check_port("127.0.0.1", port).status if 0 < port <= 65535 else "unavailable"

        if status == "running":
            pid = meta.get("pid")
            if not isinstance(pid, int) or not is_pid_running(pid):
                meta["status"] = "stale"
                meta["detail"] = f"recorded pid {pid or '(none)'} is not running"
            elif not _service_matches_record(str(name), meta):
                meta["status"] = "stale"
                meta["detail"] = "Qise service identity could not be verified"
            elif port_status != "in_use":
                meta["status"] = "stale"
                meta["detail"] = f"127.0.0.1:{port} is not listening"
        elif status == "already_running" and (port_status != "in_use" or not _service_matches_record(str(name), meta)):
            meta["status"] = "stale"
            meta["detail"] = f"127.0.0.1:{port} is no longer listening"

        meta["port_status"] = port_status
        inspected[str(name)] = meta

    return inspected


def services_are_active(services: dict[str, dict[str, Any]]) -> bool:
    """Return whether both managed protection services are currently reachable."""
    for name in ("proxy", "bridge"):
        meta = services.get(name, {})
        if meta.get("status") not in {"running", "already_running"}:
            return False
        if meta.get("port_status") != "in_use":
            return False
    return True


def _wait_for_port(host: str, port: int, timeout_s: float = 15.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if check_port(host, port).status == "in_use":
            return True
        time.sleep(0.1)
    return False


def _spawn_service(name: str, cmd: list[str], port: int, env: dict[str, str]) -> dict[str, Any]:
    log_dir = logs_dir()
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    stdout_path = log_dir / f"{name}.out.log"
    stderr_path = log_dir / f"{name}.err.log"

    if check_port("127.0.0.1", port).status == "in_use":
        health = service_health(name, port)
        if not health:
            raise RuntimeError(f"Port {port} is used by another application; Qise protection was not started.")
        previous = load_state().get("services", {}).get(name, {})
        if (previous.get("managed_by") == "qise" and previous.get("pid") == health["pid"]
                and previous.get("instance_id") == health.get("instance_id")):
            return previous
        if health.get("profile_id") != profile_id():
            raise RuntimeError(f"Port {port} belongs to a different or older Qise profile. Choose a different port or stop that service first.")
        return {
            "pid": health["pid"],
            "port": port,
            "status": "already_running",
            "managed_by": "external-qise",
            "instance_id": health.get("instance_id", ""),
            "started_at": now_iso(),
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }

    instance_id = uuid.uuid4().hex
    env = {**env, "QISE_SERVICE_INSTANCE": instance_id}
    stdout = os.fdopen(os.open(stdout_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600), "ab")
    stderr = os.fdopen(os.open(stderr_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600), "ab")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=stdout,
            stderr=stderr,
            env=env,
            cwd=str(Path.cwd()),
            start_new_session=sys.platform != "win32",
            **({"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}),
        )
    finally:
        stdout.close()
        stderr.close()

    if not _wait_for_port("127.0.0.1", port):
        return_code = proc.poll()
        if return_code is not None:
            raise RuntimeError(f"{name} exited with code {return_code}. See {stderr_path} for details.")
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        raise RuntimeError(f"{name} did not listen on 127.0.0.1:{port} within 15s")

    health = service_health(name, port)
    if not health or health.get("instance_id") != instance_id or health["pid"] != proc.pid:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        raise RuntimeError(f"{name} started but its identity could not be verified on port {port}")

    return {
        "pid": proc.pid,
        "port": port,
        "status": "running",
        "managed_by": "qise",
        "instance_id": instance_id,
        "command": _redact_command(" ".join(cmd)),
        "started_at": now_iso(),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }


def _terminate_service_record(meta: dict[str, Any]) -> None:
    """Best-effort rollback for a service started in the current transaction."""
    pid = meta.get("pid")
    if meta.get("status") != "running" or meta.get("managed_by") != "qise":
        return
    if not isinstance(pid, int) or not is_pid_running(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 2
        while time.time() < deadline and is_pid_running(pid):
            time.sleep(0.05)
        if is_pid_running(pid):
            os.kill(pid, signal.SIGTERM if sys.platform == "win32" else signal.SIGKILL)
    except OSError:
        pass


def _qise_service_command(config_args: list[str], service_args: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *config_args, *service_args]
    return [sys.executable, "-m", "qise", *config_args, *service_args]


def start_managed_services(
    *,
    config_path: str | None,
    proxy_port: int,
    bridge_port: int = DEFAULT_BRIDGE_PORT,
    upstream_url: str,
    upstream_api_key: str = "",
) -> dict[str, Any]:
    if not upstream_url:
        raise ValueError(
            "Proxy upstream is not configured. Set integration.proxy.upstream_url, "
            "QISE_PROXY_UPSTREAM_URL, OPENAI_API_BASE, ANTHROPIC_BASE_URL, or pass --base-url."
        )

    state = load_state()
    env = os.environ.copy()
    services = state.setdefault("services", {})
    config_args = ["--config", config_path] if config_path else []

    bridge_cmd = _qise_service_command(config_args, [
        "bridge",
        "start",
        "--port",
        str(bridge_port),
    ])
    proxy_cmd = _qise_service_command(config_args, [
        "proxy",
        "start",
        "--port",
        str(proxy_port),
        "--upstream",
        upstream_url.rstrip("/"),
        "--no-reload",
    ])
    proxy_env = dict(env)
    if upstream_api_key:
        proxy_env["QISE_PROXY_UPSTREAM_API_KEY"] = upstream_api_key

    if os.environ.get("QISE_NO_START_SERVICES"):
        services["bridge"] = {
            "pid": None,
            "port": bridge_port,
            "status": "skipped",
            "managed_by": "qise-test",
            "started_at": now_iso(),
        }
        services["proxy"] = {
            "pid": None,
            "port": proxy_port,
            "status": "skipped",
            "managed_by": "qise-test",
            "upstream_url": upstream_url.rstrip("/"),
            "started_at": now_iso(),
        }
        save_state(state)
        return services

    previous_bridge = services.get("bridge", {})
    bridge_meta = _spawn_service("bridge", bridge_cmd, bridge_port, env)
    services["bridge"] = bridge_meta
    try:
        services["proxy"] = _spawn_service("proxy", proxy_cmd, proxy_port, proxy_env)
    except Exception:
        if not previous_bridge.get("pid") or previous_bridge.get("pid") != bridge_meta.get("pid"):
            _terminate_service_record(bridge_meta)
        services.pop("bridge", None)
        raise
    services["proxy"]["upstream_url"] = upstream_url.rstrip("/")
    save_state(state)
    return services


def stop_managed_services() -> tuple[list[str], list[str]]:
    state = load_state()
    services = state.get("services", {})
    stopped: list[str] = []
    notes: list[str] = []

    for name, meta in list(services.items()):
        if not isinstance(meta, dict):
            continue
        pid = meta.get("pid")
        status = meta.get("status")
        if status in {"skipped", "already_running"} or not pid:
            stopped.append(f"{name}: cleared {status or 'stale'} service record")
            services.pop(name, None)
            continue
        if not is_pid_running(pid):
            stopped.append(f"{name}: no running process found for pid {pid}")
            services.pop(name, None)
            continue
        if not _service_matches_record(name, meta):
            notes.append(f"{name}: pid {pid} is running but does not look like a Qise service; not stopping")
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 5
            while time.time() < deadline and is_pid_running(pid):
                time.sleep(0.1)
            if is_pid_running(pid):
                notes.append(f"{name}: pid {pid} did not stop after SIGTERM")
            else:
                stopped.append(f"{name}: stopped pid {pid}")
                services.pop(name, None)
        except OSError as exc:
            notes.append(f"{name}: failed to stop pid {pid}: {exc}")

    if stopped:
        state["services"] = services
        save_state(state)
    return stopped, notes
