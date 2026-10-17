"""Real local CLI lifecycle: isolated Agent config, managed services and policy reload."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import tomllib
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _json_request(url: str, body: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    request = Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "Authorization": "Bearer lifecycle-test-key"},
    )
    try:
        response = build_opener(ProxyHandler({})).open(request, timeout=5)
    except HTTPError as exc:
        response = exc
    with response:
        return response.status, json.loads(response.read())


def _health(name: str, port: int) -> dict[str, Any] | None:
    path = "/_qise/health" if name == "proxy" else "/v1/bridge/health"
    try:
        status, payload = _json_request(f"http://127.0.0.1:{port}{path}")
    except (OSError, ValueError):
        return None
    return payload if status == 200 and payload.get("service") == f"qise-{name}" else None


def _cleanup_owned_services(home: Path, ports: dict[str, int]) -> None:
    """Handle failed assertions/startup without ever terminating unrelated services."""
    from qise.product.service import is_pid_running

    try:
        records = json.loads((home / "state.json").read_text()).get("services", {})
    except (OSError, ValueError):
        records = {}
    for name, port in ports.items():
        health = _health(name, port)
        if not health or not isinstance(health.get("pid"), int):
            continue
        pid = health["pid"]
        record = records.get(name, {})
        owned = record.get("pid") == pid and record.get("instance_id") == health.get("instance_id")
        if not owned and sys.platform.startswith("linux"):
            # Startup can fail before state.json is saved. The unique test home
            # proves ownership even in that rollback path.
            with suppress(OSError):
                owned = f"QISE_HOME={home}".encode() in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        if not owned:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            deadline = time.monotonic() + 3
            while is_pid_running(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if is_pid_running(pid):
                os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        except ProcessLookupError:
            pass


def test_protect_codex_live_policy_and_stop(tmp_path: Path) -> None:
    """Exercise the public CLI against real Bridge/Proxy and a local Responses API."""
    from qise.product.service import is_pid_running

    received: list[tuple[str, dict[str, Any]]] = []
    tool_call = {
        "type": "function_call",
        "id": "fc_lifecycle",
        "call_id": "call_lifecycle",
        "name": "bash",
        "arguments": json.dumps({"command": "rm -rf /"}),
        "status": "completed",
    }

    class Upstream(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            received.append((self.path, body))
            payload = json.dumps({
                "id": "resp_lifecycle",
                "object": "response",
                "status": "completed",
                "model": "lifecycle-test",
                "output": [tool_call],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    upstream.daemon_threads = True
    upstream_thread = threading.Thread(target=lambda: upstream.serve_forever(poll_interval=0.05), daemon=True)
    home = tmp_path / "qise-home"
    agent_home = tmp_path / "agent-home"
    agent_config = agent_home / ".codex" / "config.toml"
    agent_config.parent.mkdir(parents=True)
    original = (
        '# User settings must survive protect and stop exactly.\n'
        'model = "lifecycle-test"\n'
        'model_provider = "local-test"\n'
        '\n[model_providers.local-test]\n'
        'name = "Local lifecycle fixture"\n'
        f'base_url = "http://127.0.0.1:{upstream.server_port}/v1"\n'
        'env_key = "QISE_LIFECYCLE_API_KEY"\n'
        'wire_api = "responses"\n'
    ).encode()
    agent_config.write_bytes(original)
    # Reserve both distinct ports together; release them immediately before the
    # CLI starts the real services. No default/user service ports are used.
    reservations = [socket.socket(), socket.socket()]
    for reservation in reservations:
        reservation.bind(("127.0.0.1", 0))
    ports = dict(zip(("proxy", "bridge"), (sock.getsockname()[1] for sock in reservations), strict=True))
    config = tmp_path / "shield.yaml"
    config.write_text(yaml.safe_dump({
        "version": "1.0",
        "integration": {"proxy": {"port": ports["proxy"]}, "bridge_port": ports["bridge"]},
        "guards": {"enabled": ["command"], "config": {"command": {"mode": "enforce"}}},
    }))
    env = {
        name: value for name, value in os.environ.items()
        if not name.startswith(("QISE_", "OPENAI_", "ANTHROPIC_", "CLAUDE_CODE_"))
    }
    env.update({
        "QISE_HOME": str(home),
        "QISE_AGENT_HOME": str(agent_home),
        "QISE_LIFECYCLE_API_KEY": "lifecycle-test-key",
        "PYTHONPATH": str(ROOT / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    })

    def cli(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", "qise", "--config", str(config), *args],
            env=env, cwd=ROOT, capture_output=True, text=True, timeout=45,
        )
        if check:
            logs = "\n".join(path.read_text() for path in sorted((home / "logs").glob("*.log")))
            assert result.returncode == 0, f"{args}: {result.stdout}\n{result.stderr}\n{logs}"
        return result

    stopped = False
    upstream_thread.start()
    try:
        for reservation in reservations:
            reservation.close()
        cli("protect", "codex")
        state = json.loads((home / "state.json").read_text())
        records = state["services"]
        for name, port in ports.items():
            health = _health(name, port)
            assert health is not None
            assert health["pid"] == records[name]["pid"]
            assert health["instance_id"] == records[name]["instance_id"]
            assert health["instance_id"]
            if name == "proxy":
                assert health["version"]
            assert records[name]["port"] == port
            assert records[name]["managed_by"] == "qise"
        patched = tomllib.loads(agent_config.read_text())
        assert patched["model_provider"] == "qise-proxy"
        provider = patched["model_providers"]["qise-proxy"]
        assert provider["wire_api"] == "responses"
        assert provider["base_url"] == f"http://127.0.0.1:{ports['proxy']}/agent/codex/v1"
        backup = Path(state["protected_agents"]["codex"]["backup_path"])
        assert (backup / "original_config").read_bytes() == original

        request = {"model": "lifecycle-test", "input": "List the working directory.", "stream": False}
        url = provider["base_url"] + "/responses"
        status, payload = _json_request(url, request)
        assert status == 403 and payload["error"]["type"] == "qise_guard_block", payload

        cli("guards", "--set", "command", "off")
        status, payload = _json_request(url, request)
        assert status == 200 and payload["output"] == [tool_call], payload

        cli("guards", "--set", "command", "enforce")
        status, payload = _json_request(url, request)
        assert status == 403 and payload["error"]["type"] == "qise_guard_block", payload
        assert len(received) == 3  # Each decision occurred after the actual upstream response.
        assert all(path == "/v1/responses" for path, _ in received)
        for name, port in ports.items():
            health = _health(name, port)
            assert health is not None
            assert (health["pid"], health["instance_id"]) == (records[name]["pid"], records[name]["instance_id"])

        cli("stop")
        stopped = True
        assert agent_config.read_bytes() == original
        final_state = json.loads((home / "state.json").read_text())
        assert final_state["services"] == {}
        assert final_state["protected_agents"] == {}
        for name, port in ports.items():
            assert _health(name, port) is None
            assert not is_pid_running(records[name]["pid"])
    finally:
        for reservation in reservations:
            reservation.close()
        try:
            if not stopped:
                cli("stop", check=False)
        finally:
            _cleanup_owned_services(home, ports)
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=3)
