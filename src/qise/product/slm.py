"""Local SLM lifecycle helpers for the product CLI."""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml

from qise.product.service import atomic_write_text, is_pid_running, load_state, logs_dir, now_iso, qise_home, save_state

DEFAULT_SLM_MODEL = "qwen3:4b"
DEFAULT_SLM_BASE_URL = "http://localhost:11434/v1"
DEFAULT_SLM_TIMEOUT_MS = 10000
COMMON_EXECUTABLE_DIRS = (
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/opt/local/bin",
)


@dataclass
class SlmCommandResult:
    code: int
    message: str


def _config_path(config_path: str | None = None) -> Path:
    return Path(config_path).expanduser() if config_path else qise_home() / "shield.yaml"


def _read_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"version": "1.0"}
    raw = yaml.safe_load(path.read_text()) or {}
    return raw if isinstance(raw, dict) else {"version": "1.0"}


def _write_config(path: Path, data: dict[str, Any]) -> None:
    atomic_write_text(path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def _set_slm_config(
    *,
    config_path: str | None,
    base_url: str,
    model: str,
    timeout_ms: int,
    api_key: str = "",
) -> Path:
    path = _config_path(config_path)
    data = _read_config(path)
    models = data.setdefault("models", {})
    if not isinstance(models, dict):
        models = {}
        data["models"] = models
    slm = models.setdefault("slm", {})
    if not isinstance(slm, dict):
        slm = {}
        models["slm"] = slm

    slm["base_url"] = base_url.rstrip("/")
    slm["model"] = model
    slm["timeout_ms"] = timeout_ms
    if api_key:
        slm["api_key"] = api_key
    else:
        slm.pop("api_key", None)
    _write_config(path, data)
    return path


def _disable_slm_config(config_path: str | None) -> Path:
    path = _config_path(config_path)
    data = _read_config(path)
    models = data.setdefault("models", {})
    if not isinstance(models, dict):
        models = {}
        data["models"] = models
    slm = models.setdefault("slm", {})
    if not isinstance(slm, dict):
        slm = {}
        models["slm"] = slm
    slm["base_url"] = ""
    slm["model"] = ""
    slm.pop("api_key", None)
    _write_config(path, data)
    return path


def _ollama_api_base(base_url: str) -> str:
    parsed = urlparse(base_url.rstrip("/"))
    path = parsed.path.rstrip("/")
    if path.endswith("/v1"):
        path = path[:-3]
    return f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")


def _is_ollama_endpoint(base_url: str) -> bool:
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"} and (parsed.port or 80) == 11434


def _http_get_json(url: str, *, timeout_s: float = 3.0) -> dict[str, Any] | None:
    try:
        response = httpx.get(url, timeout=timeout_s)
        if response.status_code != 200:
            return None
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _ollama_tags(base_url: str) -> dict[str, Any] | None:
    return _http_get_json(f"{_ollama_api_base(base_url)}/api/tags")


def _ollama_running(base_url: str) -> bool:
    return _ollama_tags(base_url) is not None


def _ollama_model_installed(base_url: str, model: str) -> bool:
    data = _ollama_tags(base_url)
    if not data:
        return False
    models = data.get("models", [])
    if not isinstance(models, list):
        return False
    wanted = model.strip()
    for item in models:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("model") or "")
        if name == wanted:
            return True
    return False


def _process_command(pid: int) -> str:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _pid_running(pid: int | None) -> bool:
    return is_pid_running(pid)


def _which(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for directory in COMMON_EXECUTABLE_DIRS:
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _install_ollama(lines: list[str], *, no_install: bool = False) -> str:
    existing = _which("ollama")
    if existing:
        return existing
    if no_install or os.environ.get("QISE_SLM_NO_INSTALL"):
        raise RuntimeError("Ollama is not installed. Install Ollama or re-run without --no-install.")

    system = platform.system()
    brew = _which("brew")
    if system == "Darwin" and brew:
        lines.append("Ollama not found; installing with Homebrew...")
        subprocess.run([brew, "install", "ollama"], check=True)
    elif system == "Linux":
        curl = _which("curl")
        sh = _which("sh")
        if not curl or not sh:
            raise RuntimeError("Ollama is not installed and curl/sh were not found for automatic install.")
        lines.append("Ollama not found; installing from https://ollama.com/install.sh...")
        subprocess.run(f"{curl} -fsSL https://ollama.com/install.sh | {sh}", shell=True, check=True)
    else:
        raise RuntimeError("Ollama is not installed. Install it first, then run `qise slm start` again.")

    installed = _which("ollama")
    if not installed:
        raise RuntimeError("Ollama installation finished, but the `ollama` command was not found on PATH.")
    return installed


def _start_ollama_if_needed(base_url: str, lines: list[str], *, no_install: bool = False) -> tuple[int | None, str]:
    if _ollama_running(base_url):
        lines.append(f"Ollama server is already running at {_ollama_api_base(base_url)}.")
        return None, "already_running"

    ollama = _install_ollama(lines, no_install=no_install)
    log_dir = logs_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / "slm-ollama.out.log"
    stderr_path = log_dir / "slm-ollama.err.log"
    stdout = stdout_path.open("ab")
    stderr = stderr_path.open("ab")
    proc = subprocess.Popen(
        [ollama, "serve"],
        stdout=stdout,
        stderr=stderr,
        env=os.environ.copy(),
        cwd=str(Path.cwd()),
        start_new_session=True,
    )
    stdout.close()
    stderr.close()

    deadline = time.time() + 30
    while time.time() < deadline:
        if _ollama_running(base_url):
            lines.append(f"Started Ollama server at {_ollama_api_base(base_url)}.")
            return proc.pid, "running"
        if proc.poll() is not None:
            raise RuntimeError(f"Ollama exited with code {proc.returncode}. See {stderr_path}.")
        time.sleep(0.5)
    raise RuntimeError(f"Ollama did not become ready within 30s. See {stderr_path}.")


def _pull_ollama_model(base_url: str, model: str, lines: list[str], *, no_pull: bool = False) -> None:
    if _ollama_model_installed(base_url, model):
        lines.append(f"Model {model} is already installed.")
        return
    if no_pull or os.environ.get("QISE_SLM_NO_PULL"):
        raise RuntimeError(f"Model {model} is not installed. Run `ollama pull {model}` or re-run without --no-pull.")
    ollama = _which("ollama")
    if not ollama:
        raise RuntimeError("Cannot pull model because `ollama` was not found on PATH.")
    lines.append(f"Pulling model {model}. This may take a few minutes...")
    subprocess.run([ollama, "pull", model], check=True)
    lines.append(f"Model {model} is ready.")


def _verify_chat_completion(
    base_url: str,
    model: str,
    *,
    api_key: str = "",
    timeout_ms: int = DEFAULT_SLM_TIMEOUT_MS,
) -> tuple[bool, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Respond with exactly: OK"}],
        "max_tokens": 256,
        "temperature": 0,
    }
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=payload,
            timeout=timeout_ms / 1000,
        )
        if response.status_code != 200:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
        data = response.json()
        if not data.get("choices"):
            return False, "Response did not include choices."
        return True, "chat/completions responded"
    except Exception as exc:
        return False, str(exc)


def _save_slm_state(
    *,
    provider: str,
    base_url: str,
    model: str,
    config_path: Path,
    server_pid: int | None,
    server_status: str,
    managed_server: bool,
) -> None:
    state = load_state()
    state["slm"] = {
        "provider": provider,
        "base_url": base_url.rstrip("/"),
        "model": model,
        "config_path": str(config_path),
        "server_pid": server_pid,
        "server_status": server_status,
        "managed_server": managed_server,
        "updated_at": now_iso(),
    }
    save_state(state)


def start_slm(
    *,
    config_path: str | None = None,
    model: str = DEFAULT_SLM_MODEL,
    base_url: str = DEFAULT_SLM_BASE_URL,
    api_key: str = "",
    timeout_ms: int = DEFAULT_SLM_TIMEOUT_MS,
    no_install: bool = False,
    no_pull: bool = False,
    no_verify: bool = False,
) -> SlmCommandResult:
    """Enable the second-layer local SLM and prepare the backing server if it is Ollama."""
    base_url = (base_url or DEFAULT_SLM_BASE_URL).rstrip("/")
    model = model or DEFAULT_SLM_MODEL
    lines: list[str] = ["Qise SLM Start", ""]
    provider = "Ollama" if _is_ollama_endpoint(base_url) else "OpenAI-compatible"
    server_pid: int | None = None
    server_status = "external"
    managed_server = False
    code = 0

    try:
        if provider == "Ollama":
            server_pid, server_status = _start_ollama_if_needed(base_url, lines, no_install=no_install)
            managed_server = server_pid is not None
            _pull_ollama_model(base_url, model, lines, no_pull=no_pull)
        else:
            lines.append("Using custom OpenAI-compatible SLM endpoint; Qise will not manage that server.")

        config_file = _set_slm_config(
            config_path=config_path,
            base_url=base_url,
            model=model,
            timeout_ms=timeout_ms,
            api_key=api_key,
        )
        lines.append(f"Configured Qise SLM in {config_file}.")

        if no_verify or os.environ.get("QISE_SLM_NO_VERIFY"):
            lines.append("Verification skipped.")
        else:
            ok, detail = _verify_chat_completion(base_url, model, api_key=api_key, timeout_ms=timeout_ms)
            if not ok:
                lines.append(f"Warning: SLM verification failed: {detail}")
                lines.append("The config was written, but Qise may fall back to rules until the endpoint works.")
                code = 1
            else:
                lines.append(f"Verified SLM endpoint: {detail}.")
                code = 0

        _save_slm_state(
            provider=provider,
            base_url=base_url,
            model=model,
            config_path=config_file,
            server_pid=server_pid,
            server_status=server_status,
            managed_server=managed_server,
        )
    except Exception as exc:
        return SlmCommandResult(1, "\n".join(lines + [f"Error: {exc}"]))

    lines.extend([
        "",
        "SLM protection is enabled for new Qise processes.",
        "If Qise proxy is already running, restart protection with `qise stop` then `qise protect <agent>`.",
    ])
    return SlmCommandResult(code, "\n".join(lines))


def stop_slm(*, config_path: str | None = None, keep_server: bool = False) -> SlmCommandResult:
    """Disable Qise SLM configuration and optionally stop a Qise-managed Ollama server."""
    lines = ["Qise SLM Stop", ""]
    config_file = _disable_slm_config(config_path)
    lines.append(f"Disabled Qise SLM config in {config_file}.")

    state = load_state()
    slm_state = state.get("slm", {}) if isinstance(state.get("slm"), dict) else {}
    pid = slm_state.get("server_pid")
    managed = bool(slm_state.get("managed_server"))

    if keep_server:
        lines.append("Local SLM server left running because --keep-server was set.")
    elif managed and isinstance(pid, int) and _pid_running(pid):
        command = _process_command(pid)
        if "ollama" in command and "serve" in command:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 5
            while time.time() < deadline and _pid_running(pid):
                time.sleep(0.1)
            if _pid_running(pid):
                lines.append(f"Warning: Ollama pid {pid} did not stop after SIGTERM.")
            else:
                lines.append(f"Stopped Qise-managed Ollama server pid {pid}.")
        else:
            lines.append(f"SLM pid {pid} does not look like `ollama serve`; leaving it running.")
    elif managed:
        lines.append("No running Qise-managed SLM server found.")
    else:
        lines.append("No Qise-managed SLM server recorded; external Ollama/custom servers were not stopped.")

    state["slm"] = {
        "enabled": False,
        "last_base_url": slm_state.get("base_url", ""),
        "last_model": slm_state.get("model", ""),
        "updated_at": now_iso(),
    }
    save_state(state)
    lines.append("")
    lines.append("Qise will use rule-only mode for new processes until `qise slm start` is run again.")
    return SlmCommandResult(0, "\n".join(lines))


def slm_status(*, config_path: str | None = None) -> dict[str, Any]:
    """Return local SLM status as structured data."""
    config_file = _config_path(config_path)
    data = _read_config(config_file)
    models = data.get("models", {})
    slm = models.get("slm", {}) if isinstance(models, dict) else {}
    if not isinstance(slm, dict):
        slm = {}
    base_url = str(slm.get("base_url") or "")
    model = str(slm.get("model") or "")
    timeout_ms = int(slm.get("timeout_ms") or DEFAULT_SLM_TIMEOUT_MS)
    configured = bool(base_url and model)
    provider = "Ollama" if base_url and _is_ollama_endpoint(base_url) else ("OpenAI-compatible" if base_url else "none")
    server_running = False
    model_installed: bool | None = None
    verification = "not_configured"

    if configured and provider == "Ollama":
        server_running = _ollama_running(base_url)
        model_installed = _ollama_model_installed(base_url, model) if server_running else False
        verification = "ready" if server_running and model_installed else "not_ready"
    elif configured:
        ok, detail = _verify_chat_completion(
            base_url,
            model,
            api_key=str(slm.get("api_key") or ""),
            timeout_ms=min(timeout_ms, 3000),
        )
        server_running = ok
        verification = "ready" if ok else f"not_ready: {detail}"

    state = load_state()
    slm_state = state.get("slm", {}) if isinstance(state.get("slm"), dict) else {}
    return {
        "configured": configured,
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "timeout_ms": timeout_ms,
        "config_path": str(config_file),
        "server_running": server_running,
        "model_installed": model_installed,
        "verification": verification,
        "state": slm_state,
    }


def render_slm_status(status: dict[str, Any], *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(status, indent=2, sort_keys=True)
    lines = [
        "Qise SLM Status",
        "",
        f"Configured: {'yes' if status['configured'] else 'no'}",
        f"Provider: {status['provider']}",
        f"Model: {status['model'] or '(none)'}",
        f"Endpoint: {status['base_url'] or '(none)'}",
        f"Timeout: {status['timeout_ms']}ms",
        f"Config: {status['config_path']}",
        f"Server running: {'yes' if status['server_running'] else 'no'}",
    ]
    if status["model_installed"] is not None:
        lines.append(f"Model installed: {'yes' if status['model_installed'] else 'no'}")
    lines.append(f"Verification: {status['verification']}")
    if status["configured"]:
        lines.extend([
            "",
            "New Qise processes will use this SLM layer.",
            "Restart Qise proxy/protection if it was already running before this config changed.",
        ])
    else:
        lines.extend(["", "Qise is in rule-only mode for new processes."])
    return "\n".join(lines)
