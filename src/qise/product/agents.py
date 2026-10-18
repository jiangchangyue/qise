"""Agent detection, config backup, patch, and restore."""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qise.core.config import ShieldConfig
from qise.product.service import (
    atomic_write_text,
    backups_dir,
    inspect_services,
    load_state,
    now_iso,
    save_state,
    services_are_active,
    start_managed_services,
    state_path,
    write_json_file,
)

QISE_PROXY_PROVIDER = "qise-proxy"
QISE_MARKER_START = "# >>> qise protect"
QISE_MARKER_END = "# <<< qise protect"
_MISSING = object()


def _read_agent_json(text: str) -> dict[str, Any]:
    # JSONC is used by OpenCode. Match strings first so URLs and comment-like
    # content inside strings are untouched; accept trailing commas as well.
    without_comments = re.sub(
        r'("(?:\\.|[^"\\])*")|//[^\r\n]*|/\*.*?\*/',
        lambda match: match.group(1) or "",
        text,
        flags=re.DOTALL,
    )
    without_trailing = re.sub(
        r'("(?:\\.|[^"\\])*")|,(\s*[}\]])',
        lambda match: match.group(1) or match.group(2),
        without_comments,
    )
    data = json.loads(without_trailing)
    if not isinstance(data, dict):
        raise ValueError("Agent configuration must be an object")
    return data


def _undo_json_patch(original: Any, patched: Any, current: Any) -> Any:
    """Undo only our edits, preserving settings changed by the user meanwhile."""
    if original == patched:
        return current
    if current == patched:
        return original
    original_was_missing = original is _MISSING
    if original_was_missing and isinstance(patched, dict) and isinstance(current, dict):
        original = {}
    if all(isinstance(item, dict) for item in (original, patched, current)):
        restored = dict(current)
        for key in original.keys() | patched.keys():
            value = _undo_json_patch(original.get(key, _MISSING), patched.get(key, _MISSING), current.get(key, _MISSING))
            if value is _MISSING:
                restored.pop(key, None)
            else:
                restored[key] = value
        return _MISSING if original_was_missing and not restored else restored
    # A user has changed a field we also changed. Their current setting wins.
    return current
_JSON_BASE_URL_KEYS = {
    "base_url",
    "baseurl",
    "api_base",
    "apibaseurl",
    "api_base_url",
    "endpoint",
    "anthropicbaseurl",
    "anthropic_base_url",
}
_JSON_ENV_KEY_KEYS = {"env_key", "envkey", "api_key_env", "apikeyenv", "api_key_name", "apikeyname"}


@dataclass(frozen=True)
class AgentSpec:
    key: str
    display_name: str
    cli_names: tuple[str, ...]
    config_paths: tuple[str, ...]
    config_format: str
    experimental: bool = False
    note: str = ""
    auto_protect: bool = True


@dataclass(frozen=True)
class UpstreamInfo:
    base_url: str = ""
    api_key_env: str = ""
    api_key: str = ""
    source: str = ""


AGENTS: dict[str, AgentSpec] = {
    "codex": AgentSpec(
        key="codex",
        display_name="Codex",
        cli_names=("codex",),
        config_paths=("~/.codex/config.toml", "~/.codex/config.json", "~/.config/codex/config.toml"),
        config_format="toml",
        note="OpenAI-compatible protection via local Qise proxy.",
    ),
    "openclaw": AgentSpec(
        key="openclaw",
        display_name="OpenClaw",
        cli_names=("openclaw", "claw"),
        config_paths=("~/.openclaw/openclaw.json", "~/.openclaw/config.json", "~/.config/openclaw/config.json", "~/.claw/config.json"),
        config_format="json",
        note="OpenAI-compatible protection via local Qise proxy.",
    ),
    "claude-code": AgentSpec(
        key="claude-code",
        display_name="Claude Code",
        cli_names=("claude",),
        config_paths=("~/.claude/settings.json",),
        config_format="json",
        note="Anthropic Messages API protection via local Qise proxy.",
    ),
    "opencode": AgentSpec(
        key="opencode",
        display_name="OpenCode",
        cli_names=("opencode",),
        config_paths=("~/.config/opencode/opencode.json", "~/.config/opencode/opencode.jsonc"),
        config_format="json",
        note="Protect the selected model provider. Project settings may override global settings.",
    ),
    "workbuddy": AgentSpec(
        key="workbuddy",
        display_name="WorkBuddy",
        cli_names=("workbuddy",),
        config_paths=("~/.codebuddy/models.json",),
        config_format="json",
        auto_protect=False,
        note="Asset scanning is available. Connect a custom model through Qise in WorkBuddy model settings.",
    ),
}


def normalize_agent_key(value: str) -> str:
    raw = value.strip().lower().replace("_", "-")
    aliases = {
        "claude": "claude-code",
        "claudecode": "claude-code",
        "generic": "custom",
        "generic-openai": "custom",
    }
    return aliases.get(raw, raw)


def _agent_home() -> Path | None:
    value = os.environ.get("QISE_AGENT_HOME")
    return Path(value).expanduser() if value else None


def _expand_agent_path(path: str) -> Path:
    override = _agent_home()
    if override and path.startswith("~/"):
        return override / path[2:]
    return Path(path).expanduser()


def _load_config(path: str | None = None) -> tuple[ShieldConfig, str | None]:
    from qise.product.status import load_config
    config, label = load_config(path)
    return config, None if label == "(defaults)" else label


def _env_value(name: str) -> str:
    return os.environ.get(name, "") if name else ""


def _is_local_proxy_url(url: str, proxy_port: int) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host in {"127.0.0.1", "localhost", "::1"} and port == proxy_port


def _agent_api_key_env_candidates(agent_key: str) -> tuple[str, ...]:
    if agent_key == "claude-code":
        return ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY")
    return ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")


def _default_api_key_env_for_agent(agent_key: str) -> str:
    return _agent_api_key_env_candidates(agent_key)[0]


def _configured_upstream(
    config: ShieldConfig,
    *,
    override_url: str,
    proxy_port: int,
    agent_key: str = "",
) -> UpstreamInfo:
    env_base_candidates = (
        [
            ("ANTHROPIC_BASE_URL", os.environ.get("ANTHROPIC_BASE_URL", "")),
            ("OPENAI_API_BASE", os.environ.get("OPENAI_API_BASE", "")),
        ]
        if agent_key == "claude-code"
        else [
            ("OPENAI_API_BASE", os.environ.get("OPENAI_API_BASE", "")),
            ("ANTHROPIC_BASE_URL", os.environ.get("ANTHROPIC_BASE_URL", "")),
        ]
    )
    candidates = [
        (override_url, "--base-url"),
        (config.integration.proxy.upstream_url, "shield.yaml integration.proxy.upstream_url"),
        (os.environ.get("QISE_PROXY_UPSTREAM_URL", ""), "QISE_PROXY_UPSTREAM_URL"),
    ]
    candidates.extend((value, name) for name, value in env_base_candidates)
    base_url = ""
    source = ""
    for candidate, candidate_source in candidates:
        value = candidate.rstrip("/") if candidate else ""
        if value and not _is_local_proxy_url(value, proxy_port):
            base_url = value
            source = candidate_source
            break

    api_key_env = ""
    api_key = ""
    if config.integration.proxy.upstream_api_key:
        api_key = config.integration.proxy.upstream_api_key
        source = source or "shield.yaml integration.proxy.upstream_api_key"
    elif os.environ.get("QISE_PROXY_UPSTREAM_API_KEY"):
        api_key = os.environ["QISE_PROXY_UPSTREAM_API_KEY"]
        source = source or "QISE_PROXY_UPSTREAM_API_KEY"
    else:
        for candidate_env in _agent_api_key_env_candidates(agent_key):
            if os.environ.get(candidate_env):
                api_key_env = candidate_env
                api_key = os.environ[candidate_env]
                break

    return UpstreamInfo(base_url=base_url, api_key_env=api_key_env, api_key=api_key, source=source)


def _merge_upstream(primary: UpstreamInfo, fallback: UpstreamInfo) -> UpstreamInfo:
    if primary.base_url:
        return UpstreamInfo(
            base_url=primary.base_url,
            api_key_env=primary.api_key_env or fallback.api_key_env,
            api_key=primary.api_key or fallback.api_key,
            source=primary.source,
        )
    return fallback


def _state_upstream(agent_key: str, *, proxy_port: int) -> UpstreamInfo:
    state = load_state()
    protected = state.get("protected_agents", {})
    record = protected.get(agent_key, {}) if isinstance(protected, dict) else {}
    if not isinstance(record, dict):
        return UpstreamInfo()

    base_url = str(record.get("upstream_url") or "").rstrip("/")
    if not base_url or _is_local_proxy_url(base_url, proxy_port):
        return UpstreamInfo()

    env_key = str(record.get("proxy_env_key") or record.get("upstream_api_key_env") or "")
    return UpstreamInfo(
        base_url=base_url,
        api_key_env=env_key,
        api_key=_env_value(env_key),
        source=f"{state_path()}:protected_agents.{agent_key}",
    )


def detect_agents(*, include_missing: bool = False, services_active: bool | None = None) -> list[dict[str, Any]]:
    """Detect local Agents that Qise can operate on.

    The product-facing default is intentionally installed-only: ordinary users
    should only see Agents Qise can actually protect or scan on this machine.
    `include_missing=True` is kept for diagnostics and developer workflows.
    """
    state = load_state()
    protected = state.get("protected_agents", {})
    if services_active is None:
        services_active = services_are_active(inspect_services(state)) if protected else False
    rows: list[dict[str, Any]] = []
    for spec in AGENTS.values():
        cli_path = next((shutil.which(name) for name in spec.cli_names if shutil.which(name)), None)
        config_path = next(
            (str(path) for path in (_expand_agent_path(p) for p in spec.config_paths) if path.exists()),
            "",
        )
        record = protected.get(spec.key, {})
        configured = isinstance(record, dict) and bool(record)
        points_to_proxy = False
        if configured and config_path:
            try:
                expected = str(record.get("proxy_url") or "")
                port = urlparse(expected).port
                manager = AgentConfigManager(spec, proxy_port=port or 8822)
                active_port = state.get("services", {}).get("proxy", {}).get("port")
                points_to_proxy = (bool(expected) and str(active_port) == str(port)
                                   and manager.proxy_url == expected and manager.verify_patch(Path(config_path)))
            except (OSError, ValueError, TypeError):
                pass
        active = configured and bool(services_active) and points_to_proxy
        row = {
            "key": spec.key,
            "name": spec.display_name,
            "installed": bool(cli_path or config_path),
            "cli_path": cli_path or "",
            "config_path": config_path,
            "protected": active,
            "configured": configured,
            "can_protect": spec.auto_protect,
            "protection_status": "protected" if active else "needs_attention" if configured else "not_protected",
            "coverage": ["preflight", "model_traffic"] if spec.auto_protect else ["preflight", "manual_connection"],
            "experimental": spec.experimental,
            "note": spec.note,
        }
        if include_missing or row["installed"] or configured:
            rows.append(row)
    return rows


def render_agents(agents: list[dict[str, Any]], *, json_output: bool = False) -> str:
    if json_output:
        payload = {
            "agents": agents,
            "summary": {
                "installed": sum(1 for agent in agents if agent.get("installed")),
                "protected": sum(1 for agent in agents if agent.get("protected")),
                "returned": len(agents),
            },
        }
        return json.dumps(payload, indent=2, sort_keys=True)

    lines = ["Qise Agents", ""]
    if not agents:
        lines.append("  No supported Agent CLI/config was detected.")
        return "\n".join(lines)

    for agent in agents:
        install = "installed" if agent["installed"] else "not found"
        protected_text = "protected" if agent["protected"] else "configured, needs attention" if agent.get("configured") else "not protected"
        suffix = " (experimental)" if agent["experimental"] else ""
        lines.append(f"  {agent['name']}: {install}, {protected_text}{suffix}")
        if agent.get("cli_path"):
            lines.append(f"    cli: {agent['cli_path']}")
        if agent.get("config_path"):
            lines.append(f"    config: {agent['config_path']}")
    return "\n".join(lines)


class AgentConfigManager:
    def __init__(self, spec: AgentSpec, *, proxy_port: int = 8822, proxy_env_key: str = "") -> None:
        self.spec = spec
        self.proxy_port = proxy_port
        self.proxy_url = f"http://127.0.0.1:{proxy_port}/agent/{spec.key}/v1"
        self.proxy_env_key = proxy_env_key or _default_api_key_env_for_agent(spec.key)

    def detect(self) -> dict[str, Any]:
        rows = {row["key"]: row for row in detect_agents()}
        return rows.get(self.spec.key, {})

    def locate_config(self, *, create: bool = False) -> Path | None:
        for raw in self.spec.config_paths:
            path = _expand_agent_path(raw)
            if path.exists():
                return path
        if create:
            return _expand_agent_path(self.spec.config_paths[0])
        return None

    def read_config(self, config_path: Path) -> str:
        return config_path.read_text() if config_path.exists() else ""

    def infer_upstream(self, config_path: Path) -> UpstreamInfo:
        before = self.read_config(config_path)
        if not before.strip():
            return UpstreamInfo()
        if self.spec.key == "opencode":
            data = _read_agent_json(before)
            model = str(data.get("model") or "")
            name = model.split("/", 1)[0] if "/" in model else ""
            provider = data.get("provider", {}).get(name, {})
            options = provider.get("options", {})
            url = str(options.get("baseURL") or {
                "openai": "https://api.openai.com/v1", "anthropic": "https://api.anthropic.com/v1",
            }.get(name, ""))
            if not url or _is_local_proxy_url(url, self.proxy_port):
                return UpstreamInfo()
            key = str(options.get("apiKey") or "")
            env_match = re.fullmatch(r"\{env:([A-Za-z_][A-Za-z0-9_]*)\}", key)
            env_name = env_match.group(1) if env_match else ""
            return UpstreamInfo(url.rstrip("/"), env_name, _env_value(env_name), f"{config_path}:provider.{name}")
        if self.spec.key == "claude-code":
            return self._infer_claude_upstream(before, config_path)
        if self.spec.config_format == "toml" or config_path.suffix.lower() == ".toml":
            return self._infer_toml_upstream(before, config_path)
        return self._infer_json_upstream(before, config_path)

    def backup_config(self, config_path: Path) -> Path:
        timestamp = now_iso().replace(":", "").replace(".", "")
        backup_root = backups_dir() / self.spec.key / timestamp
        backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        original = backup_root / "original_config"
        before = self.read_config(config_path)
        if config_path.exists():
            atomic_write_text(original, before)
        metadata = {
            "agent": self.spec.key,
            "config_path": str(config_path),
            "original_config": str(original),
            "original_exists": config_path.exists(),
            "proxy_url": self.proxy_url,
            "proxy_env_key": self.proxy_env_key,
            "created_at": now_iso(),
        }
        write_json_file(backup_root / "backup.json", metadata)
        atomic_write_text(backup_root / "before.txt", before)
        return backup_root

    def patch_config(self, config_path: Path, backup_root: Path) -> None:
        before = self.read_config(config_path)
        after_file = backup_root / "after.txt"
        if after_file.exists() and before != after_file.read_text(encoding="utf-8"):
            if self.verify_patch(config_path):
                # Still routed correctly. Preserve the original patch baseline
                # so subsequent restore retains the user's newer settings.
                return
            raise ValueError(
                f"Agent settings changed. Run `qise restore {self.spec.key}` first "
                "(new user settings are preserved), then enable protection again."
            )
        config_path.parent.mkdir(parents=True, exist_ok=True)
        if self.spec.config_format == "toml" or config_path.suffix.lower() == ".toml":
            after = self._patch_toml(before)
        else:
            after = self._patch_json(before)
        atomic_write_text(backup_root / "after.txt", after)
        diff = "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="before",
            tofile="after",
        ))
        atomic_write_text(backup_root / "patch.diff", diff)
        atomic_write_text(config_path, after)

    def verify_patch(self, config_path: Path) -> bool:
        if not config_path.exists():
            return False
        try:
            text = config_path.read_text(encoding="utf-8")
            if self.spec.config_format == "toml" or config_path.suffix.lower() == ".toml":
                data = tomllib.loads(text)
                provider = data.get("model_providers", {}).get(data.get("model_provider"), {})
                return provider.get("base_url") == self.proxy_url
            data = _read_agent_json(text)
            if self.spec.key == "claude-code":
                return data.get("env", {}).get("ANTHROPIC_BASE_URL") == self.proxy_url
            if self.spec.key == "opencode":
                name = str(data.get("model", "")).split("/", 1)[0]
                return data.get("provider", {}).get(name, {}).get("options", {}).get("baseURL") == self.proxy_url
            urls = self._json_url_locations(data)
            return bool(urls) and all(parent[key] == self.proxy_url for parent, key in urls)
        except (ValueError, TypeError, AttributeError):
            return False

    def restore_config(self, backup_root: Path) -> None:
        metadata = json.loads((backup_root / "backup.json").read_text())
        config_path = Path(metadata["config_path"])
        original_exists = bool(metadata.get("original_exists"))
        original = Path(metadata["original_config"])
        after_file = backup_root / "after.txt"
        current = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        after = after_file.read_text(encoding="utf-8") if after_file.exists() else None
        if after is not None and current != after:
            original_text = original.read_text(encoding="utf-8") if original_exists else ""
            if config_path.suffix.lower() == ".toml":
                current_data = tomllib.loads(current)
                after_data = tomllib.loads(after)
                before_data = tomllib.loads(original_text)
                current_provider = current_data.get("model_providers", {}).get(QISE_PROXY_PROVIDER)
                after_provider = after_data.get("model_providers", {}).get(QISE_PROXY_PROVIDER)
                if current_provider is not None and current_provider != after_provider:
                    raise ValueError("Qise provider settings were edited. Your config was kept; review the backup before restoring.")
                restored = re.sub(
                    rf"(?ms){re.escape(QISE_MARKER_START)}.*?{re.escape(QISE_MARKER_END)}\n?", "", current,
                )
                if current_data.get("model_provider") == QISE_PROXY_PROVIDER:
                    previous = before_data.get("model_provider")
                    replacement = f"model_provider = {json.dumps(previous)}" if previous is not None else ""
                    restored = re.sub(r'(?m)^[ \t]*model_provider\s*=.*$', replacement, restored, count=1)
                tomllib.loads(restored)
            else:
                restored_data = _undo_json_patch(
                    _read_agent_json(original_text) if original_text.strip() else {},
                    _read_agent_json(after),
                    _read_agent_json(current) if current.strip() else {},
                )
                restored = json.dumps(restored_data, indent=2, sort_keys=True) + "\n"
            atomic_write_text(config_path, restored)
            return
        if original_exists:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(config_path, original.read_text(encoding="utf-8"))
        elif config_path.exists():
            config_path.unlink()

    def _infer_toml_upstream(self, before: str, config_path: Path) -> UpstreamInfo:
        cleaned = re.sub(
            rf"(?ms){re.escape(QISE_MARKER_START)}.*?{re.escape(QISE_MARKER_END)}\n?",
            "",
            before,
        )
        try:
            data = tomllib.loads(cleaned)
        except tomllib.TOMLDecodeError:
            return UpstreamInfo()
        if not isinstance(data, dict):
            return UpstreamInfo()

        providers = data.get("model_providers", {})
        if not isinstance(providers, dict):
            providers = {}
        active = str(data.get("model_provider", ""))
        if active == QISE_PROXY_PROVIDER:
            return UpstreamInfo()

        provider_items: list[tuple[str, Any]] = []
        if active and active != QISE_PROXY_PROVIDER and active in providers:
            provider_items.append((active, providers[active]))
        elif not active and len(providers) == 1:
            provider_items.extend(providers.items())

        for name, provider in provider_items:
            if not isinstance(provider, dict):
                continue
            base_url = str(provider.get("base_url") or provider.get("api_base") or "").rstrip("/")
            if not base_url or _is_local_proxy_url(base_url, self.proxy_port):
                continue
            env_key = str(provider.get("env_key") or provider.get("api_key_env") or "OPENAI_API_KEY")
            return UpstreamInfo(
                base_url=base_url,
                api_key_env=env_key,
                api_key=_env_value(env_key),
                source=f"{config_path}:{name}",
            )

        base_url = str(data.get("base_url") or data.get("api_base") or "").rstrip("/")
        if base_url and not _is_local_proxy_url(base_url, self.proxy_port):
            env_key = str(data.get("env_key") or data.get("api_key_env") or "OPENAI_API_KEY")
            return UpstreamInfo(
                base_url=base_url,
                api_key_env=env_key,
                api_key=_env_value(env_key),
                source=str(config_path),
            )
        return UpstreamInfo()

    def _infer_json_upstream(self, before: str, config_path: Path) -> UpstreamInfo:
        try:
            data = json.loads(before)
        except json.JSONDecodeError:
            return UpstreamInfo()
        if not isinstance(data, dict):
            raise ValueError("Agent configuration must be an object")
        locations = self._json_url_locations(data)
        if len(locations) != 1:
            return UpstreamInfo()
        parent, url_key = locations[0]
        base_url, env_key = self._find_json_upstream(parent)
        base_url = parent[url_key]
        if base_url and not _is_local_proxy_url(base_url, self.proxy_port):
            key_name = env_key or "OPENAI_API_KEY"
            return UpstreamInfo(
                base_url=base_url.rstrip("/"),
                api_key_env=key_name,
                api_key=_env_value(key_name),
                source=str(config_path),
            )
        return UpstreamInfo()

    def _infer_claude_upstream(self, before: str, config_path: Path) -> UpstreamInfo:
        try:
            data = json.loads(before)
        except json.JSONDecodeError:
            return UpstreamInfo()
        if not isinstance(data, dict):
            return UpstreamInfo()

        env = data.get("env", {})
        base_url = ""
        if isinstance(env, dict):
            base_url = str(env.get("ANTHROPIC_BASE_URL") or env.get("CLAUDE_CODE_PROXY_URL") or "").rstrip("/")
        if not base_url:
            base_url, _ = self._find_json_upstream(data)

        if base_url and not _is_local_proxy_url(base_url, self.proxy_port):
            env_key = next((name for name in _agent_api_key_env_candidates(self.spec.key) if os.environ.get(name)), "")
            return UpstreamInfo(
                base_url=base_url,
                api_key_env=env_key or _default_api_key_env_for_agent(self.spec.key),
                api_key=_env_value(env_key),
                source=str(config_path),
            )
        return UpstreamInfo()

    def _find_json_upstream(self, value: Any) -> tuple[str, str]:
        if isinstance(value, dict):
            base_url = ""
            env_key = ""
            for key, child in value.items():
                normalized = key.replace("_", "").lower()
                if normalized in _JSON_BASE_URL_KEYS or key in _JSON_BASE_URL_KEYS:
                    if isinstance(child, str):
                        base_url = child
                elif (normalized in _JSON_ENV_KEY_KEYS or key in _JSON_ENV_KEY_KEYS) and isinstance(child, str):
                    env_key = child
            if base_url:
                return base_url, env_key
            for child in value.values():
                found_url, found_env = self._find_json_upstream(child)
                if found_url:
                    return found_url, found_env
        elif isinstance(value, list):
            for child in value:
                found_url, found_env = self._find_json_upstream(child)
                if found_url:
                    return found_url, found_env
        return "", ""

    def _patch_toml(self, before: str) -> str:
        parsed_before = tomllib.loads(before)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.proxy_env_key):
            raise ValueError("Provider API key environment variable name is invalid")
        without_old = re.sub(
            rf"(?ms){re.escape(QISE_MARKER_START)}.*?{re.escape(QISE_MARKER_END)}\n?",
            "",
            before,
        ).strip()
        providers = parsed_before.get("model_providers", {})
        active_provider = providers.get(parsed_before.get("model_provider", ""), {})
        wire_api = active_provider.get("wire_api", "responses")
        if wire_api not in {"chat", "responses"}:
            raise ValueError(f"Unsupported provider wire_api: {wire_api}")
        provider_block = (
            f"{QISE_MARKER_START}: {self.spec.key}\n"
            f"[model_providers.{QISE_PROXY_PROVIDER}]\n"
            "name = \"Qise Proxy\"\n"
            f"base_url = \"{self.proxy_url}\"\n"
            f"env_key = \"{self.proxy_env_key}\"\n"
            f"wire_api = \"{wire_api}\"\n"
            f"{QISE_MARKER_END}"
        )
        # Only alter a root key. A marker comment does not end a TOML table.
        first_table = re.search(r"(?m)^\s*\[", without_old)
        root_end = first_table.start() if first_table else len(without_old)
        root = without_old[:root_end]
        tail = without_old[root_end:]
        if re.search(r"(?m)^\s*model_provider\s*=", root):
            root = re.sub(
                r"(?m)^\s*model_provider\s*=.*$",
                f'model_provider = "{QISE_PROXY_PROVIDER}"',
                root,
                count=1,
            )
        else:
            root = f'model_provider = "{QISE_PROXY_PROVIDER}"\n' + root
        after = root.rstrip() + "\n\n" + tail.rstrip() + "\n\n" + provider_block + "\n"
        parsed_after = tomllib.loads(after)
        for key, value in parsed_before.items():
            if key not in {"model_provider", "model_providers"} and parsed_after.get(key) != value:
                raise ValueError(f"Refusing to change unrelated TOML setting: {key}")
        return after

    def _patch_json(self, before: str) -> str:
        if before.strip():
            try:
                data = _read_agent_json(before) if self.spec.key == "opencode" else json.loads(before)
            except json.JSONDecodeError as exc:
                raise ValueError("Agent config is not valid JSON; no configuration was replaced") from exc
        else:
            data = {}
        if not isinstance(data, dict):
            raise ValueError("Agent configuration must be a JSON object")
        if self.spec.key == "opencode":
            return self._patch_opencode(data)
        if self.spec.key == "claude-code":
            return self._patch_claude_json_data(data)
        urls = self._json_url_locations(data)
        if len(urls) != 1:
            raise ValueError("Cannot identify a single active model endpoint. Configure a selected provider or use manual connection.")
        parent, key = urls[0]
        parent[key] = self.proxy_url
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    def _patch_claude_json_data(self, data: dict[str, Any]) -> str:
        env = data.get("env")
        if not isinstance(env, dict):
            env = {}
            data["env"] = env
        env["ANTHROPIC_BASE_URL"] = self.proxy_url
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    def _patch_opencode(self, data: dict[str, Any]) -> str:
        model = str(data.get("model") or "")
        provider_name = model.split("/", 1)[0] if "/" in model else ""
        providers = data.get("provider", {})
        if not provider_name or not isinstance(providers, dict):
            raise ValueError("Select a model in OpenCode first so Qise can protect the correct provider.")
        provider = providers.setdefault(provider_name, {})
        if not isinstance(provider, dict):
            raise ValueError("OpenCode provider configuration must be an object")
        npm = str(provider.get("npm", ""))
        supported = {"@ai-sdk/openai", "@ai-sdk/openai-compatible", "@ai-sdk/anthropic"}
        if npm not in supported and not (not npm and provider_name in {"openai", "anthropic"}):
            raise ValueError("This OpenCode provider does not use a supported OpenAI or Anthropic protocol.")
        options = provider.setdefault("options", {})
        if not isinstance(options, dict):
            raise ValueError("OpenCode provider options must be an object")
        options["baseURL"] = self.proxy_url
        data["provider"] = providers
        return json.dumps(data, indent=2, sort_keys=True) + "\n"

    def _json_url_locations(self, data: dict[str, Any]) -> list[tuple[dict[str, Any], str]]:
        """Locate the selected provider; never redirect unrelated network settings."""
        if self.spec.key == "openclaw" and isinstance(data.get("models"), dict):
            providers = data["models"].get("providers")
            if isinstance(providers, dict):
                model = data.get("agents", {}).get("defaults", {}).get("model", {})
                model = model.get("primary", "") if isinstance(model, dict) else model
                name = str(model).split("/", 1)[0]
                provider = providers.get(name)
                if not isinstance(provider, dict):
                    raise ValueError("Select an OpenClaw model with a configured provider before enabling protection.")
                if provider.get("api", "openai-completions") not in {"openai-completions", "openai-responses", "anthropic-messages"}:
                    raise ValueError("The selected OpenClaw provider does not use a supported HTTP model protocol.")
                data = provider
        found: list[tuple[dict[str, Any], str]] = []

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if (key.replace("_", "").lower() in _JSON_BASE_URL_KEYS or key in _JSON_BASE_URL_KEYS) and isinstance(child, str):
                        found.append((value, key))
                    elif isinstance(child, (dict, list)):
                        visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(data)
        return found


def protect_agent(
    agent: str,
    *,
    base_url: str = "",
    experimental: bool = False,
    config_path: str | None = None,
) -> tuple[int, str]:
    key = normalize_agent_key(agent)
    config, loaded_config_path = _load_config(config_path)
    proxy_port = config.integration.proxy.port
    configured_upstream = _configured_upstream(
        config,
        override_url=base_url,
        proxy_port=proxy_port,
        agent_key=key,
    )

    if key == "custom":
        if not configured_upstream.base_url:
            return 2, "custom protection requires --base-url or configured proxy upstream."
        start_managed_services(
            config_path=loaded_config_path,
            proxy_port=proxy_port,
            bridge_port=config.integration.bridge_port,
            upstream_url=configured_upstream.base_url,
            upstream_api_key=configured_upstream.api_key,
        )
        state = load_state()
        protected = state.setdefault("protected_agents", {})
        protected["custom"] = {
            "mode": "manual",
            "proxy_url": f"http://127.0.0.1:{proxy_port}/agent/custom/v1",
            "upstream_url": configured_upstream.base_url,
            "upstream_source": configured_upstream.source,
            "protected_at": now_iso(),
            "backup_path": "",
        }
        save_state(state)
        return 0, (
            "Qise proxy is ready for manual connection. Set your Agent base URL to "
            f"http://127.0.0.1:{proxy_port}/agent/custom/v1 to enable inspection."
        )

    spec = AGENTS.get(key)
    if spec is None:
        return 2, f"Unknown agent '{agent}'. Supported: {', '.join(AGENTS)}, custom."
    if not spec.auto_protect:
        return 2, (
            f"{spec.display_name} supports scanning and manual connection. "
            "Use `qise protect custom --base-url <model API URL>`, then set the local Qise URL "
            "in its custom model settings. Built-in model traffic is not automatically protected."
        )
    if spec.experimental and not experimental:
        return 2, (
            f"{spec.display_name} support is experimental. Re-run with --experimental to acknowledge "
            "that this integration has not completed the full verification matrix yet."
        )

    manager = AgentConfigManager(spec, proxy_port=proxy_port)
    detected = manager.detect()
    config_file = manager.locate_config(create=bool(detected.get("installed")))
    if config_file is None:
        return 2, f"{spec.display_name} was not detected. Install it first or create its config file."

    try:
        inferred_upstream = manager.infer_upstream(config_file)
    except (ValueError, AttributeError, TypeError) as exc:
        return 2, f"Could not read {spec.display_name} configuration: {exc}. No changes made."
    state_upstream = _state_upstream(key, proxy_port=proxy_port)
    upstream = _merge_upstream(configured_upstream, _merge_upstream(inferred_upstream, state_upstream))
    if not upstream.base_url:
        return 2, (
            "Proxy upstream is not configured and Qise could not infer it from the Agent config. "
            f"Run `qise protect {key} --base-url <your model API base URL>` or set "
            "integration.proxy.upstream_url / QISE_PROXY_UPSTREAM_URL."
        )

    proxy_env_key = (
        upstream.api_key_env
        or inferred_upstream.api_key_env
        or state_upstream.api_key_env
        or _default_api_key_env_for_agent(key)
    )
    manager = AgentConfigManager(spec, proxy_port=proxy_port, proxy_env_key=proxy_env_key)

    state = load_state()
    protected = state.setdefault("protected_agents", {})
    existing_record = protected.get(key, {}) if isinstance(protected, dict) else {}
    existing_backup_raw = str(existing_record.get("backup_path", "")) if isinstance(existing_record, dict) else ""
    existing_backup = Path(existing_backup_raw) if existing_backup_raw else None
    if existing_backup is not None and (existing_backup / "backup.json").exists():
        backup_root = existing_backup
    else:
        backup_root = manager.backup_config(config_file)

    before_attempt = manager.read_config(config_file)
    existed_before = config_file.exists()
    prior_after = (backup_root / "after.txt").read_text(encoding="utf-8") if (backup_root / "after.txt").exists() else None
    patched = False
    try:
        manager.patch_config(config_file, backup_root)
        patched = True
        if not manager.verify_patch(config_file):
            raise RuntimeError(f"Patch verification failed for {config_file}")
        start_managed_services(
            config_path=loaded_config_path,
            proxy_port=proxy_port,
            bridge_port=config.integration.bridge_port,
            upstream_url=upstream.base_url,
            upstream_api_key=upstream.api_key,
        )
    except Exception:
        if patched:
            if existed_before:
                atomic_write_text(config_file, before_attempt)
            elif config_file.exists():
                config_file.unlink()
        if prior_after is not None:
            atomic_write_text(backup_root / "after.txt", prior_after)
        raise

    state = load_state()
    protected = state.setdefault("protected_agents", {})
    protected[key] = {
        "agent": key,
        "display_name": spec.display_name,
        "config_path": str(config_file),
        "backup_path": str(backup_root),
        "proxy_url": manager.proxy_url,
        "proxy_env_key": proxy_env_key,
        "upstream_url": upstream.base_url,
        "upstream_source": upstream.source,
        "protected_at": now_iso(),
        "phase": "phase2-config-patch",
    }
    save_state(state)
    source_note = f" ({upstream.source})" if upstream.source else ""
    return 0, (
        f"{spec.display_name} is protected by Qise.\n"
        f"Config: {config_file}\n"
        f"Backup: {backup_root}\n"
        f"Agent base URL: {manager.proxy_url}\n"
        f"Upstream: {upstream.base_url}{source_note}\n"
        f"Provider API key env used by Agent: {proxy_env_key}\n"
        f"Run `qise restore {key}` to restore the original config."
    )


def restore_agent(agent: str) -> tuple[int, str]:
    key = normalize_agent_key(agent)
    state = load_state()
    protected = state.setdefault("protected_agents", {})
    if key == "all":
        if not protected:
            return 0, "No protected agents recorded."
        messages = []
        for item in list(protected):
            code, message = restore_agent(item)
            if code != 0:
                return code, message
            messages.append(message)
        return 0, "\n".join(messages)
    if key not in protected:
        return 0, f"No active Qise protection record found for {agent}."
    record = protected[key]
    backup_path = record.get("backup_path")
    spec = AGENTS.get(key)
    if spec and backup_path:
        AgentConfigManager(spec).restore_config(Path(backup_path))
    protected.pop(key, None)
    save_state(state)
    return 0, f"Restored protection record for {agent}. Backup kept at: {backup_path or '(none recorded)'}"
