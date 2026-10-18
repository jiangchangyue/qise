"""Regression coverage for protection settings, takeover and private state."""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from qise.bridge.server import BridgeServer
from qise.core.config import ShieldConfig
from qise.core.models import GuardContext
from qise.core.shield import Shield
from qise.product import service
from qise.product.agents import AGENTS, AgentConfigManager, detect_agents, protect_agent
from qise.product.events import append_event, count_recent_events, guard_event_from_results, load_events, make_event
from qise.product.policy import guard_rows, policy_path, refresh_guard_policy, set_guard_mode
from qise.proxy.config import ProxyConfig
from qise.proxy.interceptor import ProxyInterceptor
from qise.proxy.parser import ResponseParser


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path / "qise"))
    monkeypatch.setenv("QISE_AGENT_HOME", str(tmp_path / "agents"))
    monkeypatch.delenv("QISE_MODE", raising=False)


def command_shield() -> Shield:
    return Shield(ShieldConfig(guards={"enabled": ["command"]}))


class Request:
    def __init__(self, payload):
        self.payload = payload
        self.headers = {"Content-Type": "application/json"}
        self.content_type = "application/json"

    async def json(self):
        return self.payload


@pytest.mark.asyncio
async def test_bridge_mode_change_controls_separate_proxy_and_survives_restart():
    bridge = BridgeServer(command_shield())
    proxy_shield = command_shield()
    interceptor = ProxyInterceptor(proxy_shield, ProxyConfig())
    body = {"choices": [{"message": {"tool_calls": [{
        "id": "call1", "type": "function", "function": {
            "name": "bash", "arguments": json.dumps({"command": "rm -rf /"}),
        },
    }]}}]}
    parsed = ResponseParser().parse(body)
    assert interceptor.intercept_response(parsed, body).action == "block"
    response = await bridge._handle_set_guard_mode(Request({"guard_name": "command", "mode": "off"}))
    assert response.status == 200
    assert interceptor.intercept_response(parsed, body).action == "pass"
    assert guard_rows(proxy_shield)[0]["mode"] == "off"
    restarted = command_shield()
    refresh_guard_policy(restarted)
    assert restarted.check_sync(GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})).should_block is False
    set_guard_mode("command", "enforce")
    assert interceptor.intercept_response(parsed, body).action == "block"


def test_invalid_policy_retains_last_good_enforcement():
    shield = command_shield()
    set_guard_mode("command", "enforce")
    refresh_guard_policy(shield)
    policy_path().write_text('{"schema_version":1,"modes":{"command":"bogus"}}')
    refresh_guard_policy(shield)
    assert shield.config.guard_mode("command") == "enforce"
    with pytest.raises(ValueError):
        set_guard_mode("command", "off")


def test_service_key_is_environment_only_and_not_saved(tmp_path):
    seen = {}

    def spawn(name, cmd, port, env):
        seen[name] = (cmd, env)
        return {"pid": 101, "port": port, "status": "running", "command": " ".join(cmd)}

    key = "analysis-placeholder-secret"
    with patch.object(service, "_spawn_service", side_effect=spawn):
        service.start_managed_services(config_path=None, proxy_port=8822, upstream_url="https://example.invalid", upstream_api_key=key)
    assert key not in service.state_path().read_text()
    assert key not in " ".join(seen["proxy"][0])
    assert seen["proxy"][1]["QISE_PROXY_UPSTREAM_API_KEY"] == key
    assert seen["bridge"][1].get("QISE_PROXY_UPSTREAM_API_KEY") != key


def test_legacy_service_command_secrets_are_redacted_on_read_and_write():
    service.write_json_file(service.state_path(), {
        "services": {"proxy": {"command": "qise proxy start --upstream-key old-private-secret"}},
    })
    state = service.load_state()
    assert "old-private-secret" not in json.dumps(state)
    service.save_state(state)
    assert "old-private-secret" not in service.state_path().read_text()


def test_occupied_unrelated_port_is_not_reused():
    with (
        patch.object(service, "check_port", return_value=service.PortCheck("127.0.0.1", 8822, "in_use")),
        patch.object(service, "service_health", return_value=None),
        pytest.raises(RuntimeError, match="another application"),
    ):
        service._spawn_service("proxy", ["qise", "proxy", "start"], 8822, {})


def test_existing_service_reuse_keeps_managed_ownership():
    record = {"pid": 100, "port": 8822, "status": "running", "managed_by": "qise", "instance_id": "instance-one"}
    service.save_state({"services": {"proxy": record}})
    with (
        patch.object(service, "check_port", return_value=service.PortCheck("127.0.0.1", 8822, "in_use")),
        patch.object(service, "service_health", return_value={"pid": 100, "instance_id": "instance-one"}),
    ):
        assert service._spawn_service("proxy", ["qise"], 8822, {}) == record


def test_configured_agent_with_dead_services_needs_attention(tmp_path):
    path = tmp_path / "agents" / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    url = "http://127.0.0.1:8822/agent/claude-code/v1"
    path.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": url}}))
    service.save_state({"protected_agents": {"claude-code": {"proxy_url": url}}})
    row = next(item for item in detect_agents(services_active=False) if item["key"] == "claude-code")
    assert row["configured"] is True
    assert row["protected"] is False
    assert row["protection_status"] == "needs_attention"


def test_codex_takeover_preserves_root_settings_and_protocol():
    original = 'model = "local-model"\napproval_policy = "on-request"\n[projects."/tmp/work"]\ntrust_level = "trusted"\n'
    manager = AgentConfigManager(AGENTS["codex"])
    patched = tomllib.loads(manager._patch_toml(original))
    assert patched["model"] == "local-model"
    assert patched["approval_policy"] == "on-request"
    assert patched["projects"] == tomllib.loads(original)["projects"]
    assert patched["model_providers"]["qise-proxy"]["wire_api"] == "responses"
    chat = 'model_provider = "legacy"\n[model_providers.legacy]\nwire_api = "chat"\n'
    assert tomllib.loads(manager._patch_toml(chat))["model_providers"]["qise-proxy"]["wire_api"] == "chat"


def test_invalid_json_is_not_replaced(tmp_path):
    manager = AgentConfigManager(AGENTS["claude-code"])
    config = tmp_path / "settings.json"
    config.write_text('{"broken":')
    backup = manager.backup_config(config)
    with pytest.raises(ValueError):
        manager.patch_config(config, backup)
    assert config.read_text() == '{"broken":'


@pytest.mark.parametrize("original", [{"theme": "light"}, {"env": {"EXISTING": "value"}, "theme": "light"}])
def test_restore_preserves_new_user_settings_and_removes_only_proxy(tmp_path, original):
    manager = AgentConfigManager(AGENTS["claude-code"])
    config = tmp_path / "settings.json"
    config.write_text(json.dumps(original))
    backup = manager.backup_config(config)
    manager.patch_config(config, backup)
    current = json.loads(config.read_text())
    current["theme"] = "dark"
    current["env"]["USER_ADDED"] = "keep"
    config.write_text(json.dumps(current))
    manager.restore_config(backup)
    restored = json.loads(config.read_text())
    assert restored["theme"] == "dark"
    assert restored["env"]["USER_ADDED"] == "keep"
    assert "ANTHROPIC_BASE_URL" not in restored["env"]


def test_restore_toml_preserves_user_edit(tmp_path):
    manager = AgentConfigManager(AGENTS["codex"])
    config = tmp_path / "config.toml"
    config.write_text('model = "first"\napproval_policy = "on-request"\n')
    backup = manager.backup_config(config)
    manager.patch_config(config, backup)
    config.write_text(config.read_text().replace('"first"', '"second"'))
    manager.restore_config(backup)
    restored = tomllib.loads(config.read_text())
    assert restored["model"] == "second"
    assert restored["approval_policy"] == "on-request"
    assert "model_provider" not in restored
    assert "qise-proxy" not in restored.get("model_providers", {})


def test_opencode_changes_selected_provider_only_and_accepts_jsonc():
    original = '''{
      // User-selected model
      "model": "team/model-a",
      "provider": {
        "team": {"npm": "@ai-sdk/openai-compatible", "options": {"baseURL": "https://example.test/v1"}},
        "other": {"options": {"baseURL": "https://other.test/v1"}},
      },
    }'''
    manager = AgentConfigManager(AGENTS["opencode"])
    patched = json.loads(manager._patch_json(original))
    assert patched["provider"]["team"]["options"]["baseURL"] == manager.proxy_url
    assert patched["provider"]["other"]["options"]["baseURL"] == "https://other.test/v1"


def test_workbuddy_does_not_claim_automatic_takeover():
    code, message = protect_agent("workbuddy")
    assert code != 0
    assert "manual connection" in message
    assert not service.state_path().exists()


def test_event_evidence_redacts_keys_before_persistence():
    secret = "sk-test-abcdefghijklmnopqrstuvwxyz"
    event = make_event(stage="egress", source="test", verdict="block", category="exfil", severity="high",
                       confidence=1.0, action_type="tool_call", resource={"api_key": "custom-private-value"},
                       evidence=[{"message": f"Detected {secret}"}])
    path = append_event(event)
    data = path.read_text()
    assert secret not in data
    assert "custom-private-value" not in data
    assert "REDACTED" in data
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_state_write_is_private_and_leaves_no_partial_files(tmp_path):
    path = tmp_path / "state.json"
    service.write_json_file(path, {"revision": 1})
    service.write_json_file(path, {"revision": 2})
    assert json.loads(path.read_text()) == {"revision": 2}
    assert list(tmp_path.glob(".state.json.*")) == []
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_config_refresh_cannot_erase_saved_enforcement():
    shield = command_shield()
    set_guard_mode("command", "enforce")
    refresh_guard_policy(shield)
    shield.reconfigure(ShieldConfig(guards={"enabled": ["command"], "config": {"command": {"mode": "off"}}}))
    refresh_guard_policy(shield)
    assert shield.check_sync(GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})).should_block


def test_codex_status_uses_selected_provider_not_text_presence(tmp_path):
    manager = AgentConfigManager(AGENTS["codex"])
    config = tmp_path / "config.toml"
    config.write_text(f'model_provider = "original"\n# {manager.proxy_url}\n[model_providers.qise-proxy]\nbase_url = "{manager.proxy_url}"\n')
    assert manager.verify_patch(config) is False


def test_opencode_status_follows_model_selection(tmp_path):
    manager = AgentConfigManager(AGENTS["opencode"])
    config = tmp_path / "opencode.json"
    config.write_text(json.dumps({"model": "other/model", "provider": {
        "protected": {"options": {"baseURL": manager.proxy_url}},
        "other": {"options": {"baseURL": "https://other.invalid/v1"}},
    }}))
    assert manager.verify_patch(config) is False


def test_openclaw_selected_endpoint_preserves_other_providers(tmp_path):
    manager = AgentConfigManager(AGENTS["openclaw"])
    config = tmp_path / "openclaw.json"
    data = {"agents": {"defaults": {"model": {"primary": "selected/model"}}}, "models": {"providers": {
        "other": {"baseUrl": "https://other.invalid/v1"},
        "selected": {"api": "openai-responses", "baseUrl": "https://selected.invalid/v1"},
    }}}
    config.write_text(json.dumps(data))
    assert manager.infer_upstream(config).base_url == "https://selected.invalid/v1"
    patched = manager._patch_json(config.read_text())
    config.write_text(patched)
    assert json.loads(patched)["models"]["providers"]["other"] == data["models"]["providers"]["other"]
    assert manager.verify_patch(config)


def test_codex_inference_does_not_use_inactive_provider(tmp_path):
    manager = AgentConfigManager(AGENTS["codex"])
    config = tmp_path / "config.toml"
    config.write_text('model_provider = "active"\n[model_providers.other]\nbase_url = "https://wrong.invalid/v1"\n[model_providers.active]\nname = "Active"\n')
    assert manager.infer_upstream(config).base_url == ""


@pytest.mark.parametrize("mode,expected", [("off", "pass"), ("observe", "warn"), ("enforce", "block")])
def test_cli_check_obeys_saved_policy(mode, expected, capsys, monkeypatch):
    from qise.cli import main

    set_guard_mode("command", mode)
    config = service.qise_home() / "shield.yaml"
    config.write_text('guards:\n  enabled: [command]\n')
    monkeypatch.setattr("sys.argv", ["qise", "check", "bash", '{"command":"rm -rf /"}'])
    with pytest.raises(SystemExit) as exit_info:
        main()
    result = json.loads(capsys.readouterr().out)
    assert result["verdict"] == expected
    assert exit_info.value.code == (1 if expected == "block" else 0)


def test_only_nonfinding_warnings_become_notices():
    common = dict(stage="ingress", source="proxy", verdict="warn", action_type="request")
    notices = [{"guard": "prompt", "verdict": "warn", "evidence_kind": "precaution"}]
    informational = guard_event_from_results(**common, guard_results=notices)
    assert informational["decision"]["verdict"] == "info"
    append_event(informational)
    assert count_recent_events() == (0, 0)
    assert load_events()[0]["evidence"][0]["verdict"] == "warn"
    mixed = guard_event_from_results(**common, guard_results=notices + [{"guard": "command", "verdict": "warn"}])
    assert mixed["decision"]["verdict"] == "warn"
    blocked = guard_event_from_results(**{**common, "verdict": "block"}, guard_results=notices)
    assert blocked["decision"]["verdict"] == "block"


def test_invalid_state_shape_does_not_crash_status_inspection():
    service.write_json_file(service.state_path(), {"services": [], "protected_agents": None})
    state = service.load_state()
    assert state["services"] == state["protected_agents"] == {}
