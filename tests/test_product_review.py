"""Independent regressions for protection status and reversible takeover."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qise.product import service
from qise.product.agents import AGENTS, AgentConfigManager, detect_agents


@pytest.fixture(autouse=True)
def isolated_product_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("QISE_HOME", str(tmp_path / "qise"))
    monkeypatch.setenv("QISE_AGENT_HOME", str(tmp_path / "agents"))


@pytest.mark.parametrize("service_port,expected_protection", [(8822, True), (9900, False)])
def test_agent_protection_requires_the_service_at_its_configured_port(
    tmp_path: Path, service_port: int, expected_protection: bool,
):
    path = tmp_path / "agents" / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    proxy_url = "http://127.0.0.1:8822/agent/claude-code/v1"
    path.write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": proxy_url}}))
    service.save_state({
        "services": {
            "proxy": {"port": service_port, "status": "running"},
            "bridge": {"port": 8823, "status": "running"},
        },
        "protected_agents": {"claude-code": {"proxy_url": proxy_url}},
    })

    # get_status already verifies the current services before passing this flag.
    row = next(item for item in detect_agents(services_active=True) if item["key"] == "claude-code")
    assert row["protected"] is expected_protection


def test_codex_upstream_never_falls_back_to_an_inactive_provider(tmp_path: Path):
    path = tmp_path / "config.toml"
    path.write_text(
        'model_provider = "openai"\n'
        '[model_providers.inactive]\n'
        'base_url = "https://inactive-provider.invalid/v1"\n'
        'env_key = "INACTIVE_KEY"\n'
    )
    manager = AgentConfigManager(AGENTS["codex"])

    inferred = manager.infer_upstream(path)

    assert inferred.base_url != "https://inactive-provider.invalid/v1"


def test_repeated_takeover_preserves_settings_edited_between_attempts(tmp_path: Path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"theme": "light"}))
    manager = AgentConfigManager(AGENTS["claude-code"])
    backup = manager.backup_config(path)
    manager.patch_config(path, backup)
    edited = json.loads(path.read_text())
    edited["theme"] = "dark"
    path.write_text(json.dumps(edited))

    # protect_agent deliberately reuses the initial backup on repeated calls.
    manager.patch_config(path, backup)
    manager.restore_config(backup)

    restored = json.loads(path.read_text())
    assert restored["theme"] == "dark"
    assert "ANTHROPIC_BASE_URL" not in restored.get("env", {})
