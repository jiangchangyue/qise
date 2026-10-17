"""Product status rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qise.core.config import ShieldConfig
from qise.product.agents import detect_agents
from qise.product.events import count_recent_events, load_events
from qise.product.service import (
    check_port,
    events_path,
    inspect_services,
    load_state,
    qise_home,
    services_are_active,
    state_path,
)
from qise.product.slm import slm_status


def load_config(config_path: str | None = None) -> tuple[ShieldConfig, str]:
    if config_path:
        return ShieldConfig.from_yaml(config_path), str(Path(config_path))
    for default in (qise_home() / "shield.yaml", Path("shield.yaml")):
        if default.exists():
            return ShieldConfig.from_yaml(default), str(default)
    return ShieldConfig.default(), "(defaults)"


def get_status(config_path: str | None = None) -> dict[str, Any]:
    config, config_label = load_config(config_path)
    state = load_state()
    services = inspect_services(state)
    proxy_port = config.integration.proxy.port
    bridge_port = config.integration.bridge_port
    blocks, warnings = count_recent_events()
    events = load_events(limit=1)
    services_running = services_are_active(services)
    agents = detect_agents(services_active=services_running)

    return {
        "config": config_label,
        "state_path": str(state_path()),
        "events_path": str(events_path()),
        "services": services,
        "proxy": check_port("127.0.0.1", proxy_port).__dict__,
        "bridge": check_port("127.0.0.1", bridge_port).__dict__,
        "slm": slm_status(config_path=config_path),
        "protected_agents": state.get("protected_agents", {}),
        "services_running": services_running,
        "protection_enabled": any(agent["protected"] for agent in agents),
        "detected_agents": agents,
        "events_24h": {
            "blocked": blocks,
            "warnings": warnings,
        },
        "last_event": events[-1] if events else None,
    }


def render_status(status: dict[str, Any], *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(status, indent=2, sort_keys=True)

    protected = status["protected_agents"]
    last_event = status["last_event"]
    services = status.get("services", {})
    proxy_service = services.get("proxy", {}) if isinstance(services, dict) else {}
    bridge_service = services.get("bridge", {}) if isinstance(services, dict) else {}
    proxy_state = proxy_service.get("status") or status["proxy"]["status"]
    bridge_state = bridge_service.get("status") or status["bridge"]["status"]
    if status["proxy"]["status"] == "in_use" and proxy_state == "in_use":
        proxy_state = "listening"
    if status["bridge"]["status"] == "in_use" and bridge_state == "in_use":
        bridge_state = "listening"
    qise_running = bool(status.get("services_running", status.get("protection_enabled")))
    slm = status.get("slm", {})
    slm_ready = slm.get("verification") == "ready"
    lines = [
        "Qise Status",
        "",
        f"Config: {status['config']}",
        f"State: {status['state_path']}",
        f"Events: {status['events_path']}",
        "",
        "Services",
        f"  Qise running: {'yes' if qise_running else 'no'}",
        f"  Proxy  127.0.0.1:{status['proxy']['port']}: {proxy_state}",
        f"  Bridge 127.0.0.1:{status['bridge']['port']}: {bridge_state}",
        "",
        "SLM",
        f"  Configured: {'yes' if slm.get('configured') else 'no'}",
        f"  Provider: {slm.get('provider', 'none')}",
        f"  Model: {slm.get('model') or '(none)'}",
        f"  Endpoint: {slm.get('base_url') or '(none)'}",
        f"  Ready: {'yes' if slm_ready else 'no'} ({slm.get('verification', 'unknown')})",
        "",
        "Protection",
        f"  Protected agents: {', '.join(agent['name'] for agent in status['detected_agents'] if agent['protected']) or 'none'}",
        f"  Configured agents: {', '.join(sorted(protected)) if protected else 'none'}",
    ]
    for name, record in sorted(protected.items()):
        if isinstance(record, dict):
            lines.append(f"  - {name}: {record.get('config_path', '(manual)')}")
            if record.get("backup_path"):
                lines.append(f"    backup: {record['backup_path']}")
    lines.extend(["", "Agents"])
    if status["detected_agents"]:
        for agent in status["detected_agents"]:
            install = "installed" if agent["installed"] else "not found"
            protected_text = "protected" if agent["protected"] else "configured, needs attention" if agent.get("configured") else "not protected"
            suffix = " (experimental)" if agent["experimental"] else ""
            lines.append(f"  {agent['name']}: {install}, {protected_text}{suffix}")
    else:
        lines.append("  none detected")

    lines.extend([
        "",
        "Events (last 24h)",
        f"  Blocked: {status['events_24h']['blocked']}",
        f"  Warnings: {status['events_24h']['warnings']}",
        f"  Last event: {last_event.get('id') if last_event else 'none'}",
    ])
    return "\n".join(lines)
