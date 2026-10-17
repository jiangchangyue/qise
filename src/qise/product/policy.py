"""Persistent guard modes shared by the desktop, CLI, bridge and proxy.

Policy changes take effect at the next check without restarting a model or
interrupting an Agent's connection. Standalone SDK Shields remain independent.
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from qise.core.config import GuardConfig, GuardsConfig
from qise.product.service import file_lock, now_iso, qise_home, write_json_file

logger = logging.getLogger(__name__)
VALID_MODES = frozenset({"observe", "enforce", "off"})
_refresh_lock = threading.RLock()


def policy_path() -> Path:
    return qise_home() / "guard-policy.json"


def load_guard_policy() -> dict[str, str]:
    path = policy_path()
    if not path.exists():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("Invalid Qise guard policy format")
    modes = raw.get("modes", {})
    names = set(GuardsConfig().enabled)
    if not isinstance(modes, dict) or any(
        name not in names or not isinstance(mode, str) or mode not in VALID_MODES for name, mode in modes.items()
    ):
        raise ValueError("Invalid guard name or mode in Qise guard policy")
    return modes


def set_guard_mode(name: str, mode: str) -> None:
    if name not in GuardsConfig().enabled:
        raise ValueError(f"Unknown guard: {name}")
    if not isinstance(mode, str) or mode not in VALID_MODES:
        raise ValueError("Guard mode must be observe, enforce, or off")
    with file_lock(policy_path().with_suffix(".lock")):
        modes = load_guard_policy()
        modes[name] = mode
        write_json_file(policy_path(), {
            "schema_version": 1,
            "updated_at": now_iso(),
            "modes": modes,
        })


def refresh_guard_policy(shield: Any) -> None:
    """Apply a validated, atomic configuration snapshot when policy changes.

    Keep the last good policy if a file is temporarily unreadable. An invalid
    update never clears active protections. The CLI surfaces write errors.
    """
    with _refresh_lock:
        _refresh_guard_policy(shield)


def _refresh_guard_policy(shield: Any) -> None:
    path = policy_path()
    config_changed = getattr(shield, "_qise_policy_config", None) is not shield.config
    try:
        stat = path.stat() if path.exists() else None
        # Atomic replacement can preserve size and fall within one filesystem
        # timestamp tick (notably enforce/observe). Include file identity.
        stamp = (str(path), stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size) if stat else (str(path), None)
        if not config_changed and getattr(shield, "_qise_policy_stamp", None) == stamp:
            return
        modes = load_guard_policy()
    except (OSError, ValueError, TypeError) as exc:
        logger.warning("Could not refresh guard policy; retaining active policy: %s", exc)
        return

    config = shield.config.model_copy(deep=True)
    baseline = getattr(shield, "_qise_policy_baseline", None)
    if baseline is None or config_changed:
        baseline = {name: config.guard_mode(name) for name in config.guards.enabled}
        shield._qise_policy_baseline = baseline
    for name in config.guards.enabled:
        current = config.guards.config.get(name, GuardConfig(mode=config.guard_mode(name)))
        config.guards.config[name] = current.model_copy(update={"mode": modes.get(name, baseline.get(name, current.mode))})
    shield.config = config
    shield._qise_policy_config = config
    shield._qise_policy_stamp = stamp


def guard_rows(shield: Any) -> list[dict[str, str]]:
    refresh_guard_policy(shield)
    rows: dict[str, dict[str, str]] = {}
    for kind in ("ingress", "egress", "output"):
        for guard in getattr(shield.pipeline, kind).guards:
            if guard.name in rows:
                rows[guard.name]["pipeline"] += f"/{kind}"
                continue
            rows[guard.name] = {
                "name": guard.name,
                "pipeline": kind,
                "primary_strategy": guard.primary_strategy,
                "mode": shield.config.guard_mode(guard.name),
            }
    return list(rows.values())
