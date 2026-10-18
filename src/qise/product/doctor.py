"""Product readiness diagnostics."""

from __future__ import annotations

import json
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from typing import Any

from qise import __version__
from qise.product.agents import detect_agents
from qise.product.service import DEFAULT_BRIDGE_PORT, check_port, ensure_qise_home, events_path
from qise.product.slm import slm_status as get_slm_status
from qise.product.status import load_config


def run_doctor(config_path: str | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []

    py_ok = sys.version_info >= (3, 11)
    if not py_ok:
        errors.append("Python 3.11+ is required.")
    checks.append({
        "name": "Python",
        "status": "ok" if py_ok else "error",
        "detail": ".".join(map(str, sys.version_info[:3])),
    })

    try:
        installed_version = package_version("qise")
    except PackageNotFoundError:
        installed_version = f"{__version__} (source checkout; not installed)"
        warnings.append("Qise is importable but not installed as a package. Run pip install -e \".[dev,proxy]\".")
    checks.append({"name": "Qise", "status": "ok", "detail": installed_version})

    try:
        config, config_label = load_config(config_path)
        checks.append({"name": "Config", "status": "ok", "detail": config_label})
    except Exception as exc:
        config = None
        config_label = config_path or "shield.yaml"
        errors.append(f"Could not load config {config_label}: {exc}")
        checks.append({"name": "Config", "status": "error", "detail": str(exc)})

    proxy_port = config.integration.proxy.port if config else 8822
    proxy = check_port("127.0.0.1", proxy_port)
    bridge = check_port("127.0.0.1", DEFAULT_BRIDGE_PORT)
    checks.append({"name": "Proxy port", "status": proxy.status, "detail": f"{proxy.host}:{proxy.port}"})
    checks.append({"name": "Bridge port", "status": bridge.status, "detail": f"{bridge.host}:{bridge.port}"})

    upstream = config.integration.proxy.upstream_url if config else ""
    if upstream:
        checks.append({"name": "Upstream", "status": "ok", "detail": upstream})
    else:
        warnings.append("Proxy upstream is not configured yet.")
        checks.append({"name": "Upstream", "status": "warning", "detail": "not configured"})

    try:
        ensure_qise_home()
        events_path().parent.mkdir(parents=True, exist_ok=True)
        with events_path().open("a", encoding="utf-8"):
            pass
        checks.append({"name": "Event log", "status": "ok", "detail": str(events_path())})
    except Exception as exc:
        errors.append(f"Event log is not writable: {exc}")
        checks.append({"name": "Event log", "status": "error", "detail": str(exc)})

    try:
        slm_report = get_slm_status(config_path=config_path)
        if slm_report["configured"]:
            slm_detail = f"{slm_report['model']} at {slm_report['base_url']}"
            if slm_report["verification"] == "ready":
                slm_check_status = "ok"
                slm_detail += " (ready)"
            else:
                slm_check_status = "warning"
                slm_detail += f" ({slm_report['verification']})"
                warnings.append("Local SLM is configured but not ready. Run `qise slm status` or `qise slm start`.")
        else:
            slm_detail = "not configured (optional; lightweight rules are available)"
            slm_check_status = "ok"
    except Exception as exc:
        slm_detail = f"status check failed: {exc}"
        slm_check_status = "warning"
        warnings.append(f"Could not check local SLM status: {exc}")
    checks.append({"name": "SLM", "status": slm_check_status, "detail": slm_detail})

    agents = detect_agents()
    if not agents:
        warnings.append("No supported Agent CLI/config was detected. Manual custom proxy mode is still available.")

    result = "ready"
    if errors:
        result = "error"
    elif warnings:
        result = "ready_with_warnings"

    return {
        "result": result,
        "checks": checks,
        "agents": agents,
        "warnings": warnings,
        "errors": errors,
    }


def render_doctor(report: dict[str, Any], *, json_output: bool = False) -> str:
    if json_output:
        return json.dumps(report, indent=2, sort_keys=True)
    lines = ["Qise Doctor", "", "Runtime"]
    for check in report["checks"]:
        if check["name"] in {"Python", "Qise"}:
            lines.append(f"  {check['name']}: {check['detail']} {check['status'].upper()}")
    lines.append("")
    lines.append("Services")
    for check in report["checks"]:
        if check["name"] in {"Proxy port", "Bridge port"}:
            lines.append(f"  {check['name']}: {check['detail']} {check['status']}")
    lines.append("")
    lines.append("Agents")
    if report["agents"]:
        for agent in report["agents"]:
            install = "installed" if agent["installed"] else "not found"
            protected = "protected" if agent["protected"] else "not protected"
            suffix = ", experimental" if agent["experimental"] else ""
            lines.append(f"  {agent['name']}: {install}, {protected}{suffix}")
    else:
        lines.append("  none detected")
    lines.append("")
    lines.append("Config")
    for check in report["checks"]:
        if check["name"] in {"Config", "Upstream", "Event log", "SLM"}:
            lines.append(f"  {check['name']}: {check['detail']} {check['status']}")
    if report["warnings"]:
        lines.append("")
        lines.append("Warnings")
        for warning in report["warnings"]:
            lines.append(f"  - {warning}")
    if report["errors"]:
        lines.append("")
        lines.append("Errors")
        for error in report["errors"]:
            lines.append(f"  - {error}")
    lines.append("")
    lines.append(f"Result: {report['result']}")
    return "\n".join(lines)
