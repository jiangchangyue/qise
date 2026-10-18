"""JSONL security event store and schema for product CLI commands."""

from __future__ import annotations

import json
import uuid
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from qise.product.privacy import redact_evidence, redact_text
from qise.product.service import ensure_qise_home, events_path, load_state, now_iso

SCHEMA_VERSION = "0.1"

_PRODUCT_RISK_CATEGORIES = {
    "audit": "Suspicious Behavior Chain",
    "command": "Dangerous Commands",
    "command_injection": "Dangerous Commands",
    "dangerous_command": "Dangerous Commands",
    "credential": "Secret Leakage",
    "credential_exfil": "Secret Leakage",
    "secret_leakage": "Secret Leakage",
    "filesystem": "Sensitive Files",
    "sensitive_files": "Sensitive Files",
    "network": "Unsafe Network",
    "unsafe_network": "Unsafe Network",
    "prompt": "Prompt Injection",
    "prompt_injection": "Prompt Injection",
    "tool_sanity": "Tool Poisoning",
    "tool_poisoning": "Tool Poisoning",
    "supply_chain": "Skill Supply Chain",
    "skill_supply_chain": "Skill Supply Chain",
    "exfil": "Data Exfiltration",
    "data_exfiltration": "Data Exfiltration",
    "resource": "Resource Abuse",
    "resource_abuse": "Resource Abuse",
    "output": "Secret Leakage",
    "tool_policy": "Policy Violation",
    "agent_config": "Agent Configuration",
    "runtime": "Runtime Observation",
    "runtime_observation": "Runtime Observation",
    "process": "Runtime Process",
    "file_change": "Runtime File Changes",
    "network_observation": "Runtime Network",
}


class EventAgent(BaseModel):
    name: str = ""
    type: str = ""
    session_id: str = ""


class EventAction(BaseModel):
    type: str = ""
    name: str = ""
    resource: str = ""


class EventRisk(BaseModel):
    category: str
    severity: str = "medium"
    confidence: float = 0.0


class EventDecision(BaseModel):
    verdict: str
    mode: str = "enforce"
    blocked_by: list[str] = Field(default_factory=list)


class EventEvidence(BaseModel):
    type: str = "rule"
    rule_id: str = ""
    message: str = ""
    path: str = ""
    snippet: str = ""
    guard: str = ""
    verdict: str = ""
    risk_source: str = ""
    confidence: float | None = None
    evidence_kind: str = "finding"


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:16]}")
    schema_version: str = SCHEMA_VERSION
    timestamp: str = Field(default_factory=now_iso)
    stage: str
    source: str
    agent: EventAgent = Field(default_factory=EventAgent)
    action: EventAction
    risk: EventRisk
    decision: EventDecision
    evidence: list[EventEvidence] = Field(default_factory=list)
    recommendation: str = ""
    correlation_id: str = Field(default_factory=lambda: f"corr_{uuid.uuid4().hex[:12]}")
    raw_ref: str = ""


def product_risk_category(category: str) -> str:
    normalized = category.strip().lower().replace(" ", "_").replace("-", "_")
    return _PRODUCT_RISK_CATEGORIES.get(normalized, category.replace("_", " ").title() if category else "Unknown")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def parse_since(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value.strip().lower()
    try:
        amount = int(raw[:-1])
    except Exception:
        return _parse_timestamp(value)
    unit = raw[-1]
    if unit == "m":
        delta = timedelta(minutes=amount)
    elif unit == "h":
        delta = timedelta(hours=amount)
    elif unit == "d":
        delta = timedelta(days=amount)
    else:
        return _parse_timestamp(value)
    return datetime.now(UTC) - delta


def _safe_snippet(value: Any, *, max_len: int = 240) -> str:
    if value is None:
        return ""
    value = redact_evidence(value)
    try:
        raw = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    except Exception:
        raw = str(value)
    raw = redact_text(" ".join(raw.split()))
    if len(raw) <= max_len:
        return raw
    return raw[: max_len - 3] + "..."


def make_event(
    *,
    stage: str,
    source: str,
    verdict: str,
    category: str,
    severity: str,
    confidence: float,
    action_type: str,
    action_name: str = "",
    resource: Any = "",
    agent_name: str = "",
    session_id: str = "",
    evidence: list[dict[str, Any]] | None = None,
    recommendation: str = "",
    mode: str = "enforce",
    blocked_by: list[str] | None = None,
    raw_ref: str = "",
    correlation_id: str = "",
) -> dict[str, Any]:
    category_label = product_risk_category(category)
    blocked = blocked_by if blocked_by is not None else ([category] if verdict == "block" else [])
    event = SecurityEvent(
        stage=stage,
        source=source,
        agent=EventAgent(name=agent_name, type=agent_name, session_id=session_id),
        action=EventAction(type=action_type, name=action_name, resource=_safe_snippet(resource)),
        risk=EventRisk(category=category_label, severity=severity, confidence=confidence),
        decision=EventDecision(verdict=verdict, mode=mode, blocked_by=blocked),
        evidence=[EventEvidence(**item) for item in evidence or []],
        recommendation=recommendation,
        correlation_id=correlation_id or f"corr_{uuid.uuid4().hex[:12]}",
        raw_ref=raw_ref,
    )
    return event.model_dump(mode="json")


def _category_from_results(results: list[Any], fallback: str) -> str:
    for result in results:
        if not isinstance(result, dict):
            continue
        verdict = str(result.get("verdict", "")).lower()
        if verdict in {"block", "warn"}:
            risk_source = result.get("risk_source")
            if risk_source:
                return str(risk_source)
            guard = result.get("guard")
            if guard:
                return str(guard)
    return fallback


def _confidence_from_results(results: list[Any], fallback: float) -> float:
    confidences: list[float] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        try:
            confidence = float(result.get("confidence"))
        except (TypeError, ValueError):
            continue
        if 0.0 <= confidence <= 1.0:
            confidences.append(confidence)
    return max(confidences) if confidences else fallback


def guard_event_from_results(
    *,
    stage: str,
    source: str,
    verdict: str,
    action_type: str,
    action_name: str = "",
    resource: Any = "",
    agent_name: str = "",
    session_id: str = "",
    blocked_by: str | None = None,
    warnings: list[str] | None = None,
    guard_results: list[dict[str, Any]] | None = None,
    recommendation: str = "",
    correlation_id: str = "",
) -> dict[str, Any]:
    """Build a product event from guard pipeline output.

    The event intentionally stores compact snippets, not full request/response
    bodies, so the local evidence trail remains useful without becoming a
    second copy of a user's private agent traffic.
    """
    results = guard_results or []
    normalized_verdict = "block" if verdict == "block" else "warn"
    notices = [result for result in results if isinstance(result, dict) and str(result.get("verdict", "pass")).lower() != "pass"]
    informational = normalized_verdict == "warn" and bool(notices) and all(
        result.get("verdict") == "warn" and result.get("evidence_kind") in {"precaution", "degraded"}
        for result in notices
    )
    if informational:
        normalized_verdict = "info"
    category = blocked_by or _category_from_results(results, "guard")
    evidence: list[dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        if str(result.get("verdict", "pass")).lower() == "pass":
            continue
        evidence.append({
            "type": "guard_result",
            "guard": str(result.get("guard", "")),
            "verdict": str(result.get("verdict", "")),
            "message": _safe_snippet(result.get("message", "")),
            "risk_source": str(result.get("risk_source", "")),
            "confidence": result.get("confidence"),
            "evidence_kind": str(result.get("evidence_kind", "finding")),
        })
    for warning in warnings or []:
        evidence.append({
            "type": "runtime",
            "message": _safe_snippet(warning),
        })
    resource_snippet = _safe_snippet(resource)
    if resource_snippet:
        evidence.append({
            "type": "runtime",
            "message": "Action/resource snippet captured by Qise.",
            "snippet": resource_snippet,
        })
    if not recommendation:
        recommendation = (
            "Protection notice: review detection availability or content isolation details. No specific threat was identified."
            if informational else
            "Qise blocked this action. Review the evidence before retrying or relaxing guard mode."
            if normalized_verdict == "block"
            else "Qise observed suspicious behavior. Review the evidence before continuing."
        )
    correlation_id = correlation_id or _active_runtime_correlation(agent_name)
    return make_event(
        stage=stage,
        source=source,
        verdict=normalized_verdict,
        category="Protection Notice" if informational else category,
        severity="info" if informational else "high" if normalized_verdict == "block" else "medium",
        confidence=_confidence_from_results(results, 1.0 if normalized_verdict == "block" else 0.6),
        action_type=action_type,
        action_name=action_name,
        resource=resource_snippet,
        agent_name=agent_name,
        session_id=session_id,
        evidence=evidence,
        recommendation=recommendation,
        blocked_by=[blocked_by] if normalized_verdict == "block" and blocked_by else None,
        correlation_id=correlation_id,
    )


def _active_runtime_correlation(agent_name: str = "") -> str:
    try:
        runs = load_state().get("runtime_runs", {})
    except Exception:
        return ""
    if not isinstance(runs, dict):
        return ""
    active: list[tuple[str, dict[str, Any]]] = []
    for corr_id, record in runs.items():
        if not isinstance(record, dict):
            continue
        if record.get("status") != "running":
            continue
        if agent_name and record.get("agent") not in {agent_name, ""}:
            continue
        active.append((str(corr_id), record))
    if not active and agent_name:
        for corr_id, record in runs.items():
            if isinstance(record, dict) and record.get("status") == "running":
                active.append((str(corr_id), record))
    if not active:
        return ""
    active.sort(key=lambda item: str(item[1].get("updated_at") or item[1].get("started_at") or ""))
    return active[-1][0]


def record_guard_event(**kwargs: Any) -> Path:
    """Append a WARN/BLOCK guard event to the local JSONL event store."""
    event = guard_event_from_results(**kwargs)
    return append_event(event)




def record_runtime_event(
    *,
    agent_name: str,
    command: list[str],
    cwd: str,
    pid: int,
    returncode: int | None,
    duration_s: float,
    correlation_id: str,
    stdout_summary: str = "",
    stderr_summary: str = "",
    process_tree: list[dict[str, Any]] | None = None,
    file_changes: dict[str, Any] | None = None,
    network: list[dict[str, Any]] | None = None,
) -> Path:
    """Append a runtime-observer event to the product event store."""
    evidence: list[dict[str, Any]] = [
        {
            "type": "runtime",
            "message": f"Observed process pid={pid}, exit={returncode}, duration={duration_s:.2f}s.",
            "snippet": " ".join(command),
        },
        {
            "type": "runtime",
            "message": f"Working directory: {cwd}",
        },
    ]

    process_tree = process_tree or []
    file_changes = file_changes or {"added": [], "modified": [], "deleted": [], "truncated": False}
    network = network or []

    if process_tree:
        commands = [str(item.get("command", "")) for item in process_tree if item.get("command")]
        evidence.append({
            "type": "process",
            "message": f"Process tree sampled: {len(process_tree)} process(es).",
            "snippet": _safe_snippet(commands, max_len=360),
        })
    if stdout_summary:
        evidence.append({
            "type": "stdout",
            "message": "stdout summary captured by Qise Runtime Observer.",
            "snippet": _safe_snippet(stdout_summary, max_len=360),
        })
    if stderr_summary:
        evidence.append({
            "type": "stderr",
            "message": "stderr summary captured by Qise Runtime Observer.",
            "snippet": _safe_snippet(stderr_summary, max_len=360),
        })
    changed_count = sum(len(file_changes.get(key, [])) for key in ("added", "modified", "deleted"))
    if changed_count:
        evidence.append({
            "type": "file_change",
            "message": (
                f"File changes: +{len(file_changes.get('added', []))}, "
                f"~{len(file_changes.get('modified', []))}, "
                f"-{len(file_changes.get('deleted', []))}."
            ),
            "snippet": _safe_snippet(file_changes, max_len=360),
        })
    if network:
        evidence.append({
            "type": "network",
            "message": f"Observed network endpoint(s): {len(network)}.",
            "snippet": _safe_snippet(network, max_len=360),
        })

    suspicious = _runtime_suspicious(command, process_tree, network)
    verdict = "warn" if suspicious or (returncode not in (0, None)) else "pass"
    recommendation = (
        "Qise observed runtime behavior worth reviewing. Check process, file, and network evidence."
        if verdict == "warn"
        else "Runtime behavior was recorded for audit correlation."
    )
    event = make_event(
        stage="runtime",
        source="observer",
        verdict=verdict,
        category="runtime_observation",
        severity="medium" if verdict == "warn" else "low",
        confidence=0.8 if verdict == "warn" else 0.4,
        action_type="process",
        action_name=agent_name,
        resource={
            "command": command,
            "cwd": cwd,
            "pid": pid,
            "returncode": returncode,
            "duration_s": round(duration_s, 3),
        },
        agent_name=agent_name,
        session_id=correlation_id,
        evidence=evidence,
        recommendation=recommendation,
        mode="observe",
        correlation_id=correlation_id,
    )
    return append_event(event)


def _runtime_suspicious(command: list[str], process_tree: list[dict[str, Any]], network: list[dict[str, Any]]) -> bool:
    joined = " ".join(command + [str(item.get("command", "")) for item in process_tree]).lower()
    suspicious_tokens = [
        "curl ",
        "wget ",
        "| bash",
        "| sh",
        "rm -rf /",
        "/etc/shadow",
        "chmod 777",
        "sudo ",
        "nc ",
        "netcat",
    ]
    return any(token in joined for token in suspicious_tokens) or bool(network)


def append_event(event: dict[str, Any]) -> Path:
    ensure_qise_home()
    normalized = SecurityEvent.model_validate(redact_evidence(event)).model_dump(mode="json")
    path = events_path()
    import os
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(json.dumps(normalized, sort_keys=True) + "\n")
    return path


def _iter_events(*, since: str | None = None, stage: str | None = None):
    path = events_path()
    if not path.exists():
        return

    since_dt = parse_since(since)
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = SecurityEvent.model_validate(redact_evidence(json.loads(line))).model_dump(mode="json")
            except Exception:
                continue
            if since_dt is not None:
                ts = _parse_timestamp(str(event.get("timestamp", "")))
                if ts is None or ts < since_dt:
                    continue
            if stage and str(event.get("stage", "")).lower() != stage.lower():
                continue
            yield event


def load_events(*, limit: int = 50, since: str | None = None, stage: str | None = None) -> list[dict[str, Any]]:
    return list(deque(_iter_events(since=since, stage=stage), maxlen=limit if limit > 0 else None))


def count_recent_events(hours: int = 24) -> tuple[int, int]:
    events = _iter_events(since=f"{hours}h")
    blocks = 0
    warnings = 0
    for event in events:
        verdict = event.get("decision", {}).get("verdict")
        if verdict == "block":
            blocks += 1
        elif verdict == "warn":
            warnings += 1
    return blocks, warnings


def format_events(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No security events yet."

    lines = []
    for event in events:
        risk = event.get("risk", {})
        decision = event.get("decision", {})
        action = event.get("action", {})
        evidence = event.get("evidence", [])
        action_label = action.get("name") or action.get("resource") or "-"
        lines.append(
            f"{event.get('timestamp', '')} {decision.get('verdict', 'unknown').upper():<5} "
            f"{risk.get('category', 'Unknown')} / {risk.get('severity', 'medium')} "
            f"[{event.get('source', '')}:{event.get('stage', '')}] "
            f"{action.get('type', '')}:{action_label} "
            f"id={event.get('id', '')}"
        )
        if evidence:
            first = evidence[0]
            message = first.get("message") or first.get("snippet")
            if message:
                lines.append(f"  Evidence: {message}")
        recommendation = event.get("recommendation")
        if recommendation:
            lines.append(f"  Recommendation: {recommendation}")
    return "\n".join(lines)
