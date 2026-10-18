"""Core data models for Qise security framework.

All models follow the interface definitions in docs/architecture.md.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Trust model
# ---------------------------------------------------------------------------


class TrustBoundary(str):
    """10 trust boundary types representing data provenance.

    Each boundary has an associated TrustLevel that determines how
    aggressively content from that source is inspected.
    """

    USER_INPUT = "user_input"
    TOOL_RESULT = "tool_result"
    WEB_CONTENT = "web_content"
    MCP_RESPONSE = "mcp_response"
    CONTEXT_FILE = "context_file"
    SKILL_CONTENT = "skill_content"
    MEMORY_RETRIEVAL = "memory_retrieval"
    AGENT_MESSAGE = "agent_message"
    KNOWLEDGE_BASE = "knowledge_base"
    TOOL_DESCRIPTION = "tool_description"


class TrustLevel(IntEnum):
    """5-tier trust level for data sources.

    Higher values = more trusted = less aggressive inspection.
    """

    UNTRUSTED = 0  # web_content, mcp_response (unverified)
    LOW = 1  # tool_result, knowledge_base (data may be poisoned)
    MEDIUM = 2  # user_input, skill_content, memory_retrieval
    HIGH = 3  # context_file, agent_message (own data)
    VERIFIED = 4  # hash-verified persistent data


# Default mapping from trust boundary → trust level
TRUST_LEVEL_MAP: dict[str, TrustLevel] = {
    TrustBoundary.WEB_CONTENT: TrustLevel.UNTRUSTED,
    TrustBoundary.MCP_RESPONSE: TrustLevel.UNTRUSTED,
    TrustBoundary.TOOL_RESULT: TrustLevel.LOW,
    TrustBoundary.KNOWLEDGE_BASE: TrustLevel.LOW,
    TrustBoundary.TOOL_DESCRIPTION: TrustLevel.LOW,
    TrustBoundary.USER_INPUT: TrustLevel.MEDIUM,
    TrustBoundary.SKILL_CONTENT: TrustLevel.MEDIUM,
    TrustBoundary.MEMORY_RETRIEVAL: TrustLevel.MEDIUM,
    TrustBoundary.CONTEXT_FILE: TrustLevel.HIGH,
    TrustBoundary.AGENT_MESSAGE: TrustLevel.HIGH,
}


def trust_level_for(boundary: str | None) -> TrustLevel | None:
    """Return the default trust level for a given boundary, or None if unknown."""
    if boundary is None:
        return None
    return TRUST_LEVEL_MAP.get(boundary)


# ---------------------------------------------------------------------------
# Guard verdict
# ---------------------------------------------------------------------------


class GuardVerdict(str):
    """Verdict returned by every guard check.

    PASS       — No issue detected
    WARN       — Suspicious but not blocked (observe mode)
    ESCALATE   — Escalate to LLM deep analysis
    BLOCK      — Action blocked
    APPROVE    — Requires human approval
    """

    PASS = "pass"
    WARN = "warn"
    ESCALATE = "escalate"
    BLOCK = "block"
    APPROVE = "approve"


# ---------------------------------------------------------------------------
# Guard result models
# ---------------------------------------------------------------------------


class RiskAttribution(BaseModel):
    """Structured risk attribution from AI model analysis.

    Inspired by XSafeClaw's taxonomy but more concise.
    """

    risk_source: str = Field(
        description="e.g., 'indirect_injection', 'tool_poison', 'credential_exfil'",
    )
    failure_mode: str = Field(
        description="e.g., 'unauthorized_action', 'data_leakage', 'identity_hijack'",
    )
    real_world_harm: str = Field(
        description="e.g., 'financial_loss', 'privacy_violation', 'system_compromise'",
    )
    confidence: float = Field(ge=0.0, le=1.0, description="0.0-1.0")
    reasoning: str = Field(description="Model's reasoning process (explainability)")


class ToolCallRecord(BaseModel):
    """Record of a prior tool call within the current session."""

    tool_name: str
    tool_args: dict[str, Any] = {}
    verdict: str = GuardVerdict.PASS
    timestamp: float = 0.0


class GuardContext(BaseModel):
    """Context passed to every guard check.

    Populated by the integration layer (proxy / MCP / SDK adapter).
    Not all fields are available in every integration mode — guards
    must handle None gracefully.
    """

    # What the agent is about to do
    tool_name: str
    tool_args: dict[str, Any] = {}
    trust_boundary: str | None = None

    # Trajectory context (critical for AI understanding)
    session_trajectory: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Conversation history summary",
    )
    tool_call_history: list[ToolCallRecord] = Field(
        default_factory=list,
        description="Prior tool calls this session",
    )
    iteration_count: int = 0

    # Tool metadata (for tool poisoning detection)
    tool_description: str | None = None
    tool_source: str | None = None

    # Agent reasoning (for ReasoningGuard)
    agent_reasoning: str | None = Field(
        default=None,
        description="Agent's chain of thought",
    )

    # Execution environment
    workspace_path: str | None = None
    session_id: str | None = None
    user_id: str | None = None

    # Integration mode that produced this context
    integration_mode: Literal["proxy", "mcp", "sdk"] = "sdk"

    # Framework-specific data
    framework_metadata: dict[str, Any] = {}

    # Soft-hard linkage: security rules from SecurityContextProvider
    active_security_rules: list[str] = Field(
        default_factory=list,
        description="Security rules from SecurityContextProvider for current context",
    )

    def trust_level(self) -> TrustLevel | None:
        """Convenience: return trust level for this context's trust boundary."""
        return trust_level_for(self.trust_boundary)


class GuardResult(BaseModel):
    """Result returned by every guard check."""

    guard_name: str
    verdict: str = GuardVerdict.PASS
    confidence: float = 1.0
    message: str = ""
    remediation: str = ""
    evidence_kind: Literal["finding", "precaution", "degraded"] = Field(
        default="finding",
        description=(
            "finding: concrete risk or policy decision; precaution: source isolation only; "
            "degraded: security analysis unavailable. Informational only; never overrides verdict."
        ),
    )
    risk_attribution: RiskAttribution | None = None
    transformed_args: dict[str, Any] | None = Field(
        default=None,
        description="For arg sanitization (e.g., redacting credentials)",
    )
    model_used: str | None = None
    latency_ms: int | None = None
    threshold_adjustments: dict[str, float] | None = Field(
        default=None,
        description="ReasoningGuard signal: guard_name → threshold delta",
    )

    @property
    def should_block(self) -> bool:
        """True when execution must stop, including pending human approval."""
        return self.verdict in (GuardVerdict.BLOCK, GuardVerdict.APPROVE)


class PipelineResult(BaseModel):
    """Aggregated result from running a guard pipeline."""

    verdict: str = GuardVerdict.PASS
    results: list[GuardResult] = Field(default_factory=list)
    blocked_by: str | None = None
    warnings: list[str] = Field(default_factory=list)
    threshold_adjustments: dict[str, float] = Field(default_factory=dict)
    transformed_args: dict[str, Any] | None = Field(
        default=None,
        description="Final checked arguments after sequential guard transformations",
    )

    @property
    def should_block(self) -> bool:
        return self.verdict in (GuardVerdict.BLOCK, GuardVerdict.APPROVE)


# ---------------------------------------------------------------------------
# Guard mode
# ---------------------------------------------------------------------------


class GuardMode(str):
    """Operational mode for each guard."""

    OBSERVE = "observe"  # Log only, never block
    ENFORCE = "enforce"  # Block on high-confidence detections
    OFF = "off"  # Guard disabled


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ModelUnavailableError(Exception):
    """Raised when an AI model (SLM/LLM) is unavailable.

    Guards catch this and fall back to rule-based checks.
    """
