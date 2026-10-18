"""Bridge protocol — request/response types for Rust ↔ Python communication."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class BridgeMessage(BaseModel):
    """A parsed message from a chat completion request."""
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str = ""
    trust_boundary: str | None = None


class BridgeToolDef(BaseModel):
    """A tool definition from a chat completion request."""
    name: str
    description: str = ""


class BridgeToolCall(BaseModel):
    """A tool call from a chat completion response."""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)


class GuardCheckRequest(BaseModel):
    """Request from Rust Proxy to Python Bridge for guard analysis."""
    type: str  # "request" | "response"
    messages: list[BridgeMessage] = Field(default_factory=list)
    tools: list[BridgeToolDef] = Field(default_factory=list)
    tool_calls: list[BridgeToolCall] = Field(default_factory=list)
    content: str = ""
    reasoning: str = ""
    model: str = ""
    stream: bool = False


class GuardResultSummary(BaseModel):
    """Summary of a single guard's result."""
    guard: str
    verdict: str
    message: str = ""
    latency_ms: int = 0
    evidence_kind: str = "finding"


class GuardCheckResponse(BaseModel):
    """Response from Python Bridge to Rust Proxy with guard decision."""
    action: str  # "pass" | "warn" | "block"
    guard_results: list[GuardResultSummary] = Field(default_factory=list)
    security_context: str = ""
    warnings: list[str] = Field(default_factory=list)
    block_reason: str = ""
