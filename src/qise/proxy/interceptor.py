"""ProxyInterceptor — routes parsed content through the Guard Pipeline.

Coordinates request and response interception:
  - Request interception: check user messages and tool results for injection (ingress)
  - Response interception: check tool calls for dangerous actions (egress)
  - Output interception: check response text for credential/PII leaks (output)
"""

from __future__ import annotations

import copy
from contextlib import suppress
from typing import Any

from pydantic import BaseModel, Field

from qise.core.models import GuardContext, PipelineResult, ToolCallRecord
from qise.product.events import record_guard_event
from qise.proxy.parser import ParsedMessage, ParsedRequest, ParsedResponse


class ProxyDecision(BaseModel):
    """Decision returned by the proxy interceptor.

    Attributes:
        action: pass, warn, or block.
        modified_body: Modified request/response body (e.g., with injected context).
        warnings: List of warning messages from guards.
        block_reason: Human-readable reason for blocking (if action=block).
        guard_results: All guard results from the interception.
    """

    action: str = "pass"  # "pass" | "warn" | "block"
    modified_body: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    block_reason: str = ""
    guard_results: list[dict[str, Any]] = Field(default_factory=list)


class ProxyInterceptor:
    """Route parsed content through the Guard Pipeline.

    Usage:
        interceptor = ProxyInterceptor(shield)
        decision = interceptor.intercept_request(parsed_request, raw_body)
        decision = interceptor.intercept_response(parsed_response, raw_body)
    """

    def __init__(self, shield: Any, config: Any = None) -> None:
        """Initialize with a Shield instance.

        Args:
            shield: A Shield instance with a configured pipeline.
            config: Optional ProxyConfig for behavior tuning.
        """
        self._shield = shield
        self._config = config

    def intercept_request(
        self,
        parsed: ParsedRequest,
        raw_body: dict[str, Any],
        agent_name: str = "",
    ) -> ProxyDecision:
        """Intercept a chat completion request.

        Checks:
          1. User messages for injection (ingress)
          2. Tool results for injection (ingress)
          3. Tool descriptions for poisoning (ingress)

        Returns:
            ProxyDecision with action pass/warn/block.
        """
        from qise.product.policy import refresh_guard_policy

        refresh_guard_policy(self._shield)
        all_warnings: list[str] = []
        all_results: list[dict[str, Any]] = []
        should_block = False
        block_reason = ""
        modified_body = copy.deepcopy(raw_body)
        request_context = self._request_context(parsed, agent_name)

        config = self._shield.config
        guard_modes = {name: config.guard_mode(name) for name in config.guards.enabled}

        # Check user messages and tool results for injection
        for msg in parsed.messages:
            if msg.role in {"user", "tool"} and msg.content:
                trust_boundary = msg.trust_boundary or ("tool_result" if msg.role == "tool" else "user_input")
                ctx = GuardContext(
                    tool_name="content_check",
                    tool_args={"content": msg.content},
                    trust_boundary=trust_boundary,
                    integration_mode="proxy",
                    **request_context,
                )
                result = self._shield.pipeline.run_ingress(ctx, guard_modes)
                all_results.extend(self._summarize_results(result))
                all_warnings.extend(result.warnings)
                if result.transformed_args:
                    transformed = result.transformed_args.get("content")
                    if isinstance(transformed, str) and transformed != msg.content:
                        self._replace_message_content(modified_body, msg, transformed)

                if result.should_block:
                    should_block = True
                    block_reason = f"Request blocked by guard: {result.blocked_by}"
                    break

        # Check tool descriptions for poisoning (if tools present)
        if not should_block:
            for tool_def in parsed.tools:
                if tool_def.description:
                    ctx = GuardContext(
                        tool_name=tool_def.name,
                        tool_args={},
                        tool_description=tool_def.description,
                        trust_boundary="tool_description",
                        integration_mode="proxy",
                        **request_context,
                    )
                    result = self._shield.pipeline.run_ingress(ctx, guard_modes)
                    all_results.extend(self._summarize_results(result))
                    all_warnings.extend(result.warnings)

                    if result.should_block:
                        should_block = True
                        block_reason = f"Tool description blocked: {result.blocked_by}"
                        break

        # Determine action
        if should_block:
            action = "block"
        elif all_warnings:
            action = "warn"
        else:
            action = "pass"

        decision = ProxyDecision(
            action=action,
            modified_body=modified_body,
            warnings=all_warnings,
            block_reason=block_reason,
            guard_results=all_results,
        )
        self._record_decision_event(
            stage="ingress",
            decision=decision,
            action_type="request",
            action_name=self._request_action_name(parsed),
            resource=self._request_resource(parsed),
            agent_name=agent_name,
        )
        return decision

    def intercept_response(
        self,
        parsed: ParsedResponse,
        raw_body: dict[str, Any],
        agent_name: str = "",
        request_context: ParsedRequest | None = None,
        audit_only: bool = False,
    ) -> ProxyDecision:
        """Intercept a chat completion response.

        Checks:
          1. Tool calls for dangerous actions (egress)
          2. Reasoning content for manipulation traces (ingress/reasoning)
          3. Response text for credential/PII leaks (output)

        Returns:
            ProxyDecision with action pass/warn/block.
        """
        from qise.product.policy import refresh_guard_policy

        refresh_guard_policy(self._shield)
        all_warnings: list[str] = []
        all_results: list[dict[str, Any]] = []
        should_block = False
        block_reason = ""
        context_fields = self._request_context(request_context, agent_name) if request_context else {}

        config = self._shield.config
        guard_modes = {name: config.guard_mode(name) for name in config.guards.enabled}

        # Check tool calls for dangerous actions (egress)
        for tc in parsed.tool_calls:
            if not tc.arguments_valid or not tc.tool_name:
                should_block = True
                block_reason = "Tool call has incomplete or invalid arguments"
                break
            ctx = GuardContext(
                tool_name=tc.tool_name,
                tool_args=tc.tool_args,
                integration_mode="proxy",
                agent_reasoning=parsed.reasoning or None,
                active_security_rules=self._security_rules(tc.tool_name, tc.tool_args),
                **context_fields,
            )
            result = self._shield.pipeline.run_egress(ctx, guard_modes)
            all_results.extend(self._summarize_results(result))
            all_warnings.extend(result.warnings)

            if result.should_block:
                should_block = True
                block_reason = f"Tool call blocked by guard: {result.blocked_by}"
                break

        # Check response text for credential/PII leaks (output)
        if not should_block and (parsed.content or parsed.reasoning):
            ctx = GuardContext(
                tool_name="output",
                tool_args={"text": parsed.content},
                integration_mode="proxy",
                agent_reasoning=parsed.reasoning or None,
                **context_fields,
            )
            result = self._shield.pipeline.run_output(ctx, guard_modes)
            all_results.extend(self._summarize_results(result))
            all_warnings.extend(result.warnings)

            if result.should_block:
                should_block = True
                block_reason = f"Output blocked by guard: {result.blocked_by}"

        # Determine action
        if should_block and audit_only:
            all_warnings.append("Output audit detected risk after text was delivered; delivery was not blocked")
            action = "warn"
        elif should_block:
            action = "block"
        elif all_warnings:
            action = "warn"
        else:
            action = "pass"

        decision = ProxyDecision(
            action=action,
            modified_body=raw_body,
            warnings=all_warnings,
            block_reason=block_reason,
            guard_results=all_results,
        )
        self._record_decision_event(
            stage="egress" if parsed.tool_calls else "output",
            decision=decision,
            action_type="tool_call" if parsed.tool_calls else "output",
            action_name=parsed.tool_calls[0].tool_name if parsed.tool_calls else "output",
            resource=parsed.tool_calls[0].tool_args if parsed.tool_calls else parsed.content,
            agent_name=agent_name,
        )
        return decision

    def _security_rules(self, tool_name: str, tool_args: dict[str, Any]) -> list[str]:
        context = self._shield.get_security_context(tool_name, tool_args)
        return [line for line in context.splitlines() if line.strip()] if context else []

    def _request_context(self, parsed: ParsedRequest, agent_name: str) -> dict[str, Any]:
        """Use only history actually supplied in this request; do not invent hidden state."""
        history = [
            ToolCallRecord(tool_name=call.tool_name, tool_args=call.tool_args)
            for message in parsed.messages
            for call in message.tool_calls
        ]
        trajectory = [
            {"role": message.role, "content": message.content[:4000]}
            for message in parsed.messages[-20:]
            if message.content
        ]
        metadata = parsed.raw_body.get("metadata") or {}
        session_id = metadata.get("session_id") if isinstance(metadata, dict) else None
        return {
            "session_trajectory": trajectory,
            "tool_call_history": history[-20:],
            "iteration_count": len(history),
            "session_id": f"{agent_name}:{session_id}" if isinstance(session_id, str) else None,
            "framework_metadata": {
                "agent_name": agent_name,
                "api_format": parsed.api_format,
                "history_scope": "request_only",
                "previous_response_id": parsed.raw_body.get("previous_response_id"),
            },
        }

    @staticmethod
    def _replace_message_content(body: dict[str, Any], message: ParsedMessage, transformed: str) -> None:
        """Replace inspected text only, retaining image/file blocks and protocol fields."""
        if message.content and transformed.endswith(message.content) and message.content_paths:
            # Isolation adds a prefix. Preserve all original block positions, so
            # text surrounding an image or file keeps its original meaning.
            prefix = transformed[: -len(message.content)]
            parent: Any = body
            path = message.content_paths[0]
            for component in path[:-1]:
                parent = parent[component]
            parent[path[-1]] = prefix + parent[path[-1]]
            return
        for index, path in enumerate(message.content_paths):
            parent: Any = body
            for component in path[:-1]:
                parent = parent[component]
            parent[path[-1]] = transformed if index == 0 else ""

    def _record_decision_event(
        self,
        *,
        stage: str,
        decision: ProxyDecision,
        action_type: str,
        action_name: str = "",
        resource: Any = "",
        agent_name: str = "",
    ) -> None:
        if decision.action not in {"warn", "block"}:
            return
        # Event storage must never change the guard decision.
        with suppress(Exception):
            record_guard_event(
                stage=stage,
                source="proxy",
                verdict=decision.action,
                action_type=action_type,
                action_name=action_name,
                resource=resource,
                agent_name=agent_name,
                blocked_by=self._blocked_by(decision),
                warnings=decision.warnings,
                guard_results=decision.guard_results,
            )

    def _blocked_by(self, decision: ProxyDecision) -> str | None:
        if not decision.block_reason:
            return None
        if ":" in decision.block_reason:
            return decision.block_reason.rsplit(":", 1)[-1].strip() or None
        return decision.block_reason

    def _request_action_name(self, parsed: ParsedRequest) -> str:
        if parsed.tools:
            return parsed.tools[0].name
        if any(msg.role == "tool" and msg.content for msg in parsed.messages):
            return "tool_result"
        return "content_check"

    def _request_resource(self, parsed: ParsedRequest) -> Any:
        if parsed.tools:
            return {"tool": parsed.tools[0].name, "description": parsed.tools[0].description}
        for msg in parsed.messages:
            if msg.role in {"user", "tool"} and msg.content:
                return msg.content
        return {"model": parsed.model}

    def _summarize_results(self, result: PipelineResult) -> list[dict[str, Any]]:
        """Summarize pipeline results for the ProxyDecision."""
        summaries = []
        for gr in result.results:
            summary: dict[str, Any] = {
                "guard": gr.guard_name,
                "verdict": gr.verdict,
                "confidence": gr.confidence,
                "message": gr.message,
                "evidence_kind": gr.evidence_kind,
            }
            if gr.risk_attribution:
                summary["risk_source"] = gr.risk_attribution.risk_source
            summaries.append(summary)
        return summaries
