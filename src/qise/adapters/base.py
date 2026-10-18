"""Base adapter classes for Qise framework integration.

All adapters inherit from AgentAdapter and use IngressCheckMixin and/or
EgressCheckMixin to route content through the Guard Pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from qise.core.models import GuardContext, GuardVerdict, PipelineResult
from qise.core.shield import Shield


def blocked_message(result: PipelineResult) -> str:
    """Explain why a caller must stop instead of executing or exposing data."""
    if result.verdict == GuardVerdict.APPROVE:
        return f"Agent360 requires human approval before execution: {result.blocked_by}"
    return f"Agent360 blocked: {result.blocked_by}"


def tool_arguments(tool: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Inspect the values actually passed to a callable, including defaults."""
    import inspect

    try:
        bound = inspect.signature(tool).bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {"_positional": str(args), **kwargs}


class IngressCheckMixin:
    """Mixin that provides ingress (World → Agent) guard checks.

    Use this in adapters that can intercept incoming content:
    user messages, tool results, MCP responses, etc.
    """

    shield: Shield

    def check_user_input(
        self,
        content: str,
        trust_boundary: str = "user_input",
        session_id: str | None = None,
    ) -> PipelineResult:
        """Check user input for injection attacks."""
        ctx = GuardContext(
            tool_name="content_check",
            tool_args={"content": content},
            trust_boundary=trust_boundary,
            session_id=session_id,
            integration_mode=self._integration_mode(),
        )
        return self.shield.check_sync(ctx, pipeline_kind="ingress")

    def check_tool_result(
        self,
        content: str,
        tool_name: str = "",
        session_id: str | None = None,
    ) -> PipelineResult:
        """Check tool result for injection attacks."""
        ctx = GuardContext(
            tool_name=tool_name or "tool_result",
            tool_args={"content": content},
            trust_boundary="tool_result",
            session_id=session_id,
            integration_mode=self._integration_mode(),
        )
        return self.shield.check_sync(ctx, pipeline_kind="ingress")

    def protect_tool_result(
        self, output: Any, tool_name: str = "", session_id: str | None = None,
        *, apply_transforms: bool = False,
    ) -> Any:
        """Stop blocked results and apply checked text transformations.

        Generic callable wrappers preserve their return contract, including
        machine-readable strings. Consumers handing text directly to a model
        can opt into isolation banners with apply_transforms=True. Structured
        results retain their original type.
        """
        result = self.check_tool_result(str(output), tool_name, session_id)
        if result.should_block:
            raise RuntimeError(blocked_message(result))
        if apply_transforms and isinstance(output, str) and result.transformed_args is not None:
            content = result.transformed_args.get("content")
            if isinstance(content, str):
                return content
        return output

    def _integration_mode(self) -> str:
        return "sdk"


class EgressCheckMixin:
    """Mixin that provides egress (Agent → World) and output guard checks.

    Use this in adapters that can intercept outgoing actions:
    tool calls, commands, and output text.
    """

    shield: Shield

    def check_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        session_id: str | None = None,
        **kwargs: Any,
    ) -> PipelineResult:
        """Check a tool call for dangerous actions.

        Auto-fills active_security_rules from SecurityContextProvider.
        """
        ctx = GuardContext(
            tool_name=tool_name,
            tool_args=tool_args,
            session_id=session_id,
            integration_mode=self._integration_mode(),
            **kwargs,
        )
        return self.shield.check_sync(ctx, pipeline_kind="egress")

    def check_output(
        self,
        text: str,
        session_id: str | None = None,
    ) -> PipelineResult:
        """Check output text for credential/PII leaks.

        Args:
            text: The output text to check.
            session_id: Optional session ID for tracking.

        Returns:
            PipelineResult with should_block property.
        """
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": text},
            session_id=session_id,
            integration_mode=self._integration_mode(),
        )
        return self.shield.check_sync(ctx, pipeline_kind="output")

    def _integration_mode(self) -> str:
        return "sdk"

    def _get_security_rules(self, tool_name: str, tool_args: dict[str, Any] | None = None) -> list[str]:
        """Get security rules from SecurityContextProvider for the given tool."""
        ctx_text = self.shield.get_security_context(tool_name, tool_args)
        if not ctx_text:
            return []
        return [line for line in ctx_text.split("\n") if line.strip()]


class AgentAdapter(ABC):
    """Base class for framework-specific security adapters.

    All adapters must implement install() and uninstall() to manage
    their hooks/callbacks in the target framework.
    """

    def __init__(self, shield: Shield) -> None:
        self.shield = shield

    @abstractmethod
    def install(self) -> None:
        """Register hooks/callbacks into the framework."""

    @abstractmethod
    def uninstall(self) -> None:
        """Remove hooks/callbacks from the framework."""
