"""Hermes adapter — wraps tool functions with Qise Shield security checks.

NOTE: Hermes-ai (hermes-ai on PyPI) does NOT have a plugin/hook system.
The original adapter assumed register_hook() and PluginContext, which do
not exist in Hermes 0.3.20.

This adapter now uses tool wrapping: before passing tools to
Agent(tools=[...]), wrap each one with Qise security checks.

For full protection (including LLM output checks), use **Proxy mode**:
Hermes uses LlamaIndex under the hood, which respects the OPENAI_API_BASE
environment variable. Set it to the Qise proxy endpoint.

BLOCK strategy: Raise RuntimeError when a tool call is blocked.

Usage:
    from qise import Shield
    from qise.adapters.hermes import QiseHermesAdapter

    shield = Shield.from_config()
    adapter = QiseHermesAdapter(shield)

    # Wrap tools before passing to Hermes Agent
    safe_tools = [adapter.wrap_tool(tool) for tool in my_tools]
    agent = Agent(provider="openai", model="gpt-4", tools=safe_tools)

    # Or for full protection, use Proxy mode:
    # export OPENAI_API_BASE=http://localhost:8822/v1
"""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any

from qise.adapters.base import (
    AgentAdapter,
    EgressCheckMixin,
    IngressCheckMixin,
    blocked_message,
    tool_arguments,
)
from qise.core.shield import Shield

logger = logging.getLogger("qise.adapters.hermes")


class QiseHermesAdapter(AgentAdapter, EgressCheckMixin, IngressCheckMixin):
    """Hermes adapter that wraps tools with Qise security checks.

    Since Hermes-ai does not have a plugin/hook system, this adapter
    wraps tool functions before they are passed to Agent(tools=[...]).

    For full protection including LLM output checks, use Proxy mode.
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._installed = False

    def install(self) -> None:
        """Mark adapter as installed."""
        self._installed = True
        logger.info("QiseHermesAdapter installed")

    def uninstall(self) -> None:
        """Mark adapter as uninstalled."""
        self._installed = False
        logger.info("QiseHermesAdapter uninstalled")

    def wrap_tool(self, tool: Callable) -> Callable:
        """Wrap a tool function with Qise security checks.

        Before executing the tool, runs egress checks. If blocked,
        raises RuntimeError instead of executing.

        Args:
            tool: The original tool function.

        Returns:
            Wrapped function that checks security before execution.
        """
        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "unknown")

        @functools.wraps(tool)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            tool_args = tool_arguments(tool, args, kwargs)

            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )

            if result.should_block:
                reason = blocked_message(result)
                logger.warning("Hermes: blocked %s — %s", tool_name, reason)
                raise RuntimeError(reason)

            output = tool(*args, **kwargs)
            return self.protect_tool_result(output, tool_name, self.session_id)

        if inspect.iscoroutinefunction(tool):
            @functools.wraps(tool)
            async def async_wrapped(*args: Any, **kwargs: Any) -> Any:
                result = self.check_tool_call(
                    tool_name, tool_arguments(tool, args, kwargs), self.session_id,
                )
                if result.should_block:
                    raise RuntimeError(blocked_message(result))
                output = await tool(*args, **kwargs)
                return self.protect_tool_result(output, tool_name, self.session_id)

            async_wrapped.name = tool_name
            return async_wrapped

        wrapped.name = tool_name  # type: ignore[attr-defined]
        return wrapped

    def check_agent_output(self, text: str) -> Any:
        """Check agent output text for credential/PII leaks.

        Since Hermes has no post_llm_call hook, this must be called
        manually by the user after getting the agent's response.
        """
        return super().check_output(text=text, session_id=self.session_id)
