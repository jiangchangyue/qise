"""LangGraph adapter — routes tool calls through Qise Shield via wrapper functions.

Uses LangGraph's create_react_agent for non-invasive integration:
- wrap_tool_call: Wrap a @tool-decorated function with Qise security checks
- awrap_tool_call: Async version of wrap_tool_call
- qise_pre_model_hook: Inject SecurityContext into messages before model call
  (uses llm_input_messages for ephemeral injection — LLM sees it but it
  doesn't pollute the persistent message history)

BLOCK strategy:
- wrap_tool_call / awrap_tool_call: Raise ToolException with block reason
  (ToolException is from langchain_core.tools, not langgraph.tools)

Usage:
    from qise import Shield
    from qise.adapters.langgraph import QiseLangGraphWrapper

    shield = Shield.from_config()
    wrapper = QiseLangGraphWrapper(shield)

    # Wrap tools — preserves StructuredTool type and schema
    safe_tools = [wrapper.wrap_tool_call(tool) for tool in my_tools]

    # Create agent with pre_model_hook for security context injection
    agent = create_react_agent(
        model=llm,
        tools=safe_tools,
        pre_model_hook=wrapper.qise_pre_model_hook,
    )
"""

from __future__ import annotations

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

logger = logging.getLogger("qise.adapters.langgraph")

# Try to import ToolException from the correct location
_ToolException: type | None = None
try:
    from langchain_core.tools import ToolException as _ToolException
except ImportError:
    pass


def _raise_blocked(reason: str) -> None:
    """Raise ToolException if available, otherwise RuntimeError."""
    if _ToolException is not None:
        raise _ToolException(reason)
    raise RuntimeError(reason)


class QiseLangGraphWrapper(AgentAdapter, IngressCheckMixin, EgressCheckMixin):
    """LangGraph tool wrapper that routes tool calls through Qise Shield.

    Integration points:
      - wrap_tool_call: Wraps a StructuredTool or callable with security checks
      - awrap_tool_call: Async version of wrap_tool_call
      - qise_pre_model_hook: Injects SecurityContext into state messages
        (passes as llm_input_messages for ephemeral injection)
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._installed = False

    def install(self) -> None:
        """Mark wrapper as installed."""
        self._installed = True
        logger.info("QiseLangGraphWrapper installed")

    def uninstall(self) -> None:
        """Mark wrapper as uninstalled."""
        self._installed = False
        logger.info("QiseLangGraphWrapper uninstalled")

    # ------------------------------------------------------------------
    # Tool call wrappers
    # ------------------------------------------------------------------

    def wrap_tool_call(self, tool: Any) -> Any:
        """Wrap a @tool-decorated function or StructuredTool with Qise checks.

        For StructuredTool (produced by @tool decorator), creates a new
        StructuredTool with the same schema but a guarded .func.

        For plain callables, wraps with functools.wraps.

        Args:
            tool: The original tool (@tool-decorated, StructuredTool, or callable).

        Returns:
            Wrapped tool with security checks before execution.
        """
        is_base_tool = hasattr(tool, "invoke") and hasattr(tool, "name")

        if is_base_tool:
            return self._wrap_base_tool(tool)
        else:
            return self._wrap_callable(tool)

    def _wrap_base_tool(self, tool: Any) -> Any:
        """Wrap a StructuredTool/BaseTool instance by creating a new StructuredTool."""
        import functools

        original_func = getattr(tool, "func", None) or tool
        tool_name = getattr(tool, "name", "unknown")
        tool_description = getattr(tool, "description", "")
        args_schema = getattr(tool, "args_schema", None)

        # Create guarded function
        @functools.wraps(original_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            tool_args = tool_arguments(original_func, args, kwargs)
            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )
            if result.should_block:
                reason = blocked_message(result)
                logger.warning("LangGraph: blocked %s — %s", tool_name, reason)
                _raise_blocked(reason)

            output = original_func(*args, **kwargs)
            return self.protect_tool_result(output, tool_name, self.session_id)

        # Try to create a new StructuredTool with the guarded func
        try:
            from langchain_core.tools import StructuredTool

            return StructuredTool.from_function(
                func=guarded_func,
                name=tool_name,
                description=tool_description,
                args_schema=args_schema,
            )
        except (ImportError, Exception) as e:
            logger.debug("Could not create StructuredTool, using plain wrapper: %s", e)
            # Fallback: set attributes on the guarded func
            guarded_func.name = tool_name  # type: ignore[attr-defined]
            guarded_func.description = tool_description  # type: ignore[attr-defined]
            return guarded_func

    def _wrap_callable(self, tool: Callable, *, tool_name: str | None = None) -> Callable:
        """Wrap a plain callable with Qise security checks."""
        import functools

        tool_name = tool_name or getattr(tool, "name", None) or getattr(tool, "__name__", "unknown")

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
                logger.warning("LangGraph: blocked %s — %s", tool_name, reason)
                _raise_blocked(reason)

            output = tool(*args, **kwargs)
            return self.protect_tool_result(output, tool_name, self.session_id)

        wrapped.name = tool_name  # type: ignore[attr-defined]
        return wrapped

    def awrap_tool_call(self, tool: Any) -> Any:
        """Wrap an async tool with Qise security checks.

        For StructuredTool, creates a new StructuredTool with guarded coroutine.
        For plain async callables, wraps directly.
        """
        is_base_tool = hasattr(tool, "ainvoke") and hasattr(tool, "name")

        if is_base_tool:
            return self._awrap_base_tool(tool)
        else:
            return self._awrap_callable(tool)

    def _awrap_base_tool(self, tool: Any) -> Any:
        """Wrap a StructuredTool/BaseTool with async guarded function."""
        import functools

        original_func = getattr(tool, "func", None)
        original_coroutine = getattr(tool, "coroutine", None)
        tool_name = getattr(tool, "name", "unknown")
        tool_description = getattr(tool, "description", "")
        args_schema = getattr(tool, "args_schema", None)

        @functools.wraps(original_func or tool)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            tool_args = tool_arguments(original_func or original_coroutine or tool, args, kwargs)
            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )
            if result.should_block:
                reason = blocked_message(result)
                logger.warning("LangGraph: blocked %s — %s", tool_name, reason)
                _raise_blocked(reason)

            if original_coroutine:
                output = await original_coroutine(*args, **kwargs)
            elif original_func:
                output = original_func(*args, **kwargs)
            else:
                output = await tool.ainvoke(tool_args)
            return self.protect_tool_result(output, tool_name, self.session_id)

        # Try to create StructuredTool
        try:
            from langchain_core.tools import StructuredTool

            return StructuredTool.from_function(
                func=self._wrap_callable(original_func, tool_name=tool_name) if original_func else None,
                coroutine=guarded_coroutine,
                name=tool_name,
                description=tool_description,
                args_schema=args_schema,
            )
        except (ImportError, Exception) as e:
            logger.debug("Could not create StructuredTool, using plain wrapper: %s", e)
            guarded_coroutine.name = tool_name  # type: ignore[attr-defined]
            guarded_coroutine.description = tool_description  # type: ignore[attr-defined]
            return guarded_coroutine

    def _awrap_callable(self, tool: Callable) -> Callable:
        """Wrap a plain async callable with Qise security checks."""
        import functools

        tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", "unknown")

        @functools.wraps(tool)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            tool_args = tool_arguments(tool, args, kwargs)

            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )

            if result.should_block:
                reason = blocked_message(result)
                logger.warning("LangGraph: blocked %s — %s", tool_name, reason)
                _raise_blocked(reason)

            output = await tool(*args, **kwargs)
            return self.protect_tool_result(output, tool_name, self.session_id)

        wrapped.name = tool_name  # type: ignore[attr-defined]
        return wrapped

    # ------------------------------------------------------------------
    # Model hooks
    # ------------------------------------------------------------------

    def qise_pre_model_hook(self, state: dict[str, Any]) -> dict[str, Any]:
        """LangGraph pre_model_hook: inject SecurityContext into messages.

        Uses llm_input_messages for ephemeral injection — the LLM sees the
        security context but it doesn't persist in the conversation history.

        Args:
            state: LangGraph state dict with "messages" key.

        Returns:
            State update dict with security context injected.
        """
        messages = state.get("messages", [])
        if not messages:
            return {}

        # Collect tool names from AIMessage.tool_calls (native LangChain attr)
        tool_names = set()
        for msg in messages:
            # LangChain AIMessage has native .tool_calls attribute
            msg_tool_calls = getattr(msg, "tool_calls", None)
            if msg_tool_calls:
                for tc in msg_tool_calls:
                    name = tc.get("name", "") if isinstance(tc, dict) else getattr(tc, "name", "")
                    if name:
                        tool_names.add(name)
            # Fallback: dict format messages
            elif isinstance(msg, dict):
                for tc in msg.get("tool_calls", []):
                    if isinstance(tc, dict):
                        name = tc.get("function", {}).get("name", "")
                        if name:
                            tool_names.add(name)

        if not tool_names:
            return {}

        # Build security context text
        context_parts: list[str] = []
        for tn in tool_names:
            ctx_text = self.shield.get_security_context(tn, None)
            if ctx_text:
                context_parts.append(ctx_text)

        if not context_parts:
            return {}

        security_text = "\n".join(context_parts)

        # Inject as llm_input_messages (ephemeral — LLM sees but doesn't persist)
        try:
            from langchain_core.messages import SystemMessage

            security_msg = SystemMessage(content=security_text)

            # If llm_input_messages exists in state, use it for ephemeral injection
            if "llm_input_messages" in state:
                llm_messages = state.get("llm_input_messages") or list(messages)
                return {
                    "llm_input_messages": [security_msg] + list(llm_messages),
                }

            # Fallback: inject into messages (persistent)
            all_messages = list(messages)
            new_messages = [security_msg] + all_messages
            return {"messages": new_messages}

        except ImportError:
            # No langchain_core — use dict format
            security_msg = {"role": "system", "content": security_text}

            if "llm_input_messages" in state:
                llm_messages = state.get("llm_input_messages") or list(messages)
                return {
                    "llm_input_messages": [security_msg] + list(llm_messages),
                }

            new_messages = [security_msg] + list(messages)
            return {"messages": new_messages}
