"""Nanobot adapter — routes tool calls through Qise Shield via AgentHook.

Uses Nanobot's AgentHook mechanism for non-invasive integration:
- before_execute_tools: check each tool call, remove dangerous ones
- after_iteration: check tool results and output text

BLOCK strategy: Remove dangerous tool calls from the mutable
context.tool_calls list rather than raising exceptions.

Usage:
    from qise import Shield
    from qise.adapters.nanobot import QiseNanobotHook

    shield = Shield.from_config()
    hook = QiseNanobotHook(shield)

    # Option 1: Pass to AgentLoop
    from nanobot.agent.loop import AgentLoop
    loop = AgentLoop(hooks=[hook])

    # Option 2: Pass to Nanobot.run
    from nanobot import Nanobot
    bot = Nanobot()
    await bot.run("Hello", hooks=[hook])
"""

from __future__ import annotations

import logging
from typing import Any

from qise.adapters.base import AgentAdapter, EgressCheckMixin, IngressCheckMixin, blocked_message
from qise.core.shield import Shield

logger = logging.getLogger("qise.adapters.nanobot")



class QiseNanobotHook(AgentAdapter, EgressCheckMixin, IngressCheckMixin):
    """Nanobot AgentHook that routes all tool calls through Qise Shield.

    Integration points:
      - before_execute_tools: intercept and filter dangerous tool calls
      - after_iteration: check tool results for injection, output for leaks

    BLOCK strategy: Remove dangerous tool calls from context.tool_calls
    (mutable list) rather than raising exceptions.

    Note: context.tool_results contains raw return values from tool.execute(),
    NOT objects with .content/.tool_name attributes. Tool names must be obtained
    from context.tool_calls by matching index.
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._installed = False

    def install(self) -> None:
        """Mark hook as installed. Nanobot's AgentLoop handles registration."""
        self._installed = True
        logger.info("QiseNanobotHook installed")

    def uninstall(self) -> None:
        """Mark hook as uninstalled."""
        self._installed = False
        logger.info("QiseNanobotHook uninstalled")

    async def before_execute_tools(self, context: Any) -> None:
        """Intercept tool calls — remove dangerous ones from the list.

        Args:
            context: Nanobot AgentHookContext with:
                - tool_calls: list[ToolCallRequest] (mutable — can remove items)
                - messages: list[dict] of conversation messages
        """
        if not self._installed:
            return

        tool_calls = getattr(context, "tool_calls", [])
        if not tool_calls:
            return

        safe_calls = []
        for tc in tool_calls:
            tool_name = getattr(tc, "name", "") or getattr(tc, "function", "")
            tool_args = getattr(tc, "arguments", {}) or getattr(tc, "params", {})
            if isinstance(tool_args, str):
                import json
                try:
                    tool_args = json.loads(tool_args)
                except (json.JSONDecodeError, TypeError):
                    tool_args = {"_raw": tool_args}

            result = self.check_tool_call(
                tool_name=tool_name,
                tool_args=tool_args,
                session_id=self.session_id,
            )

            if result.should_block:
                logger.warning(
                    "Nanobot: blocked tool call %s — %s",
                    tool_name,
                    result.blocked_by,
                )
            else:
                safe_calls.append(tc)

        # Replace the list with safe calls only
        tool_calls.clear()
        tool_calls.extend(safe_calls)

        # Inject SecurityContext into messages
        self._inject_security_context(context)

    async def after_iteration(self, context: Any) -> None:
        """Check tool results and output text after iteration.

        Tool names are obtained from context.tool_calls (matched by index),
        since context.tool_results contains raw return values (strings, lists)
        without .name or .content attributes.

        Args:
            context: Nanobot AgentHookContext with:
                - tool_calls: list[ToolCallRequest]
                - tool_results: list[Any] (raw return values, matched by index)
                - final_content: str | None (agent's output text)
        """
        if not self._installed:
            return

        # Check tool results for injection
        # tool_results are raw values — get tool names from tool_calls by index
        tool_calls = getattr(context, "tool_calls", [])
        tool_results = getattr(context, "tool_results", [])

        for i, tr in enumerate(tool_results):
            # Get tool name from tool_calls by matching index
            tool_name = ""
            if i < len(tool_calls):
                tool_name = getattr(tool_calls[i], "name", "")

            content = str(tr) if tr else ""
            if content:
                result = self.check_tool_result(
                    content=content,
                    tool_name=tool_name,
                    session_id=self.session_id,
                )
                if result.should_block:
                    logger.warning(
                        "Nanobot: blocked tool result from %s — %s",
                        tool_name,
                        result.blocked_by,
                    )
                    tool_results[i] = blocked_message(result)
                    raise RuntimeError(blocked_message(result))
                if isinstance(tr, str) and result.transformed_args is not None:
                    checked_content = result.transformed_args.get("content")
                    if isinstance(checked_content, str):
                        tool_results[i] = checked_content

        # Check final output for leaks
        final_content = getattr(context, "final_content", None)
        if final_content:
            result = self.check_output(
                text=str(final_content),
                session_id=self.session_id,
            )
            if result.should_block:
                logger.warning("Nanobot: output blocked — %s", result.blocked_by)
                context.final_content = blocked_message(result)
                raise RuntimeError(blocked_message(result))

    def _inject_security_context(self, context: Any) -> None:
        """Inject security context into the messages list.

        Finds tool names from context.tool_calls and injects matching
        security rules into the system message. Mutates context.messages
        in place if possible.
        """
        from qise.proxy.context_injector import ContextInjector

        tool_calls = getattr(context, "tool_calls", [])
        tool_names = []
        for tc in tool_calls:
            name = getattr(tc, "name", "") or getattr(tc, "function", "")
            if name:
                tool_names.append(name)

        if not tool_names:
            return

        injector = ContextInjector(self.shield.context_provider)

        # Build a minimal messages body for the injector
        messages = getattr(context, "messages", [])
        if not messages:
            return

        body: dict[str, Any] = {
            "messages": [
                msg if isinstance(msg, dict) else {
                    "role": getattr(msg, "role", "user"),
                    "content": getattr(msg, "content", ""),
                }
                for msg in messages
            ],
        }

        new_body = injector.inject(body, tool_names=tool_names)

        # Apply the injection to the actual messages list
        if new_body["messages"] != body["messages"]:
            for i, new_msg in enumerate(new_body["messages"]):
                if i >= len(messages):
                    # New system message was added — append it
                    if isinstance(messages, list):
                        messages.append(new_msg)
                elif new_msg.get("role") == "system" and isinstance(messages[i], dict):
                    # Existing system message was modified — update content
                    if messages[i].get("content", "") != new_msg.get("content", ""):
                        messages[i]["content"] = new_msg["content"]
            logger.debug("Nanobot: security context injected for tools %s", tool_names)
