"""NexAU adapter — routes tool calls through Qise Shield via Middleware hooks.

Uses NexAU's Middleware class for non-invasive integration:
- before_agent: Check agent startup context
- after_agent: Check agent output for leaks
- before_model: Inject SecurityContext into messages
- after_model: Check reasoning + filter dangerous tool calls
- before_tool: Secondary egress check before tool execution
- after_tool: Check tool results for injection

BLOCK strategy:
- after_model: Remove dangerous tool calls from parsed_response.tool_calls list
- before_tool: Raise RuntimeError before tool execution

Usage:
    from qise import Shield
    from qise.adapters.nexau import QiseNexauMiddleware

    shield = Shield.from_config()
    middleware = QiseNexauMiddleware(shield)

    # Register with NexAU Agent
    agent = NexAUAgent(middlewares=[middleware])
"""

from __future__ import annotations

import logging
from typing import Any

from qise.adapters.base import AgentAdapter, EgressCheckMixin, IngressCheckMixin, blocked_message
from qise.core.shield import Shield

logger = logging.getLogger("qise.adapters.nexau")


class QiseNexauMiddleware(AgentAdapter, IngressCheckMixin, EgressCheckMixin):
    """NexAU Middleware that routes all agent actions through Qise Shield.

    Hook mapping:
      before_agent  → Egress: check agent startup args
      after_agent   → Output: check agent output for leaks
      before_model  → Ingress: inject SecurityContext into messages
      after_model   → Egress: check reasoning + filter dangerous tool calls
      before_tool   → Egress: secondary check before tool execution
      after_tool    → Ingress: check tool result for injection
    """

    def __init__(self, shield: Shield, session_id: str | None = None) -> None:
        super().__init__(shield)
        self.session_id = session_id
        self._installed = False

    def install(self) -> None:
        """Mark middleware as installed. NexAU's Agent handles registration."""
        self._installed = True
        logger.info("QiseNexauMiddleware installed")

    def uninstall(self) -> None:
        """Mark middleware as uninstalled."""
        self._installed = False
        logger.info("QiseNexauMiddleware uninstalled")

    # ------------------------------------------------------------------
    # NexAU Middleware hooks
    # ------------------------------------------------------------------

    async def before_agent(self, context: Any) -> None:
        """Hook: Check agent startup context.

        Inspects initial agent args for dangerous configurations.
        """
        if not self._installed:
            return

        agent_args = getattr(context, "args", {}) or {}
        if not agent_args:
            return

        result = self.check_tool_call(
            tool_name="agent_startup",
            tool_args=agent_args if isinstance(agent_args, dict) else {"args": str(agent_args)},
            session_id=self.session_id,
        )
        if result.should_block:
            logger.warning("NexAU: agent startup blocked — %s", result.blocked_by)
            raise RuntimeError(blocked_message(result))

    async def after_agent(self, context: Any) -> None:
        """Hook: Check agent output for credential/PII leaks.

        Inspects the agent's final output text.
        """
        if not self._installed:
            return

        output = getattr(context, "output", "") or getattr(context, "result", "")
        if not output:
            return

        result = self.check_output(
            text=str(output),
            session_id=self.session_id,
        )
        if result.should_block:
            logger.warning("NexAU: agent output blocked — %s", result.blocked_by)
            for key in ("output", "result"):
                if hasattr(context, key):
                    setattr(context, key, blocked_message(result))
            raise RuntimeError(blocked_message(result))

    async def before_model(self, context: Any) -> None:
        """Hook: Inject SecurityContext into messages before model call.

        Adds security rules relevant to the current tool operations
        into the system message of the messages list.
        """
        if not self._installed:
            return

        messages = getattr(context, "messages", [])
        if not messages:
            return

        # Collect tool names from recent messages to determine relevant rules
        tool_names = set()
        for msg in messages:
            if isinstance(msg, dict):
                # Check for tool_use content blocks
                content = msg.get("content", "")
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            tool_names.add(block.get("name", ""))
                # Check for tool calls in OpenAI format
                for tc in msg.get("tool_calls", []):
                    if isinstance(tc, dict):
                        name = tc.get("function", {}).get("name", "")
                        if name:
                            tool_names.add(name)

        if not tool_names:
            return

        # Inject security context for each tool
        from qise.proxy.context_injector import ContextInjector

        injector = ContextInjector(self.shield.context_provider)
        body: dict[str, Any] = {
            "messages": [
                msg if isinstance(msg, dict) else {
                    "role": getattr(msg, "role", "user"),
                    "content": getattr(msg, "content", ""),
                }
                for msg in messages
            ],
        }

        new_body = injector.inject(body, tool_names=list(tool_names))

        # Apply injection to actual messages list
        if new_body["messages"] != body["messages"]:
            for i, new_msg in enumerate(new_body["messages"]):
                if i >= len(messages):
                    if isinstance(messages, list):
                        messages.append(new_msg)
                elif new_msg.get("role") == "system" and isinstance(messages[i], dict):
                    if messages[i].get("content", "") != new_msg.get("content", ""):
                        messages[i]["content"] = new_msg["content"]
            logger.debug("NexAU: security context injected for tools %s", tool_names)

    async def after_model(self, context: Any) -> None:
        """Hook: Check reasoning + filter dangerous tool calls.

        For each tool call in parsed_response.tool_calls:
        - Run egress check
        - Remove dangerous calls from the list

        Also checks reasoning content for manipulation traces.
        """
        if not self._installed:
            return

        # Check reasoning if available
        reasoning = getattr(context, "reasoning", None) or getattr(context, "thinking", None)
        if reasoning:
            result = self.check_tool_call(
                tool_name="reasoning",
                tool_args={"reasoning": str(reasoning)},
                session_id=self.session_id,
                agent_reasoning=str(reasoning),
            )
            if result.should_block:
                logger.warning("NexAU: dangerous reasoning detected")

        # Filter dangerous tool calls
        parsed_response = getattr(context, "parsed_response", None)
        if parsed_response is None:
            return

        tool_calls = getattr(parsed_response, "tool_calls", None)
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
                    "NexAU: blocked tool call %s — %s",
                    tool_name,
                    result.blocked_by,
                )
            else:
                safe_calls.append(tc)

        # Replace tool calls with safe ones only
        tool_calls.clear()
        tool_calls.extend(safe_calls)

    async def before_tool(self, context: Any) -> None:
        """Hook: Secondary egress check before tool execution.

        If blocked, raises before execution rather than calling with empty input.
        """
        if not self._installed:
            return

        tool_name = getattr(context, "tool_name", "") or getattr(context, "name", "")
        tool_input = getattr(context, "tool_input", {}) or getattr(context, "arguments", {})

        if isinstance(tool_input, str):
            import json
            try:
                tool_input = json.loads(tool_input)
            except (json.JSONDecodeError, TypeError):
                tool_input = {"_raw": tool_input}

        result = self.check_tool_call(
            tool_name=tool_name,
            tool_args=tool_input if isinstance(tool_input, dict) else {"input": str(tool_input)},
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning(
                "NexAU: blocked tool %s at execution — %s",
                tool_name,
                result.blocked_by,
            )
            raise RuntimeError(blocked_message(result))

    async def after_tool(self, context: Any) -> None:
        """Hook: Check tool result for injection.

        Runs ingress check on tool output content.
        """
        if not self._installed:
            return

        tool_name = getattr(context, "tool_name", "") or getattr(context, "name", "")
        tool_result = getattr(context, "tool_result", "") or getattr(context, "result", "")

        if not tool_result:
            return

        result = self.check_tool_result(
            content=str(tool_result),
            tool_name=tool_name,
            session_id=self.session_id,
        )

        if result.should_block:
            logger.warning(
                "NexAU: blocked tool result from %s — %s",
                tool_name,
                result.blocked_by,
            )
            for key in ("tool_result", "result"):
                if hasattr(context, key):
                    setattr(context, key, blocked_message(result))
            raise RuntimeError(blocked_message(result))
        if isinstance(tool_result, str) and result.transformed_args is not None:
            content = result.transformed_args.get("content")
            if isinstance(content, str):
                key = "tool_result" if hasattr(context, "tool_result") else "result"
                setattr(context, key, content)
