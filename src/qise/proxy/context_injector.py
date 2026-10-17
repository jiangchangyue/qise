"""ContextInjector — injects security context into request system messages.

Uses the SecurityContextProvider to generate scene-aware security rules
based on the tools being used, and injects them into the system message
of the chat completion request.
"""

from __future__ import annotations

import copy
from typing import Any


class ContextInjector:
    """Inject security context into chat completion request messages.

    For each tool referenced in the request (either in tool definitions
    or in assistant tool_calls), renders the matching security context
    and appends it to the system message.

    If no system message exists, one is created.
    """

    def __init__(self, context_provider: Any) -> None:
        """Initialize with a SecurityContextProvider instance.

        Args:
            context_provider: A SecurityContextProvider with loaded templates.
        """
        self._provider = context_provider

    def inject(self, body: dict[str, Any], tool_names: list[str] | None = None) -> dict[str, Any]:
        """Inject security context into the request body.

        Args:
            body: The chat completion request body (will NOT be mutated).
            tool_names: Tool names to generate context for. If None, extracts
                        from the request's tools array.

        Returns:
            A new dict with the security context injected into the system message.
        """
        # Determine which tools to generate context for
        if tool_names is None:
            tool_names = self._extract_tool_names(body)

        if not tool_names:
            return body  # Nothing to inject

        # Generate security context text for each tool
        context_parts: list[str] = []
        for tool_name in tool_names:
            ctx = self._provider.render_for_agent(tool_name)
            if ctx:
                context_parts.append(ctx)

        if not context_parts:
            return body  # No matching templates

        # Build the injection text
        injection = "\n\n".join(context_parts)

        # Deep-copy to avoid mutating the original
        new_body = copy.deepcopy(body)
        messages = new_body.get("messages", [])

        # Find or create the system message
        self._inject_into_messages(messages, injection)
        new_body["messages"] = messages

        return new_body

    def inject_anthropic(self, body: dict[str, Any], tool_names: list[str] | None = None) -> dict[str, Any]:
        """Inject security context into an Anthropic /v1/messages request body.

        Anthropic uses a top-level ``system`` field instead of a system role in
        ``messages``. The field can be a string or an array of text blocks.
        """
        if tool_names is None:
            tool_names = self._extract_anthropic_tool_names(body)

        if not tool_names:
            return body

        context_parts: list[str] = []
        for tool_name in tool_names:
            ctx = self._provider.render_for_agent(tool_name)
            if ctx:
                context_parts.append(ctx)

        if not context_parts:
            return body

        injection = "\n\n".join(context_parts)
        new_body = copy.deepcopy(body)
        system = new_body.get("system")
        if isinstance(system, str):
            new_body["system"] = system + "\n\n" + injection if system else injection
        elif isinstance(system, list):
            system.append({"type": "text", "text": injection})
        elif system is None:
            new_body["system"] = injection
        else:
            new_body["system"] = [
                {"type": "text", "text": str(system)},
                {"type": "text", "text": injection},
            ]
        return new_body

    def inject_responses(self, body: dict[str, Any], tool_names: list[str] | None = None) -> dict[str, Any]:
        """Responses uses a top-level instructions field and flat tool definitions."""
        names = (
            tool_names
            if tool_names is not None
            else [tool.get("name", "") for tool in body.get("tools", []) if tool.get("type") in {"function", "custom"}]
        )
        parts = [self._provider.render_for_agent(name) for name in dict.fromkeys(names) if name]
        injection = "\n\n".join(part for part in parts if part)
        if not injection:
            return body
        new_body = copy.deepcopy(body)
        instructions = new_body.get("instructions") or ""
        new_body["instructions"] = instructions + "\n\n" + injection if instructions else injection
        return new_body

    def _inject_into_messages(self, messages: list[dict[str, Any]], injection: str) -> None:
        """Inject security context text into the message list.

        If a system message already exists, append the injection.
        If not, insert a new system message at the beginning.
        """
        for msg in messages:
            if msg.get("role") == "system":
                # Append to existing system message
                content = msg.get("content", "")
                if isinstance(content, str):
                    msg["content"] = content + "\n\n" + injection
                elif isinstance(content, list):
                    # Multi-part content: add a new text part
                    content.append({"type": "text", "text": injection})
                return

        # No system message found — insert one at the beginning
        messages.insert(0, {"role": "system", "content": injection})

    def _extract_tool_names(self, body: dict[str, Any]) -> list[str]:
        """Extract unique tool names from the request's tools array."""
        names: list[str] = []
        seen: set[str] = set()
        for tool in body.get("tools", []):
            func = tool.get("function", {})
            name = func.get("name", "")
            if name and name not in seen:
                names.append(name)
                seen.add(name)
        return names

    def _extract_anthropic_tool_names(self, body: dict[str, Any]) -> list[str]:
        """Extract unique tool names from Anthropic tool definitions."""
        names: list[str] = []
        seen: set[str] = set()
        for tool in body.get("tools", []):
            if not isinstance(tool, dict):
                continue
            name = tool.get("name", "")
            if name and name not in seen:
                names.append(name)
                seen.add(name)
        return names
