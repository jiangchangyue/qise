"""Tests for Round 9 new adapters — NexAU, LangGraph, OpenAI Agents SDK.

Uses mock objects instead of real framework dependencies.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from qise.adapters.langgraph import QiseLangGraphWrapper
from qise.adapters.nexau import QiseNexauMiddleware
from qise.adapters.openai_agents import QiseOpenAIAgentsGuardrails
from qise.core.shield import Shield

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def shield() -> Shield:
    return Shield.from_config()


# ---------------------------------------------------------------------------
# NexAU Adapter Tests
# ---------------------------------------------------------------------------


class TestNexauMiddleware:

    def test_install_uninstall(self, shield: Shield) -> None:
        """Middleware should track install state."""
        mw = QiseNexauMiddleware(shield)
        assert not mw._installed
        mw.install()
        assert mw._installed
        mw.uninstall()
        assert not mw._installed

    @pytest.mark.asyncio
    async def test_after_model_removes_dangerous_tool_calls(self, shield: Shield) -> None:
        """after_model should remove dangerous tool calls from the list."""
        mw = QiseNexauMiddleware(shield)
        mw.install()

        # Create mock tool calls — one safe, one dangerous
        safe_tc = SimpleNamespace(name="bash", arguments={"command": "ls"})
        dangerous_tc = SimpleNamespace(name="bash", arguments={"command": "rm -rf /"})

        parsed_response = SimpleNamespace(tool_calls=[safe_tc, dangerous_tc])
        context = SimpleNamespace(
            parsed_response=parsed_response,
            reasoning=None,
        )

        await mw.after_model(context)

        # dangerous_tc should have been removed
        assert dangerous_tc not in parsed_response.tool_calls
        assert safe_tc in parsed_response.tool_calls

    @pytest.mark.asyncio
    async def test_before_tool_stops_execution_on_block(self, shield: Shield) -> None:
        """A blocked tool must not run with empty or default arguments."""
        mw = QiseNexauMiddleware(shield)
        mw.install()

        context = SimpleNamespace(
            tool_name="bash",
            tool_input={"command": "rm -rf /"},
        )

        with pytest.raises(RuntimeError, match="blocked"):
            await mw.before_tool(context)
        assert context.tool_input == {"command": "rm -rf /"}

    @pytest.mark.asyncio
    async def test_after_tool_checks_result(self, shield: Shield) -> None:
        """after_tool should check tool result for injection."""
        mw = QiseNexauMiddleware(shield)
        mw.install()

        # Safe tool result — should not raise
        context = SimpleNamespace(
            tool_name="bash",
            tool_result="file1.txt\nfile2.txt",
        )
        await mw.after_tool(context)
        # No exception means pass

    @pytest.mark.asyncio
    async def test_not_installed_skips_hooks(self, shield: Shield) -> None:
        """Hooks should be no-ops when middleware is not installed."""
        mw = QiseNexauMiddleware(shield)
        # Not installed — hooks should return immediately

        context = SimpleNamespace(
            tool_name="bash",
            tool_input={"command": "rm -rf /"},
        )
        await mw.before_tool(context)
        # tool_input should not be modified
        assert context.tool_input == {"command": "rm -rf /"}

    @pytest.mark.asyncio
    async def test_before_agent_checks_args(self, shield: Shield) -> None:
        """before_agent should check agent startup args."""
        mw = QiseNexauMiddleware(shield)
        mw.install()

        context = SimpleNamespace(args={"workspace": "/tmp"})
        await mw.before_agent(context)
        # Safe args — no exception


# ---------------------------------------------------------------------------
# LangGraph Adapter Tests
# ---------------------------------------------------------------------------


class TestLangGraphWrapper:

    def test_install_uninstall(self, shield: Shield) -> None:
        """Wrapper should track install state."""
        wrapper = QiseLangGraphWrapper(shield)
        assert not wrapper._installed
        wrapper.install()
        assert wrapper._installed
        wrapper.uninstall()
        assert not wrapper._installed

    def test_wrap_tool_call_passes_safe(self, shield: Shield) -> None:
        """Wrapped tool should execute when check passes."""
        wrapper = QiseLangGraphWrapper(shield)

        def my_tool(directory: str = ".") -> str:
            return f"listing {directory}"

        wrapped = wrapper.wrap_tool_call(my_tool)
        # "ls" equivalent — should pass
        result = wrapped(directory="/tmp")
        assert result == "listing /tmp"

    def test_wrap_tool_call_blocks_dangerous(self, shield: Shield) -> None:
        """Wrapped tool should raise when check blocks."""
        wrapper = QiseLangGraphWrapper(shield)

        def my_tool(command: str = "") -> str:
            return f"ran {command}"

        my_tool.name = "bash"
        wrapped = wrapper.wrap_tool_call(my_tool)

        with pytest.raises((RuntimeError, Exception)):
            wrapped(command="rm -rf /")

    @pytest.mark.asyncio
    async def test_awrap_tool_call_passes_safe(self, shield: Shield) -> None:
        """Async wrapped tool should execute when check passes."""
        wrapper = QiseLangGraphWrapper(shield)

        async def my_async_tool(path: str = ".") -> str:
            return f"read {path}"

        wrapped = wrapper.awrap_tool_call(my_async_tool)
        result = await wrapped(path="/tmp/test")
        assert result == "read /tmp/test"

    @pytest.mark.asyncio
    async def test_awrap_tool_call_blocks_dangerous(self, shield: Shield) -> None:
        """Async wrapped tool should raise when check blocks."""
        wrapper = QiseLangGraphWrapper(shield)

        async def my_async_tool(command: str = "") -> str:
            return f"ran {command}"

        my_async_tool.name = "bash"
        wrapped = wrapper.awrap_tool_call(my_async_tool)

        with pytest.raises((RuntimeError, Exception)):
            await wrapped(command="rm -rf /")

    def test_pre_model_hook_injects_context(self, shield: Shield) -> None:
        """qise_pre_model_hook should inject security context when tool_calls present."""
        wrapper = QiseLangGraphWrapper(shield)

        # State without tool_calls → should return empty dict
        state_no_tools = {
            "messages": [
                {"role": "user", "content": "List files"},
            ],
        }
        result = wrapper.qise_pre_model_hook(state_no_tools)
        assert result == {}  # No tool calls → nothing to inject

        # State with tool_calls → should inject context
        state_with_tools = {
            "messages": [
                {"role": "user", "content": "List files"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "bash"}, "id": "tc1"},
                ]},
            ],
        }
        result = wrapper.qise_pre_model_hook(state_with_tools)
        # Should return a dict with messages or llm_input_messages
        assert "messages" in result or "llm_input_messages" in result


# ---------------------------------------------------------------------------
# OpenAI Agents SDK Adapter Tests
# ---------------------------------------------------------------------------


class TestOpenAIAgentsGuardrails:

    def test_install_uninstall(self, shield: Shield) -> None:
        """Guardrails should track install state."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)
        assert not guardrails._installed
        guardrails.install()
        assert guardrails._installed
        guardrails.uninstall()
        assert not guardrails._installed

    @pytest.mark.asyncio
    async def test_input_guardrail_safe(self, shield: Shield) -> None:
        """input_guardrail should pass safe user input."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        result = await guardrails.input_guardrail(None, "What is the weather?")
        # GuardrailFunctionOutput or dict depending on SDK availability
        triggered = result.tripwire_triggered if hasattr(result, "tripwire_triggered") else result["tripwire_triggered"]
        assert triggered is False

    @pytest.mark.asyncio
    async def test_output_guardrail_safe(self, shield: Shield) -> None:
        """output_guardrail should pass safe agent output."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        result = await guardrails.output_guardrail(None, "The weather is sunny.")
        triggered = result.tripwire_triggered if hasattr(result, "tripwire_triggered") else result["tripwire_triggered"]
        assert triggered is False

    @pytest.mark.asyncio
    async def test_tool_input_guardrail_blocks_dangerous(self, shield: Shield) -> None:
        """tool_input_guardrail should block dangerous tool calls."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        result = await guardrails.tool_input_guardrail(
            None,
            tool_name="bash",
            tool_args={"command": "rm -rf /"},
        )
        triggered = result.tripwire_triggered if hasattr(result, "tripwire_triggered") else result["tripwire_triggered"]
        assert triggered is True

    @pytest.mark.asyncio
    async def test_tool_input_guardrail_passes_safe(self, shield: Shield) -> None:
        """tool_input_guardrail should pass safe tool calls."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        result = await guardrails.tool_input_guardrail(
            None,
            tool_name="bash",
            tool_args={"command": "ls"},
        )
        triggered = result.tripwire_triggered if hasattr(result, "tripwire_triggered") else result["tripwire_triggered"]
        assert triggered is False

    @pytest.mark.asyncio
    async def test_tool_output_guardrail_safe(self, shield: Shield) -> None:
        """tool_output_guardrail should pass safe tool results."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        result = await guardrails.tool_output_guardrail(
            None,
            tool_name="bash",
            tool_result="file1.txt\nfile2.txt",
        )
        triggered = result.tripwire_triggered if hasattr(result, "tripwire_triggered") else result["tripwire_triggered"]
        assert triggered is False

    @pytest.mark.asyncio
    async def test_wrap_tool_function(self, shield: Shield) -> None:
        """wrap_tool should wrap a plain callable with guardrail checks."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        def my_read_tool(path: str = "") -> str:
            return f"contents of {path}"

        wrapped = guardrails.wrap_tool(my_read_tool)
        assert callable(wrapped)

    @pytest.mark.asyncio
    async def test_input_guardrail_with_message_list(self, shield: Shield) -> None:
        """input_guardrail should handle message list format."""
        guardrails = QiseOpenAIAgentsGuardrails(shield)

        messages = [
            {"role": "user", "content": "Hello, how are you?"},
        ]
        result = await guardrails.input_guardrail(None, messages)
        triggered = result.tripwire_triggered if hasattr(result, "tripwire_triggered") else result["tripwire_triggered"]
        assert triggered is False
