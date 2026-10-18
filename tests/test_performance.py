"""Performance baseline tests — verify latency targets for Qise guard pipeline.

Latency targets:
  - Rule fast-path: <1ms (command guard, credential guard, etc.)
  - Full pipeline (rule-only): <10ms (egress pipeline with all guards)
  - Shield init: <100ms (creating Shield from default config)
  - SecurityContext render: <5ms (template rendering)
  - Ingress pipeline: <10ms (rule-only path)
  - Output pipeline: <10ms (rule-only path)
"""

from __future__ import annotations

import statistics
import time
from math import ceil

from qise.core.models import GuardContext
from qise.core.shield import Shield

# Number of iterations for reliable measurement
_WARMUP = 3
_ITERS = 20


def _measure(func, iters: int = _ITERS, warmup: int = _WARMUP) -> list[float]:
    """Measure function execution time in ms over multiple iterations."""
    # Warmup
    for _ in range(warmup):
        func()
    # Measure
    times: list[float] = []
    for _ in range(iters):
        start = time.perf_counter()
        func()
        elapsed_ms = (time.perf_counter() - start) * 1000
        times.append(elapsed_ms)
    return times


def _report(name: str, times: list[float], budget_ms: float) -> None:
    """Print timing report and assert budget is met (p95)."""
    p50 = statistics.median(times)
    # Nearest-rank percentiles use one-based ranks. With 20 samples, p95
    # is the 19th value; indexing at 19 incorrectly reports the maximum.
    ordered = sorted(times)
    p95 = ordered[ceil(len(times) * 0.95) - 1]
    p99 = ordered[ceil(len(times) * 0.99) - 1]
    print(f"  {name}: p50={p50:.2f}ms, p95={p95:.2f}ms, p99={p99:.2f}ms (budget={budget_ms}ms)")
    assert p95 < budget_ms, f"{name} p95={p95:.2f}ms exceeds budget {budget_ms}ms"


class TestRuleFastPath:
    """Rule-only guards must complete in <1ms."""

    def test_command_guard_dangerous(self) -> None:
        """CommandGuard blocks 'rm -rf /' via rule fast-path."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        times = _measure(lambda: shield.pipeline.run_egress(ctx))
        _report("command_guard_dangerous", times, budget_ms=1.0)

    def test_command_guard_safe(self) -> None:
        """CommandGuard passes 'ls -la' via rule fast-path."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls -la"})
        times = _measure(lambda: shield.pipeline.run_egress(ctx))
        _report("command_guard_safe", times, budget_ms=1.0)

    def test_credential_guard_detection(self) -> None:
        """CredentialGuard detects AWS key via rule fast-path."""
        shield = Shield.from_config()
        ctx = GuardContext(
            tool_name="output_check",
            tool_args={"content": "AWS key: AKIAIOSFODNN7EXAMPLE"},
        )
        times = _measure(lambda: shield.pipeline.run_output(ctx))
        _report("credential_guard_detection", times, budget_ms=1.0)

    def test_filesystem_guard_traversal(self) -> None:
        """FilesystemGuard blocks path traversal via rule fast-path."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="write_file", tool_args={"path": "/etc/passwd"})
        times = _measure(lambda: shield.pipeline.run_egress(ctx))
        _report("filesystem_guard_traversal", times, budget_ms=1.0)

    def test_network_guard_ssrf(self) -> None:
        """NetworkGuard blocks SSRF via rule fast-path."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://169.254.169.254/"})
        times = _measure(lambda: shield.pipeline.run_egress(ctx))
        _report("network_guard_ssrf", times, budget_ms=1.0)


class TestFullPipeline:
    """Full pipeline with all guards must complete in <10ms (rule-only path)."""

    def test_egress_pipeline_safe(self) -> None:
        """Egress pipeline passes safe tool call."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "echo hello"})
        times = _measure(lambda: shield.pipeline.run_egress(ctx))
        _report("egress_pipeline_safe", times, budget_ms=10.0)

    def test_egress_pipeline_blocked(self) -> None:
        """Egress pipeline blocks dangerous tool call."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        times = _measure(lambda: shield.pipeline.run_egress(ctx))
        _report("egress_pipeline_blocked", times, budget_ms=10.0)

    def test_ingress_pipeline_safe(self) -> None:
        """Ingress pipeline passes safe content."""
        shield = Shield.from_config()
        ctx = GuardContext(
            tool_name="search",
            tool_args={"query": "weather today"},
            trust_boundary="user_input",
        )
        times = _measure(lambda: shield.pipeline.run_ingress(ctx))
        _report("ingress_pipeline_safe", times, budget_ms=10.0)

    def test_output_pipeline_safe(self) -> None:
        """Output pipeline passes clean output."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="output_check", tool_args={"content": "Hello world"})
        times = _measure(lambda: shield.pipeline.run_output(ctx))
        _report("output_pipeline_safe", times, budget_ms=10.0)

    def test_output_pipeline_blocked(self) -> None:
        """Output pipeline blocks credential leak."""
        shield = Shield.from_config()
        ctx = GuardContext(
            tool_name="output_check",
            tool_args={"content": "AWS key: AKIAIOSFODNN7EXAMPLE"},
        )
        times = _measure(lambda: shield.pipeline.run_output(ctx))
        _report("output_pipeline_blocked", times, budget_ms=10.0)


class TestShieldInit:
    """Shield initialization must complete in <100ms."""

    def test_shield_from_config(self) -> None:
        """Shield.from_config() with default config."""
        times = _measure(lambda: Shield.from_config())
        _report("shield_init", times, budget_ms=100.0)

    def test_shield_default(self) -> None:
        """Shield() with default config."""
        times = _measure(lambda: Shield())
        _report("shield_default_init", times, budget_ms=100.0)


class TestSecurityContextRender:
    """SecurityContextProvider rendering must complete in <5ms."""

    def test_render_shell_commands(self) -> None:
        """Render security context for shell_commands."""
        shield = Shield.from_config()
        times = _measure(lambda: shield.get_security_context("bash", {"command": "ls"}))
        _report("context_render_shell", times, budget_ms=5.0)

    def test_render_database_write(self) -> None:
        """Render security context for database_write."""
        shield = Shield.from_config()
        times = _measure(lambda: shield.get_security_context("database", {"operation": "write"}))
        _report("context_render_database", times, budget_ms=5.0)

    def test_render_unknown_tool(self) -> None:
        """Render security context for unknown tool (no match)."""
        shield = Shield.from_config()
        times = _measure(lambda: shield.get_security_context("unknown_tool_xyz", {}))
        _report("context_render_unknown", times, budget_ms=5.0)


class TestConcurrentChecks:
    """Verify performance doesn't degrade with many sequential checks."""

    def test_100_sequential_egress_checks(self) -> None:
        """100 sequential egress checks should complete in <500ms total."""
        shield = Shield.from_config()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "echo test"})
        start = time.perf_counter()
        for _ in range(100):
            shield.pipeline.run_egress(ctx)
        total_ms = (time.perf_counter() - start) * 1000
        avg_ms = total_ms / 100
        print(f"  100 egress checks: total={total_ms:.1f}ms, avg={avg_ms:.2f}ms")
        assert total_ms < 500, f"100 checks took {total_ms:.1f}ms (>500ms)"

    def test_100_sequential_ingress_checks(self) -> None:
        """100 sequential ingress checks should complete in <500ms total."""
        shield = Shield.from_config()
        ctx = GuardContext(
            tool_name="search",
            tool_args={"query": "test"},
            trust_boundary="user_input",
        )
        start = time.perf_counter()
        for _ in range(100):
            shield.pipeline.run_ingress(ctx)
        total_ms = (time.perf_counter() - start) * 1000
        avg_ms = total_ms / 100
        print(f"  100 ingress checks: total={total_ms:.1f}ms, avg={avg_ms:.2f}ms")
        assert total_ms < 500, f"100 checks took {total_ms:.1f}ms (>500ms)"
