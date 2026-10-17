"""Tests for GuardPipeline with real guards."""

from pathlib import Path

from qise.core.models import GuardContext, GuardMode, GuardResult, GuardVerdict
from qise.core.pipeline import GuardPipeline, PipelineKind, SubPipeline
from qise.data.pattern_loader import ThreatPatternLoader
from qise.guards.command import CommandGuard
from qise.guards.credential import CredentialGuard
from qise.guards.prompt import PromptGuard


class TestSubPipelineBlockShortCircuit:

    def test_block_stops_pipeline(self) -> None:
        cmd = CommandGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        result = sub.run(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert result.blocked_by == "command"

    def test_pass_continues_pipeline(self) -> None:
        cmd = CommandGuard()
        cred = CredentialGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd, cred])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls -la"})
        result = sub.run(ctx)
        assert result.verdict == GuardVerdict.PASS
        assert len(result.results) == 2

    def test_warn_does_not_short_circuit(self) -> None:
        cmd = CommandGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "sudo apt update"})
        result = sub.run(ctx)
        assert result.verdict == GuardVerdict.WARN
        assert len(result.results) == 1


class TestSubPipelineObserveMode:

    def test_observe_downgrades_block_to_warn(self) -> None:
        cmd = CommandGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        result = sub.run(ctx, guard_modes={"command": GuardMode.OBSERVE})
        assert result.verdict == GuardVerdict.WARN
        assert "[OBSERVE]" in result.warnings[0]

    def test_observe_does_not_affect_pass(self) -> None:
        cmd = CommandGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls -la"})
        result = sub.run(ctx, guard_modes={"command": GuardMode.OBSERVE})
        assert result.verdict == GuardVerdict.PASS


class TestSubPipelineOffMode:

    def test_off_skips_guard(self) -> None:
        cmd = CommandGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        result = sub.run(ctx, guard_modes={"command": GuardMode.OFF})
        assert result.verdict == GuardVerdict.PASS
        assert len(result.results) == 0


class TestSubPipelineGuardError:

    def test_guard_error_blocks_by_default(self) -> None:
        """An enforcing guard crash must stop the checked action."""

        class FailingGuard(CommandGuard):
            name = "failing"

            def check(self, context: GuardContext) -> GuardResult:
                raise RuntimeError("Guard crashed")

        guard = FailingGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [guard])
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls"})
        result = sub.run(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert result.should_block
        assert "error" in result.results[0].message.lower()


class TestGuardPipelineRegistration:

    def test_pipeline_has_three_sub_pipelines(self) -> None:
        pipeline = GuardPipeline()
        assert pipeline.ingress.kind == PipelineKind.INGRESS
        assert pipeline.egress.kind == PipelineKind.EGRESS
        assert pipeline.output.kind == PipelineKind.OUTPUT

    def test_add_guards_to_sub_pipelines(self) -> None:
        pipeline = GuardPipeline()
        loader = ThreatPatternLoader(Path("./data/threat_patterns"))
        prompt = PromptGuard(pattern_loader=loader)
        cmd = CommandGuard()
        cred = CredentialGuard()

        pipeline.ingress.add_guard(prompt)
        pipeline.egress.add_guard(cmd)
        pipeline.output.add_guard(cred)

        assert len(pipeline.all_guards) == 3
        assert pipeline.ingress.guards[0].name == "prompt"
        assert pipeline.egress.guards[0].name == "command"
        assert pipeline.output.guards[0].name == "credential"


class TestGuardPipelineEgress:

    def test_egress_blocks_dangerous_command(self) -> None:
        pipeline = GuardPipeline()
        pipeline.egress.add_guard(CommandGuard())
        ctx = GuardContext(tool_name="bash", tool_args={"command": "rm -rf /"})
        result = pipeline.run_egress(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_egress_passes_safe_command(self) -> None:
        pipeline = GuardPipeline()
        pipeline.egress.add_guard(CommandGuard())
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls -la"})
        result = pipeline.run_egress(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestGuardPipelineOutput:

    def test_output_blocks_credential(self) -> None:
        pipeline = GuardPipeline()
        pipeline.output.add_guard(CredentialGuard())
        ctx = GuardContext(tool_name="output", tool_args={"text": "Key: AKIAIOSFODNN7EXAMPLE"})
        result = pipeline.run_output(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_output_passes_clean_text(self) -> None:
        pipeline = GuardPipeline()
        pipeline.output.add_guard(CredentialGuard())
        ctx = GuardContext(tool_name="output", tool_args={"text": "Normal output text"})
        result = pipeline.run_output(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestGuardPipelineRunAll:

    def test_run_all_ingress_block_short_circuits(self) -> None:
        pipeline = GuardPipeline()
        loader = ThreatPatternLoader(Path("./data/threat_patterns"))
        prompt = PromptGuard(pattern_loader=loader)
        cmd = CommandGuard()
        cred = CredentialGuard()

        pipeline.ingress.add_guard(prompt)
        pipeline.egress.add_guard(cmd)
        pipeline.output.add_guard(cred)

        # Content with invisible unicode should block at ingress
        ctx = GuardContext(tool_name="search", tool_args={"result": "Hello\u200bWorld"})
        result = pipeline.run_all(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_run_all_passes_clean(self) -> None:
        pipeline = GuardPipeline()
        loader = ThreatPatternLoader(Path("./data/threat_patterns"))
        prompt = PromptGuard(pattern_loader=loader)
        cmd = CommandGuard()
        cred = CredentialGuard()

        pipeline.ingress.add_guard(prompt)
        pipeline.egress.add_guard(cmd)
        pipeline.output.add_guard(cred)

        ctx = GuardContext(tool_name="read_file", tool_args={"content": "Normal file content"})
        result = pipeline.run_all(ctx)
        assert result.verdict in (GuardVerdict.PASS, GuardVerdict.WARN)


class TestGuardPipelineWarnCollection:

    def test_multiple_warns_collected(self) -> None:
        """Multiple guards returning WARN should collect all warnings."""
        cmd = CommandGuard()
        cred = CredentialGuard()

        sub = SubPipeline(PipelineKind.EGRESS, [cmd, cred])
        # sudo triggers WARN from CommandGuard, no credentials for CredentialGuard
        ctx = GuardContext(tool_name="bash", tool_args={"command": "sudo ls"})
        result = sub.run(ctx)
        assert result.verdict == GuardVerdict.WARN
        assert len(result.warnings) >= 1  # At least CommandGuard warns

    def test_warn_does_not_override_pass(self) -> None:
        """If first guard passes and second warns, result should be WARN."""
        cmd = CommandGuard()
        cred = CredentialGuard()
        sub = SubPipeline(PipelineKind.EGRESS, [cmd, cred])
        # ls passes CommandGuard, normal text passes CredentialGuard
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls -la", "output": "normal"})
        result = sub.run(ctx)
        assert result.verdict == GuardVerdict.PASS
