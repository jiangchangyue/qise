"""GuardPipeline — three sub-pipelines with short-circuit execution.

Ingress  (World → Agent): PromptGuard → ToolSanityGuard → ContextGuard → SupplyChainGuard
Egress   (Agent → World): CommandGuard → FilesystemGuard → NetworkGuard → ExfilGuard → ResourceGuard → ToolPolicyGuard
Output   (Audit):         CredentialGuard → AuditGuard → OutputGuard

Execution rules:
  - BLOCK short-circuits: pipeline stops immediately
  - WARN results are collected
  - ESCALATE triggers LLM deep analysis on the guard that returned it
  - ReasoningGuard threshold_adjustments are propagated to subsequent guards
"""

from __future__ import annotations

from copy import copy
from enum import Enum
from typing import Any

from qise.core.guard_base import AIGuardBase
from qise.core.models import (
    GuardContext,
    GuardMode,
    GuardResult,
    GuardVerdict,
    PipelineResult,
)


class PipelineKind(str, Enum):
    INGRESS = "ingress"
    EGRESS = "egress"
    OUTPUT = "output"


class SubPipeline:
    """An ordered sequence of guards forming one pipeline (Ingress/Egress/Output)."""

    def __init__(self, kind: PipelineKind, guards: list[AIGuardBase] | None = None) -> None:
        self.kind = kind
        self.guards: list[AIGuardBase] = guards or []

    def add_guard(self, guard: AIGuardBase) -> None:
        self.guards.append(guard)

    def run(self, context: GuardContext, guard_modes: dict[str, str] | None = None) -> PipelineResult:
        """Execute all guards in order with short-circuit on BLOCK.

        Args:
            context: The guard context to check.
            guard_modes: Optional mapping of guard_name → mode (observe/enforce/off).
                         If a guard is "off", it is skipped.

        Returns:
            PipelineResult with aggregated verdicts and threshold adjustments.
        """
        results: list[GuardResult] = []
        warnings: list[str] = []
        threshold_adjustments: dict[str, float] = {}
        blocked_by: str | None = None
        final_verdict = GuardVerdict.PASS
        guard_modes = guard_modes or {}

        checked_context = context
        transformed_args: dict[str, Any] | None = None

        for guard in self.guards:
            # Skip disabled guards
            mode = guard_modes.get(guard.name, GuardMode.ENFORCE)
            if mode == GuardMode.OFF:
                continue

            # Apply any threshold adjustments from ReasoningGuard
            if guard.name in threshold_adjustments:
                # Threshold changes belong to this check, not a shared guard
                # instance concurrently used by another session.
                guard = copy(guard)
                guard.slm_confidence_threshold = max(
                    0.1, guard.slm_confidence_threshold + threshold_adjustments[guard.name]
                )

            try:
                result = guard.check(checked_context)
                if not isinstance(result, GuardResult) or result.verdict not in (
                    GuardVerdict.PASS, GuardVerdict.WARN,
                    GuardVerdict.BLOCK, GuardVerdict.APPROVE,
                ):
                    raise ValueError("Guard did not return a final security verdict")
            except Exception as exc:
                # A broken enforcing check cannot authorize execution.
                result = GuardResult(
                    guard_name=guard.name,
                    verdict=(GuardVerdict.WARN if mode == GuardMode.OBSERVE else GuardVerdict.BLOCK),
                    confidence=0.3,
                    message=f"Guard error: {exc}",
                    remediation="Retry after the security check is available.",
                )

            if result.verdict == GuardVerdict.APPROVE:
                result = result.model_copy(update={
                    "remediation": "Human approval is required before execution. This check does not grant approval.",
                })

            # Observation reports a pending approval without stopping work.
            if mode == GuardMode.OBSERVE and result.should_block:
                action = "require human approval" if result.verdict == GuardVerdict.APPROVE else "block"
                result = result.model_copy(update={
                    "verdict": GuardVerdict.WARN,
                    "message": f"[OBSERVE] Would {action}: {result.message}",
                })

            results.append(result)

            # Collect threshold adjustments for downstream guards
            if result.threshold_adjustments:
                for gname, delta in result.threshold_adjustments.items():
                    current = threshold_adjustments.get(gname, 0.0)
                    threshold_adjustments[gname] = current + delta

            # Handle verdict
            if result.should_block:
                blocked_by = guard.name
                final_verdict = result.verdict
                break  # Short-circuit

            if result.transformed_args is not None:
                transformed_args = dict(result.transformed_args)
                checked_context = checked_context.model_copy(update={"tool_args": transformed_args})

            if result.verdict == GuardVerdict.WARN:
                warnings.append(f"[{guard.name}] {result.message}")
                # WARN doesn't override PASS → but if any warn, result is at least warn
                if final_verdict == GuardVerdict.PASS:
                    final_verdict = GuardVerdict.WARN

            # ESCALATE: the guard's own _slm_check already handled this
            # by falling through to LLM in AIGuardBase.check().
            # No special pipeline handling needed — the guard returns its
            # final verdict after internal escalation.

        return PipelineResult(
            verdict=final_verdict,
            results=results,
            blocked_by=blocked_by,
            warnings=warnings,
            threshold_adjustments=threshold_adjustments,
            transformed_args=transformed_args,
        )


class GuardPipeline:
    """Full pipeline: Ingress + Egress + Output sub-pipelines.

    The Shield determines which sub-pipelines to run based on the context:
      - Incoming content (user_input, tool_result, etc.) → Ingress
      - Agent action (tool_call, command) → Egress
      - Agent output / tool response → Output
    """

    def __init__(self) -> None:
        self.ingress = SubPipeline(PipelineKind.INGRESS)
        self.egress = SubPipeline(PipelineKind.EGRESS)
        self.output = SubPipeline(PipelineKind.OUTPUT)
        self._metrics: Any = None

    def set_metrics(self, metrics: Any) -> None:
        """Inject the GuardMetrics instance for recording pipeline runs."""
        self._metrics = metrics

    @property
    def all_guards(self) -> list[AIGuardBase]:
        """Return all guards across all sub-pipelines."""
        return self.ingress.guards + self.egress.guards + self.output.guards

    def run_ingress(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run Ingress pipeline for incoming data checks."""
        result = self.ingress.run(context, guard_modes)
        if self._metrics is not None:
            self._metrics.record_pipeline_run("ingress", blocked=result.should_block)
        return result

    def run_egress(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run Egress pipeline for outgoing action checks."""
        result = self.egress.run(context, guard_modes)
        if self._metrics is not None:
            self._metrics.record_pipeline_run("egress", blocked=result.should_block)
        return result

    def run_output(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run Output pipeline for audit and leak detection."""
        result = self.output.run(context, guard_modes)
        if self._metrics is not None:
            self._metrics.record_pipeline_run("output", blocked=result.should_block)
        return result

    def run_all(
        self, context: GuardContext, guard_modes: dict[str, str] | None = None
    ) -> PipelineResult:
        """Run each stage, retaining earlier evidence and content transforms."""
        combined = PipelineResult()
        checked_context = context
        for run in (self.run_ingress, self.run_egress, self.run_output):
            result = run(checked_context, guard_modes)
            combined.results.extend(result.results)
            combined.warnings.extend(result.warnings)
            for name, delta in result.threshold_adjustments.items():
                combined.threshold_adjustments[name] = combined.threshold_adjustments.get(name, 0.0) + delta
            if result.transformed_args is not None:
                combined.transformed_args = result.transformed_args
                checked_context = checked_context.model_copy(update={"tool_args": result.transformed_args})
            if result.should_block:
                combined.verdict = result.verdict
                combined.blocked_by = result.blocked_by
                break
            if result.verdict == GuardVerdict.WARN:
                combined.verdict = GuardVerdict.WARN
        return combined
