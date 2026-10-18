"""Guard base classes: RuleChecker and AIGuardBase.

The three-layer decision flow (rule fast-path → SLM → LLM → rule fallback)
implements the "never fail-open" principle described in docs/architecture.md.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Literal

from qise.core.models import (
    GuardContext,
    GuardResult,
    GuardVerdict,
    ModelUnavailableError,
    RiskAttribution,
)

if TYPE_CHECKING:
    from qise.models.router import ModelRouter


# ---------------------------------------------------------------------------
# RuleChecker — deterministic rule fallback
# ---------------------------------------------------------------------------


class RuleChecker(ABC):
    """Base class for deterministic rule checks.

    Subclass this to implement rule-only guards (e.g., FilesystemGuard,
    NetworkGuard, CredentialGuard) or rule fallbacks for AI-first guards.
    """

    @abstractmethod
    def check(self, context: GuardContext) -> GuardResult:
        """Run deterministic check. Return PASS or BLOCK for definite results."""

    def check_safe_default(self, context: GuardContext) -> GuardResult:
        """Conservative default when models are unavailable.

        Override to customize, but the default is WARN (safe but not blocking).
        Never return PASS from this method — we are uncertain.
        """
        return GuardResult(
            guard_name=self.__class__.__name__,
            verdict=GuardVerdict.WARN,
            confidence=0.5,
            message="Security models unavailable, applying safe defaults",
            evidence_kind="degraded",
        )


# ---------------------------------------------------------------------------
# AIGuardBase — AI-first guard with three-layer decision
# ---------------------------------------------------------------------------


class AIGuardBase:
    """Base class for all guards.

    Even rule-only guards inherit from this (set primary_strategy="rules").

    Three-layer decision flow:
        Layer 0: Rule fast-path (0ms) — deterministic BLOCK/PASS shortcuts
        Layer 1: SLM semantic screen — model/server-dependent risk classification
        Layer 2: LLM deep analysis (<2s) — full trajectory reasoning
        Layer 3: Rule fallback — never fail-open
    """

    name: str = ""
    primary_strategy: Literal["ai", "rules"] = "ai"
    slm_prompt_template: str = ""
    llm_prompt_template: str | None = None
    rule_fallback: RuleChecker | None = None
    slm_confidence_threshold: float = 0.7
    skip_slm_on_rule_pass: bool = False
    slm_override_rule_warn_threshold: float = 0.65

    # Set by Shield during initialization
    _model_router: ModelRouter | None = None
    _example_loader: Any | None = None

    def set_model_router(self, router: ModelRouter) -> None:
        """Inject the shared ModelRouter instance."""
        self._model_router = router

    def set_example_loader(self, loader: Any) -> None:
        """Inject the PromptExampleLoader for dynamic few-shot examples."""
        self._example_loader = loader

    def set_metrics(self, metrics: Any) -> None:
        """Inject the GuardMetrics instance for recording check results."""
        self._metrics = metrics

    def check(self, context: GuardContext) -> GuardResult:
        """Three-layer decision: rule fast-path → SLM → LLM → rule fallback.

        Key principle: SLM can ESCALATE a rule verdict but never DOWNGRADE it.
        If rules return BLOCK, that's final. If rules return WARN from a
        hard-coded pattern, SLM can override to PASS (the pattern may be
        overly conservative). But if rules return WARN from a trust boundary
        isolation (low confidence), SLM can override it since SLM provides
        actual content analysis.

        In practice: rule WARN with confidence < slm_override_rule_warn_threshold
        can be overridden by SLM PASS (trust boundary isolation is a precaution,
        not a finding). Rule WARN with confidence >= slm_override_rule_warn_threshold
        cannot be overridden.
        """
        result = self._check_impl(context)
        # Record metrics if available
        if hasattr(self, "_metrics") and self._metrics is not None:
            self._metrics.record_guard_check(
                self.name, str(result.verdict), result.latency_ms,
            )
        return result

    def _check_impl(self, context: GuardContext) -> GuardResult:
        """Internal implementation of three-layer decision flow."""
        start = time.monotonic()
        # Layer 0: Deterministic rule fast-path (0ms overhead)
        rule_result: GuardResult | None = None
        rule_warn: GuardResult | None = None
        if self.rule_fallback is not None:
            rule_result = self.rule_fallback.check(context)
            # A model must never waive a denial or required human approval.
            if rule_result.verdict in (GuardVerdict.BLOCK, GuardVerdict.APPROVE):
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            # For rule-only guards, rule PASS always short-circuits
            # For AI-first guards, rule PASS short-circuits only when
            # skip_slm_on_rule_pass is True (trading accuracy for latency)
            # Otherwise SLM gets final say (rules may miss semantic attacks
            # like base64 exfil)
            if rule_result.verdict == GuardVerdict.PASS and (
                self.primary_strategy == "rules" or self.skip_slm_on_rule_pass
            ):
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            # Save WARN result — SLM may or may not be able to downgrade
            if rule_result.verdict == GuardVerdict.WARN:
                rule_warn = rule_result

        # For rule-only guards, stop here after rule fast-path
        if self.primary_strategy == "rules":
            if rule_result is not None:
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            return GuardResult(
                guard_name=self.name,
                verdict=GuardVerdict.PASS,
                latency_ms=_elapsed_ms(start),
            )

        # Layer 1: SLM semantic screen (model/server dependent)
        try:
            slm_result = self._slm_check(context)
            if (
                slm_result.confidence >= self.slm_confidence_threshold
                and slm_result.verdict != GuardVerdict.ESCALATE
            ):
                return self._combine_model_result(slm_result, rule_warn, start)
            # ESCALATE → fall through to LLM
        except ModelUnavailableError:
            pass  # Degrade to LLM or rule fallback

        # Layer 2: LLM deep analysis (<2s)
        if self.llm_prompt_template:
            try:
                llm_result = self._llm_check(context)
                return self._combine_model_result(llm_result, rule_warn, start)
            except ModelUnavailableError:
                pass  # Fall through to rule fallback

        # Layer 3: Rule fallback (never fail-open)
        # Preserve the original finding. Re-running a stateful rule may change
        # its answer (for example, after recording a first-seen hash baseline).
        if rule_result is not None:
            if rule_result.verdict != GuardVerdict.ESCALATE:
                rule_result.latency_ms = _elapsed_ms(start)
                return rule_result
            # An unresolved finding remains visible even without a model.
            return rule_result.model_copy(update={
                "verdict": GuardVerdict.WARN,
                "message": f"{rule_result.message}; security models unavailable for further analysis",
                "latency_ms": _elapsed_ms(start),
            })

        return GuardResult(
            guard_name=self.name,
            verdict=GuardVerdict.WARN,
            confidence=0.5,
            message="Security models unavailable, applying safe defaults",
            evidence_kind="degraded",
            latency_ms=_elapsed_ms(start),
        )

    def _combine_model_result(
        self, result: GuardResult, rule_warn: GuardResult | None, start: float,
    ) -> GuardResult:
        """Apply the same rule precedence to both model stages."""
        if rule_warn is not None:
            if (
                (
                    result.verdict == GuardVerdict.PASS
                    and rule_warn.confidence >= self.slm_override_rule_warn_threshold
                )
                or (rule_warn.evidence_kind == "finding" and result.evidence_kind != "finding")
            ):
                attribution = rule_warn.risk_attribution or RiskAttribution(
                    risk_source=self.name,
                    failure_mode="rule_finding",
                    real_world_harm="unknown",
                    confidence=rule_warn.confidence,
                    reasoning=f"{rule_warn.message}. Model assessment: {result.message}",
                )
                return rule_warn.model_copy(update={
                    "latency_ms": _elapsed_ms(start),
                    "model_used": result.model_used,
                    "risk_attribution": attribution,
                })
            # Isolation or sanitization remains available to callers even when
            # a model clears a precautionary source-trust warning.
            if result.transformed_args is None:
                result.transformed_args = rule_warn.transformed_args
        result.latency_ms = _elapsed_ms(start)
        return result

    def _slm_check(self, context: GuardContext) -> GuardResult:
        """SLM fast-screen stub.

        Constructs prompt from slm_prompt_template, calls ModelRouter.slm_check(),
        and parses the model response into a GuardResult.

        Expected SLM output format (JSON):
            {
                "verdict": "safe" | "suspicious" | "malicious",
                "confidence": 0.0-1.0,
                "risk_source": "...",
                "reasoning": "..."
            }

        Requires: A local SLM (≤4B params) deployed with an OpenAI-compatible
        API endpoint, e.g., AgentDoG-Qwen3-4B via vLLM or Ollama.
        Latency depends on the selected local model and server.
        """
        if self._model_router is None:
            raise ModelUnavailableError("ModelRouter not configured")

        prompt = self._render_prompt(self.slm_prompt_template, context)
        response = self._model_router.slm_check_sync(prompt)
        return self._parse_model_response(response, model_tag="slm")

    def _llm_check(self, context: GuardContext) -> GuardResult:
        """LLM deep analysis stub.

        Constructs prompt from llm_prompt_template with full trajectory,
        calls ModelRouter.llm_deep_analysis(), and parses into GuardResult
        with structured RiskAttribution.

        Expected LLM output format (JSON):
            {
                "verdict": "safe" | "suspicious" | "malicious",
                "confidence": 0.0-1.0,
                "risk_attribution": {
                    "risk_source": "...",
                    "failure_mode": "...",
                    "real_world_harm": "...",
                    "confidence": 0.0-1.0,
                    "reasoning": "..."
                }
            }

        Requires: A larger LLM (8B-70B params) via cloud API or local deployment,
        e.g., Claude Sonnet, GPT-4o-mini, Qwen2.5-72B.
        Target latency: <2s.
        """
        if self._model_router is None:
            raise ModelUnavailableError("ModelRouter not configured")

        if not self.llm_prompt_template:
            raise ModelUnavailableError("No LLM prompt template configured")

        prompt = self._render_prompt(self.llm_prompt_template, context)
        trajectory = context.session_trajectory
        response = self._model_router.llm_deep_analysis_sync(prompt, trajectory)
        return self._parse_model_response(response, model_tag="llm")

    def _render_prompt(self, template: str, context: GuardContext) -> str:
        """Render a prompt template with context variables.

        If the template already contains a '## Examples' section (hardcoded
        few-shot), dynamic examples are NOT appended to avoid duplication.
        Otherwise, dynamic few-shot examples from the YAML library are injected.
        """
        active_security_rules = "\n".join(context.active_security_rules) if context.active_security_rules else "None"
        rendered = template.format(
            tool_name=context.tool_name,
            tool_args=context.tool_args,
            trust_boundary=context.trust_boundary or "unknown",
            trust_level=context.trust_level(),
            session_trajectory=context.session_trajectory,
            tool_call_history=context.tool_call_history,
            iteration_count=context.iteration_count,
            tool_description=context.tool_description or "",
            tool_source=context.tool_source or "",
            agent_reasoning=context.agent_reasoning or "",
            workspace_path=context.workspace_path or "",
            session_id=context.session_id or "",
            user_id=context.user_id or "",
            integration_mode=context.integration_mode,
            active_security_rules=active_security_rules,
        )

        # Inject dynamic few-shot examples if template doesn't already have them
        if "## Examples" not in rendered and self._example_loader is not None:
            try:
                # SLM: max 2+2 examples; LLM: max 4+4
                is_llm = template is self.llm_prompt_template
                max_pos = 4 if is_llm else 2
                max_neg = 4 if is_llm else 2
                examples = self._example_loader.render_examples(
                    self.name, max_positive=max_pos, max_negative=max_neg,
                )
                if examples:
                    rendered = rendered.rstrip() + "\n\n## Dynamic Examples\n\n" + examples
            except Exception:
                pass  # Non-critical: examples are optional enhancement

        return rendered

    def _parse_model_response(
        self, response: Any, model_tag: str = "unknown"
    ) -> GuardResult:
        """Parse a model response dict into a GuardResult.

        The response dict is expected to have:
            verdict: "safe" | "suspicious" | "malicious"
            confidence: float
            risk_source: str (optional)
            reasoning: str (optional)
            risk_attribution: dict (optional, for LLM responses)

        Handles common SLM issues:
          - Markdown-wrapped JSON (```json ... ```)
          - Verdict synonyms (e.g., "dangerous" → "malicious")
          - Confidence out of range (clamped to 0.0-1.0)
        """
        # If response is a string, try to extract JSON from it
        if isinstance(response, str):
            response = self._extract_json_from_text(response)

        if not isinstance(response, dict):
            return GuardResult(
                guard_name=self.name,
                verdict=GuardVerdict.WARN,
                confidence=0.3,
                message=f"Unexpected model response type: {type(response)}",
                evidence_kind="degraded",
                model_used=model_tag,
                risk_attribution=RiskAttribution(
                    risk_source="unknown",
                    failure_mode="invalid_model_response",
                    real_world_harm="unknown",
                    confidence=0.3,
                    reasoning="Security model did not return a structured assessment",
                ),
            )

        raw_verdict = response.get("verdict", "suspicious")
        has_valid_verdict = "verdict" in response and isinstance(raw_verdict, str)
        if not isinstance(raw_verdict, str):
            raw_verdict = "suspicious"

        # Normalize common verdict synonyms
        verdict_synonyms: dict[str, str] = {
            "dangerous": "malicious",
            "harmful": "malicious",
            "unsafe": "malicious",
            "bad": "malicious",
            "benign": "safe",
            "clean": "safe",
            "ok": "safe",
            "normal": "safe",
            "warning": "suspicious",
            "concerned": "suspicious",
            "alarmed": "malicious",
        }
        normalized = raw_verdict.strip().lower()
        normalized = verdict_synonyms.get(normalized, normalized)

        verdict_map = {
            "safe": GuardVerdict.PASS,
            "suspicious": GuardVerdict.WARN,
            "malicious": GuardVerdict.BLOCK,
        }
        verdict = verdict_map.get(normalized, GuardVerdict.WARN)

        # Clamp confidence to [0.0, 1.0]
        try:
            confidence = float(response.get("confidence", 0.5))
            if confidence > 1.0:
                confidence = confidence / 10.0  # Handle 1-10 scale
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.5

        reasoning = str(response.get("reasoning") or "")

        ra_data = response.get("risk_attribution")
        attribution = ra_data if isinstance(ra_data, dict) else response
        try:
            attribution_confidence = max(0.0, min(1.0, float(attribution.get("confidence", confidence))))
        except (ValueError, TypeError):
            attribution_confidence = confidence
        risk_attribution = RiskAttribution(
            risk_source=str(attribution.get("risk_source", response.get("risk_source", "unknown"))),
            failure_mode=str(attribution.get("failure_mode", "unknown")),
            real_world_harm=str(attribution.get("real_world_harm", "unknown")),
            confidence=attribution_confidence,
            reasoning=str(attribution.get("reasoning", reasoning)),
        )

        message = reasoning or f"Model ({model_tag}) assessed as {raw_verdict}"

        return GuardResult(
            guard_name=self.name,
            verdict=verdict,
            confidence=confidence,
            message=message,
            risk_attribution=risk_attribution,
            model_used=model_tag,
            evidence_kind=(
                "finding" if has_valid_verdict and normalized in verdict_map else "degraded"
            ),
        )

    @staticmethod
    def _extract_json_from_text(text: str) -> Any:
        """Extract JSON from text that may contain markdown wrapping.

        Handles:
          - ```json ... ``` markdown code blocks
          - Bare JSON objects
          - Leading/trailing whitespace and text
        """
        import json
        import re

        text = text.strip()

        # Try markdown code block first
        md_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if md_match:
            try:
                return json.loads(md_match.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Try to find a JSON object in the text
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        return text


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _elapsed_ms(start: float) -> int:
    """Return elapsed time in milliseconds since *start*."""
    return int((time.monotonic() - start) * 1000)
