"""Shield — main entry point for Qise security framework.

Wires together: GuardPipeline, ModelRouter, SecurityContextProvider, ShieldConfig,
ThreatPatternLoader, BaselineManager, and all enabled Guards.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Literal

from qise.core.config import ShieldConfig
from qise.core.event_logger import EventLogger
from qise.core.guard_base import AIGuardBase
from qise.core.metrics import GuardMetrics
from qise.core.models import GuardContext, PipelineResult, ToolCallRecord
from qise.core.pipeline import GuardPipeline
from qise.core.session_tracker import SessionTracker
from qise.data.baseline_manager import BaselineManager
from qise.data.pattern_loader import ThreatPatternLoader

# Guard imports
from qise.guards.audit import AuditGuard
from qise.guards.command import CommandGuard
from qise.guards.context import ContextGuard
from qise.guards.credential import CredentialGuard
from qise.guards.exfil import ExfilGuard
from qise.guards.filesystem import FilesystemGuard
from qise.guards.network import NetworkGuard
from qise.guards.output import OutputGuard
from qise.guards.prompt import PromptGuard
from qise.guards.reasoning import ReasoningGuard
from qise.guards.resource import ResourceGuard
from qise.guards.supply_chain import SupplyChainGuard
from qise.guards.tool_policy import ToolPolicyGuard, ToolPolicyProfile
from qise.guards.tool_sanity import ToolSanityGuard
from qise.models.router import ModelRouter
from qise.providers.security_context import SecurityContextProvider

# Guard name → factory class mapping
_GUARD_FACTORIES: dict[str, type[AIGuardBase]] = {
    "prompt": PromptGuard,
    "command": CommandGuard,
    "credential": CredentialGuard,
    "reasoning": ReasoningGuard,
    "filesystem": FilesystemGuard,
    "network": NetworkGuard,
    "exfil": ExfilGuard,
    "resource": ResourceGuard,
    "audit": AuditGuard,
    "tool_sanity": ToolSanityGuard,
    "context": ContextGuard,
    "output": OutputGuard,
    "tool_policy": ToolPolicyGuard,
    "supply_chain": SupplyChainGuard,
}


class Shield:
    """Main entry point for Qise security framework.

    Usage:
        shield = Shield.from_config("shield.yaml")
        result = await shield.check_tool_call("bash", {"command": "rm -rf /"})
        context = shield.get_security_context("bash", {"command": "rm -rf /"})
    """

    def __init__(
        self,
        config: ShieldConfig | None = None,
        pipeline: GuardPipeline | None = None,
        model_router: ModelRouter | None = None,
        context_provider: SecurityContextProvider | None = None,
        pattern_loader: ThreatPatternLoader | None = None,
        session_tracker: SessionTracker | None = None,
        event_logger: EventLogger | None = None,
        baseline_manager: BaselineManager | None = None,
    ) -> None:
        self.config = config or ShieldConfig.default()
        self.model_router = model_router or self._build_model_router()
        self.context_provider = context_provider or self._build_context_provider()
        self.pattern_loader = pattern_loader or self._build_pattern_loader()
        self.session_tracker = session_tracker or SessionTracker()
        self.event_logger = event_logger or EventLogger(
            level=self.config.logging.level,
            output=self.config.logging.output,
        )
        self.baseline_manager = baseline_manager or self._build_baseline_manager()

        # Build metrics collector
        self.metrics = GuardMetrics()

        # Build guards and pipeline
        self.pipeline = pipeline or self._build_guards()

        # Wire model router and metrics into all guards
        for guard in self.pipeline.all_guards:
            guard.set_model_router(self.model_router)
            guard.set_metrics(self.metrics)

        # Wire metrics into pipeline
        self.pipeline.set_metrics(self.metrics)

        # Wire example loader into all AI guards
        try:
            from qise.data.prompt_loader import PromptExampleLoader
            example_loader = PromptExampleLoader()
            for guard in self.pipeline.all_guards:
                guard.set_example_loader(example_loader)
        except Exception:
            pass  # Non-critical: examples are optional

    @classmethod
    def from_config(cls, path: str | Path | None = None) -> Shield:
        """Create a Shield from a shield.yaml file.

        If path is None, looks for ./shield.yaml, then falls back to defaults.
        """
        if path is None:
            default_path = Path("shield.yaml")
            path = default_path if default_path.exists() else Path("nonexistent")

        config = ShieldConfig.from_yaml(path)
        return cls(config=config)

    async def check(self, context: GuardContext) -> PipelineResult:
        """Run applicable guard pipelines and return aggregate result."""
        return self.check_sync(context)

    def check_sync(
        self,
        context: GuardContext,
        *,
        pipeline_kind: Literal["ingress", "egress", "output"] | None = None,
    ) -> PipelineResult:
        """Check with configured modes and shared session/security context.

        Synchronous integrations use this entry point rather than bypassing
        mode handling through a raw pipeline. Returned transformations apply
        to the checked content; callers must stop on ``should_block`` first.
        """
        config = self.config
        guard_modes = {
            name: config.guard_mode(name)
            for name in config.guards.enabled
        }

        updates: dict[str, Any] = {}
        if not context.active_security_rules:
            rules = self.context_provider.render_for_agent(
                context.tool_name, context.tool_args, trust_boundary=context.trust_boundary,
            )
            updates["active_security_rules"] = [line for line in rules.splitlines() if line.strip()]
        if context.session_id and not context.tool_call_history:
            updates["tool_call_history"] = self.session_tracker.get_tool_call_history(
                context.session_id,
            )
        context = context.model_copy(update=updates)

        if pipeline_kind is None:
            if context.trust_boundary is not None:
                pipeline_kind = "ingress"
            elif context.tool_name in ("output", "output_check", "content_check"):
                pipeline_kind = "output"
            else:
                pipeline_kind = "egress"
        runner = {
            "ingress": self.pipeline.run_ingress,
            "egress": self.pipeline.run_egress,
            "output": self.pipeline.run_output,
        }[pipeline_kind]
        result = runner(context, guard_modes)

        if context.session_id:
            for guard_result in result.results:
                self.session_tracker.record_guard_result(context.session_id, guard_result)
            if pipeline_kind == "egress":
                self.session_tracker.record_tool_call(
                    context.session_id,
                    ToolCallRecord(
                        tool_name=context.tool_name,
                        tool_args=context.tool_args,
                        verdict=result.verdict,
                        timestamp=time.time(),
                    ),
                )
        return result

    async def check_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        **kwargs: Any,
    ) -> PipelineResult:
        """Convenience method: build GuardContext and run egress check."""
        context = GuardContext(
            tool_name=tool_name,
            tool_args=tool_args,
            **kwargs,
        )
        return self.check_sync(context, pipeline_kind="egress")

    def get_security_context(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
    ) -> str:
        """Get rendered security context for injection into agent observation."""
        return self.context_provider.render_for_agent(tool_name, tool_args)

    def reconfigure(self, config: ShieldConfig) -> None:
        """Hot-reload the shield with a new configuration.

        Rebuilds guards, pipeline, and model router while preserving
        session state. Used by ConfigWatcher for live config updates.

        Args:
            config: New ShieldConfig to apply.
        """
        self.config = config

        # Rebuild model router (may change SLM/LLM endpoints)
        self.model_router = self._build_model_router()

        # Rebuild context provider (may change data paths)
        self.context_provider = self._build_context_provider()

        # Rebuild pattern loader
        self.pattern_loader = self._build_pattern_loader()

        # Rebuild baseline manager
        self.baseline_manager = self._build_baseline_manager()

        # Rebuild guards and pipeline
        self.pipeline = self._build_guards()
        self.pipeline.set_metrics(self.metrics)

        # Wire model router and metrics into all guards
        for guard in self.pipeline.all_guards:
            guard.set_model_router(self.model_router)
            guard.set_metrics(self.metrics)

        # Wire example loader into all AI guards
        try:
            from qise.data.prompt_loader import PromptExampleLoader
            example_loader = PromptExampleLoader()
            for guard in self.pipeline.all_guards:
                guard.set_example_loader(example_loader)
        except Exception:
            pass

        self.event_logger.log_event(
            "config_reloaded",
            {"message": "Shield reconfigured with new config"},
        )

    def get_metrics(self) -> dict:
        """Return current runtime metrics as a dict.

        Includes guard invocation counts, verdict distributions, latency
        stats, and pipeline-level counters.
        """
        return self.metrics.snapshot()

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_model_router(self) -> ModelRouter:
        """Build ModelRouter from config."""
        return ModelRouter(
            slm_config=self.config.models.slm,
            llm_config=self.config.models.llm,
            embedding_config=self.config.models.embedding,
        )

    def _build_context_provider(self) -> SecurityContextProvider:
        """Build SecurityContextProvider from config data path."""
        contexts_dir = self.config.data.resolve_data_dir("security_contexts")
        return SecurityContextProvider(contexts_dir)

    def _build_pattern_loader(self) -> ThreatPatternLoader:
        """Build ThreatPatternLoader from config data path."""
        patterns_dir = self.config.data.resolve_data_dir("threat_patterns")
        return ThreatPatternLoader(patterns_dir)

    def _build_baseline_manager(self) -> BaselineManager:
        """Build BaselineManager from config data path."""
        baselines_dir = self.config.data.resolve_data_dir("baselines")
        return BaselineManager(baselines_dir)

    def _build_guards(self) -> GuardPipeline:
        """Build GuardPipeline with enabled guards from config.

        Pipeline assignment:
          Ingress: prompt, tool_sanity, context, supply_chain
          Egress: reasoning, command, filesystem, network, exfil, resource, tool_policy
          Output: credential, audit, output

        ReasoningGuard is cross-cutting — placed first in egress so its
        threshold_adjustments propagate to subsequent guards.
        """
        pipeline = GuardPipeline()

        for guard_name in self.config.guards.enabled:
            # Keep configured guards available so changing off → enforce does
            # not require rebuilding the Shield. Pipeline execution skips off.
            guard = self._create_guard(guard_name)
            if guard is None:
                continue

            # Assign to pipeline based on guard role
            if guard_name in ("prompt", "tool_sanity", "context", "supply_chain"):
                pipeline.ingress.add_guard(guard)
            elif guard_name == "reasoning":
                # Cross-cutting: placed in egress (runs before command/exfil/etc.)
                # so its threshold_adjustments propagate to subsequent guards.
                # Also added to output for audit correlation.
                pipeline.egress.add_guard(guard)
                pipeline.output.add_guard(guard)
            elif guard_name in ("command", "filesystem", "network", "exfil", "resource", "tool_policy"):
                pipeline.egress.add_guard(guard)
            elif guard_name in ("credential", "audit", "output"):
                pipeline.output.add_guard(guard)
            else:
                # Default: egress for unknown guards
                pipeline.egress.add_guard(guard)

        pipeline.egress.guards.sort(key=lambda guard: guard.name != "reasoning")
        return pipeline

    def _create_guard(self, guard_name: str) -> AIGuardBase | None:
        """Create a guard instance by name, injecting dependencies as needed."""
        factory = _GUARD_FACTORIES.get(guard_name)
        if factory is None:
            return None

        # Pass shared resources to guards that need them
        if guard_name == "prompt":
            guard = factory(pattern_loader=self.pattern_loader)
        elif guard_name == "audit":
            guard = factory(
                session_tracker=self.session_tracker,
                event_logger=self.event_logger,
            )
        elif guard_name == "tool_sanity":
            guard = factory(
                baseline_manager=self.baseline_manager,
                pattern_loader=self.pattern_loader,
            )
        elif guard_name == "context":
            guard = factory(
                baseline_manager=self.baseline_manager,
                pattern_loader=self.pattern_loader,
            )
        elif guard_name == "supply_chain":
            guard = factory(baseline_manager=self.baseline_manager)
        elif guard_name == "tool_policy":
            guard = factory(
                profiles=self._build_tool_policy_profiles(),
                active_profile=self.config.tool_policy.active_profile,
            )
        else:
            guard = factory()

        # Wire per-guard config into guard instance
        gc = self.config.guards.config.get(guard_name)
        if gc is not None:
            if gc.slm_confidence_threshold is not None:
                guard.slm_confidence_threshold = gc.slm_confidence_threshold
            if gc.skip_slm_on_rule_pass is not None:
                guard.skip_slm_on_rule_pass = gc.skip_slm_on_rule_pass
            if gc.slm_override_rule_warn_threshold is not None:
                guard.slm_override_rule_warn_threshold = gc.slm_override_rule_warn_threshold

        return guard

    def _build_tool_policy_profiles(self) -> dict[str, ToolPolicyProfile]:
        """Build tool policy profiles from config."""
        profiles: dict[str, ToolPolicyProfile] = {}
        for name, profile_cfg in self.config.tool_policy.profiles.items():
            profiles[name] = ToolPolicyProfile(
                deny=profile_cfg.deny,
                require_approval=profile_cfg.require_approval,
                owner_only=profile_cfg.owner_only,
                allow_all=profile_cfg.allow_all,
            )
        return profiles
