"""ThreatPatternLoader — load YAML threat patterns for guards and models.

Threat patterns serve three purposes:
  1. Few-shot examples for SLM/LLM prompts (attack_examples field)
  2. Rule fast-paths for deterministic detection (rule_signatures field)
  3. Mitigation templates for trust boundary banners (mitigations field)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from qise.data.yaml_loader import load_yaml_file, yaml_files

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class RuleSignature(BaseModel):
    """A deterministic detection rule within a threat pattern."""

    type: str = "regex"  # "regex" | "keyword_in_description" | "length_anomaly"
    pattern: str | None = None
    keywords: list[str] = []
    threshold: int | None = None
    confidence: float = 0.5


class AttackExample(BaseModel):
    """An attack sample usable as a few-shot example for AI models."""

    input: str
    verdict: str  # "malicious" | "suspicious" | "safe"
    reasoning: str = ""


class Mitigation(BaseModel):
    """A recommended mitigation action for a threat pattern."""

    trust_boundary: str | None = None
    action: str  # "isolate" | "hash_baseline" | "source_whitelist"
    banner: str | None = None
    description: str = ""


class ThreatPattern(BaseModel):
    """A complete threat pattern loaded from YAML."""

    id: str = ""
    name: str = ""
    category: str = ""  # "world_to_agent" | "agent_to_world"
    risk_source: str = ""
    failure_mode: str = ""
    real_world_harm: str = ""
    severity: str = "medium"
    attack_examples: list[AttackExample] = []
    rule_signatures: list[RuleSignature] = []
    mitigations: list[Mitigation] = []


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


class ThreatPatternLoader:
    """Load and query YAML threat patterns.

    Usage:
        loader = ThreatPatternLoader(Path("./data/threat_patterns"))
        examples = loader.get_examples_for_prompt("world_to_agent", count=3)
        banners = loader.get_isolation_banners("tool_result")
    """

    def __init__(self, pattern_dir: Path | str | None = None) -> None:
        self._patterns: list[ThreatPattern] = []
        if pattern_dir is not None:
            self.load_all(Path(pattern_dir))

    def load_all(self, pattern_dir: Path) -> None:
        """Load all YAML files from the pattern directory."""
        for yaml_file in yaml_files(pattern_dir):
            try:
                raw = load_yaml_file(yaml_file)
                if raw and isinstance(raw, dict):
                    self._patterns.append(ThreatPattern(**raw))
            except Exception:
                pass  # Skip malformed files

    @property
    def patterns(self) -> list[ThreatPattern]:
        return self._patterns

    def get_examples_for_prompt(
        self, category: str, count: int = 3
    ) -> list[dict[str, Any]]:
        """Return few-shot attack examples for a given category."""
        examples: list[dict[str, Any]] = []
        for p in self._patterns:
            if p.category != category:
                continue
            for ex in p.attack_examples:
                examples.append(
                    {"input": ex.input, "verdict": ex.verdict, "reasoning": ex.reasoning}
                )
                if len(examples) >= count:
                    return examples
        return examples

    def get_rule_signatures(self, category: str) -> list[RuleSignature]:
        """Return all rule signatures for a given category or risk_source."""
        sigs: list[RuleSignature] = []
        for p in self._patterns:
            if p.category != category and p.risk_source != category:
                continue
            sigs.extend(p.rule_signatures)
        return sigs

    def get_mitigations(self, risk_source: str) -> list[Mitigation]:
        """Return mitigations for a specific risk source."""
        mits: list[Mitigation] = []
        for p in self._patterns:
            if p.risk_source != risk_source:
                continue
            mits.extend(p.mitigations)
        return mits

    def get_isolation_banners(self, trust_boundary: str) -> list[str]:
        """Return isolation banner text for a trust boundary."""
        banners: list[str] = []
        for p in self._patterns:
            for m in p.mitigations:
                if m.trust_boundary == trust_boundary and m.action == "isolate" and m.banner:
                    banners.append(m.banner)
        return banners
