"""Prompt example loader — dynamically load few-shot examples from YAML."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_DEFAULT_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


@dataclass
class PromptExample:
    """A single few-shot example for a guard prompt."""

    id: str
    input_data: dict  # trust_boundary, content, tool_args, etc.
    output_data: dict  # verdict, confidence, risk_source, reasoning
    is_positive: bool  # True = attack detected, False = safe


class PromptExampleLoader:
    """Load few-shot examples from YAML and render into prompt templates.

    Examples are stored in data/prompts/{guard_name}_examples.yaml.
    Each file has a guard name, verdict_space, and list of examples
    with positive (attack) and negative (safe) cases.
    """

    def __init__(self, prompts_dir: Path | None = None) -> None:
        if prompts_dir is None:
            # Default: project data/prompts/ directory
            prompts_dir = _DEFAULT_PROMPTS_DIR
        self.prompts_dir = prompts_dir
        self._cache: dict[str, list[PromptExample]] = {}

    def load_examples(self, guard_name: str) -> list[PromptExample]:
        """Load examples for a specific guard from YAML."""
        if guard_name in self._cache:
            return self._cache[guard_name]

        # Map guard name to file name
        file_map = {
            "prompt": "prompt_guard_examples.yaml",
            "exfil": "exfil_guard_examples.yaml",
            "reasoning": "reasoning_guard_examples.yaml",
            "audit": "audit_guard_examples.yaml",
            "command": "command_guard_examples.yaml",
            "resource": "resource_guard_examples.yaml",
        }

        filename = file_map.get(guard_name, f"{guard_name}_guard_examples.yaml")
        filepath = self.prompts_dir / filename

        if not filepath.exists():
            self._cache[guard_name] = []
            return []

        with open(filepath) as f:
            data = yaml.safe_load(f)

        examples: list[PromptExample] = []
        for ex in data.get("examples", []):
            ex_id = ex.get("id", "unknown")
            is_positive = "POS" in ex_id

            examples.append(PromptExample(
                id=ex_id,
                input_data=ex.get("input", {}),
                output_data=ex.get("output", {}),
                is_positive=is_positive,
            ))

        self._cache[guard_name] = examples
        return examples

    def select_diverse_examples(
        self,
        examples: list[PromptExample],
        max_positive: int = 2,
        max_negative: int = 2,
    ) -> list[PromptExample]:
        """Select diverse examples covering different risk_sources and trust_boundaries.

        Prioritizes examples with different risk_source values to maximize coverage.
        """
        positives = [e for e in examples if e.is_positive]
        negatives = [e for e in examples if not e.is_positive]

        # Select diverse positives by risk_source
        selected_pos = self._select_by_diversity(
            positives, max_positive, key=lambda e: e.output_data.get("risk_source", "none"),
        )

        # Select diverse negatives by trust_boundary or tool_name
        selected_neg = self._select_by_diversity(
            negatives, max_negative,
            key=lambda e: e.input_data.get("trust_boundary", e.input_data.get("tool_name", "unknown")),
        )

        return selected_pos + selected_neg

    def render_examples(
        self,
        guard_name: str,
        max_positive: int = 2,
        max_negative: int = 2,
    ) -> str:
        """Render selected examples into prompt text.

        Returns a formatted string with examples that can be appended to a prompt.
        """
        examples = self.load_examples(guard_name)
        if not examples:
            return ""

        selected = self.select_diverse_examples(examples, max_positive, max_negative)
        if not selected:
            return ""

        lines: list[str] = []
        for ex in selected:
            # Format input
            input_parts = []
            for k, v in ex.input_data.items():
                input_parts.append(f"{k}={v}")
            input_str = ", ".join(input_parts)

            # Format output as compact JSON
            output_parts = []
            for k, v in ex.output_data.items():
                output_parts.append(f'"{k}": {v!r}' if isinstance(v, str) else f'"{k}": {v}')
            output_str = "{{" + ", ".join(output_parts) + "}}"

            label = "attack" if ex.is_positive else "safe"
            lines.append(f"### ({label} — {ex.id}):")
            lines.append(f"Input: {input_str}")
            lines.append(f"Output: {output_str}")
            lines.append("")

        return "\n".join(lines)

    def _select_by_diversity(
        self,
        examples: list[PromptExample],
        max_count: int,
        key: callable,
    ) -> list[PromptExample]:
        """Select examples maximizing diversity on the given key."""
        if len(examples) <= max_count:
            return examples

        # Group by key value
        by_key: dict[str, list[PromptExample]] = {}
        for e in examples:
            k = key(e)
            by_key.setdefault(k, []).append(e)

        # Round-robin selection across key values
        selected: list[PromptExample] = []
        key_groups = list(by_key.values())

        while len(selected) < max_count and key_groups:
            remaining: list[list[PromptExample]] = []
            for group in key_groups:
                if group and len(selected) < max_count:
                    selected.append(group.pop(0))
                    if group:
                        remaining.append(group)
                elif group:
                    remaining.append(group)
            key_groups = remaining

        return selected
