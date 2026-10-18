"""SecurityContextProvider — scene-aware security context injection.

Loads security context DSL templates from YAML, matches them against the
current tool/operation, and renders them into agent-readable text for
injection into the agent's observation/context.

This is a pure rule module with no model dependency — fully implemented.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from qise.data.yaml_loader import load_yaml_file, yaml_files

# ---------------------------------------------------------------------------
# DSL data models
# ---------------------------------------------------------------------------


class SecurityRule(BaseModel):
    """A single security rule within a context template."""

    id: str = ""
    description: str
    severity: str = "medium"
    check_type: str = "rule"  # "rule" | "ai"
    params: dict[str, Any] = {}


class SecurityConstraint(BaseModel):
    """A hard constraint (also enforced by Guards)."""

    type: str
    pattern: str | None = None
    description: str = ""


class SecurityContextTemplate(BaseModel):
    """A security context DSL template loaded from YAML."""

    id: str = ""
    name: str = ""
    trigger: dict[str, Any] = Field(default_factory=dict)
    rules: list[SecurityRule] = Field(default_factory=list)
    constraints: list[SecurityConstraint] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class SecurityContextProvider:
    """Scene-aware security context provider.

    Loads YAML templates from a directory, matches the current tool/operation
    against template triggers, and renders matched rules into agent-readable text.

    Usage:
        provider = SecurityContextProvider(Path("./data/security_contexts"))
        context_text = provider.render_for_agent("bash", {"command": "rm -rf /"})
        # → "[Security Context - Active Rules]\\nscenario: shell_commands\\n..."
    """

    def __init__(self, templates_dir: Path | str | None = None) -> None:
        self._templates: list[SecurityContextTemplate] = []
        if templates_dir is not None:
            self.load_templates(Path(templates_dir))

    def load_templates(self, templates_dir: Path) -> None:
        """Load all YAML templates from a directory."""
        for yaml_file in yaml_files(templates_dir):
            try:
                raw = load_yaml_file(yaml_file)
                if raw and isinstance(raw, dict):
                    self._templates.append(SecurityContextTemplate(**raw))
            except Exception:
                # Skip malformed templates — don't crash the framework
                pass

    @property
    def templates(self) -> list[SecurityContextTemplate]:
        return self._templates

    def match_templates(
        self,
        tool_name: str,
        operation_types: list[str] | None = None,
        trust_boundary: str | None = None,
    ) -> list[SecurityContextTemplate]:
        """Find all templates whose triggers match the current context.

        Matching uses glob patterns on tool_name and optional filters on
        operation_types and trust_boundaries.
        """
        matched = []
        for tmpl in self._templates:
            trigger = tmpl.trigger
            if not trigger:
                continue

            # Match tool_patterns (glob)
            tool_patterns = trigger.get("tool_patterns", [])
            tool_match = any(
                fnmatch.fnmatch(tool_name, pat) for pat in tool_patterns
            )
            if not tool_match:
                continue

            # Match operation_types (optional filter)
            if operation_types:
                tmpl_ops = trigger.get("operation_types", [])
                if tmpl_ops and not any(op in tmpl_ops for op in operation_types):
                    continue

            # Match trust_boundaries (optional filter)
            if trust_boundary:
                tmpl_boundaries = trigger.get("trust_boundaries", [])
                if tmpl_boundaries and trust_boundary not in tmpl_boundaries:
                    continue

            matched.append(tmpl)

        return matched

    def generate_context(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        operation_types: list[str] | None = None,
        trust_boundary: str | None = None,
    ) -> list[SecurityContextTemplate]:
        """Find matching templates. Same as match_templates, semantically named."""
        return self.match_templates(tool_name, operation_types, trust_boundary)

    def render_for_agent(
        self,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        operation_types: list[str] | None = None,
        trust_boundary: str | None = None,
    ) -> str:
        """Render matched security rules into agent-readable text.

        Output format:
            [Security Context - Active Rules]
            scenario: <template_name>
            rules:
              - <rule description> [severity: high]
              - <rule description> [severity: critical]
            constraints:
              - <constraint description>
        """
        templates = self.match_templates(tool_name, operation_types, trust_boundary)
        if not templates:
            return ""

        parts: list[str] = []
        for tmpl in templates:
            section_lines: list[str] = []
            section_lines.append("[Security Context - Active Rules]")
            section_lines.append(f"scenario: {tmpl.name or tmpl.id}")

            if tmpl.rules:
                section_lines.append("rules:")
                for rule in tmpl.rules:
                    severity_tag = f" [severity: {rule.severity}]" if rule.severity else ""
                    section_lines.append(f"  - {rule.description}{severity_tag}")

            if tmpl.constraints:
                section_lines.append("constraints:")
                for constraint in tmpl.constraints:
                    section_lines.append(f"  - {constraint.description}")

            parts.append("\n".join(section_lines))

        return "\n\n".join(parts)
