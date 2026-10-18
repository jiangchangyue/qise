"""ShieldConfig — Pydantic model for shield.yaml configuration.

Supports:
  - Parsing shield.yaml with sensible defaults
  - Environment variable overrides (QISE_*)
  - Per-guard mode configuration (observe/enforce/off)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

from qise.models.router import ModelConfig

# ---------------------------------------------------------------------------
# Config sub-models
# ---------------------------------------------------------------------------


class IntegrationProxyConfig(BaseModel):
    port: int = Field(default=8822, ge=1, le=65535)
    target_agents: list[str] = Field(default_factory=lambda: ["claude_code"])
    auto_takeover: bool = True
    crash_recovery: bool = True
    upstream_url: str = ""
    upstream_api_key: str = ""


class IntegrationConfig(BaseModel):
    mode: Literal["proxy", "mcp", "sdk"] = "sdk"
    proxy: IntegrationProxyConfig = Field(default_factory=IntegrationProxyConfig)
    bridge_port: int = Field(default=8823, ge=1, le=65535)
    mcp: dict[str, Any] = Field(default_factory=dict)


class GuardConfig(BaseModel):
    mode: Literal["observe", "enforce", "off"] = "observe"
    slm_confidence_threshold: float | None = None
    threshold_adjustment_factor: float | None = None
    skip_slm_on_rule_pass: bool | None = None
    slm_override_rule_warn_threshold: float | None = None


class GuardsConfig(BaseModel):
    enabled: list[str] = Field(
        default_factory=lambda: [
            "prompt", "command", "credential", "reasoning",
            "filesystem", "network", "exfil", "resource", "audit",
            "tool_sanity", "context", "output", "tool_policy", "supply_chain",
        ]
    )
    config: dict[str, GuardConfig] = Field(default_factory=dict)


class DataConfig(BaseModel):
    threat_patterns_dir: str = ""
    security_contexts_dir: str = ""
    baselines_dir: str = ""

    def resolve_data_dir(self, subdir: str) -> Path:
        """Resolve a data directory: CWD-relative first, then package-bundled."""
        attr = f"{subdir}_dir"
        configured = getattr(self, attr)
        if configured:
            p = Path(configured)
            if p.is_absolute():
                return p
            # CWD-relative
            cwd_path = Path.cwd() / p
            if cwd_path.exists():
                return cwd_path
        # Fallback: package-bundled data
        try:
            from importlib.resources import files
            pkg_path = files("qise.data") / subdir
            if pkg_path.is_dir():
                return Path(str(pkg_path))
        except Exception:
            pass
        # Last resort: CWD-relative even if it doesn't exist
        return Path.cwd() / (configured or f"./data/{subdir}")


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["json", "text"] = "json"
    output: Literal["stderr", "file"] = "stderr"


class ModelsConfig(BaseModel):
    slm: ModelConfig = Field(default_factory=ModelConfig)
    llm: ModelConfig = Field(default_factory=lambda: ModelConfig(timeout_ms=5000))
    embedding: ModelConfig = Field(default_factory=ModelConfig)


class ToolPolicyProfileConfig(BaseModel):
    """Configuration for a tool policy profile."""

    deny: list[str] = Field(default_factory=list)
    require_approval: list[str] = Field(default_factory=list)
    owner_only: dict[str, list[str]] = Field(default_factory=dict)
    allow_all: bool = False


class ToolPolicyConfigModel(BaseModel):
    """Configuration for tool policy guard."""

    profiles: dict[str, ToolPolicyProfileConfig] = Field(
        default_factory=lambda: {"default": ToolPolicyProfileConfig()}
    )
    active_profile: str = "default"


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------

# Rules-based guards that default to enforce mode (low false-positive rate)
_ENFORCE_BY_DEFAULT = frozenset({
    "command",       # Rules-first: hardwired blacklist
    "filesystem",    # Rules: path protection
    "network",       # Rules: SSRF/CIDR blocking
    "credential",    # Rules: regex pattern matching
    "tool_policy",   # Rules: deny/allow lists
})


class ShieldConfig(BaseModel):
    """Root configuration model for Qise shield.yaml."""

    version: str = "1.0"
    integration: IntegrationConfig = Field(default_factory=IntegrationConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    guards: GuardsConfig = Field(default_factory=GuardsConfig)
    data: DataConfig = Field(default_factory=DataConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    tool_policy: ToolPolicyConfigModel = Field(default_factory=ToolPolicyConfigModel)

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> ShieldConfig:
        """Load config from a YAML file, then apply environment variable overrides."""
        path = Path(path)
        if path.exists():
            with open(path) as f:
                raw = yaml.safe_load(f) or {}
        else:
            raw = {}

        # Expand ${VAR} references in string values using environment variables
        raw = cls._expand_env_vars(raw)

        config = cls(**raw)
        config._apply_env_overrides()
        return config

    @staticmethod
    def _expand_env_vars(obj: Any) -> Any:
        """Recursively expand ${VAR} references in string values."""
        if isinstance(obj, str):
            return re.sub(
                r"\$\{(\w+)\}",
                lambda m: os.getenv(m.group(1), m.group(0)),
                obj,
            )
        if isinstance(obj, dict):
            return {k: ShieldConfig._expand_env_vars(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [ShieldConfig._expand_env_vars(v) for v in obj]
        return obj

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ShieldConfig:
        """Load config from a dict (useful for tests)."""
        config = cls(**data)
        config._apply_env_overrides()
        return config

    @classmethod
    def default(cls) -> ShieldConfig:
        """Return a config with all defaults (no YAML file needed)."""
        config = cls()
        config._apply_env_overrides()
        return config

    # ------------------------------------------------------------------
    # Environment variable overrides
    # ------------------------------------------------------------------

    def _apply_env_overrides(self) -> None:
        """Override config values from QISE_* environment variables."""
        if val := os.getenv("QISE_INTEGRATION_MODE"):
            self.integration.mode = val  # type: ignore[assignment]

        if val := os.getenv("QISE_PROXY_PORT"):
            self.integration.proxy.port = int(val)
        if val := os.getenv("QISE_PROXY_UPSTREAM_URL"):
            self.integration.proxy.upstream_url = val.rstrip("/")
        if val := os.getenv("QISE_PROXY_UPSTREAM_API_KEY"):
            self.integration.proxy.upstream_api_key = val

        if val := os.getenv("QISE_SLM_BASE_URL"):
            self.models.slm.base_url = val
        if val := os.getenv("QISE_SLM_MODEL"):
            self.models.slm.model = val
        if val := os.getenv("QISE_SLM_API_KEY"):
            self.models.slm.api_key = val

        if val := os.getenv("QISE_LLM_BASE_URL"):
            self.models.llm.base_url = val
        if val := os.getenv("QISE_LLM_MODEL"):
            self.models.llm.model = val
        if val := os.getenv("QISE_LLM_API_KEY"):
            self.models.llm.api_key = val

        if val := os.getenv("QISE_LOG_LEVEL"):
            self.logging.level = val  # type: ignore[assignment]

        if val := os.getenv("QISE_MODE"):
            # Global guard mode override — apply to all guards
            if val not in {"observe", "enforce", "off"}:
                raise ValueError("QISE_MODE must be observe, enforce, or off")
            for name in self.guards.enabled:
                current = self.guards.config.get(name, GuardConfig())
                self.guards.config[name] = current.model_copy(update={"mode": val})

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    def guard_mode(self, guard_name: str) -> str:
        """Return the mode for a specific guard.

        Default by guard type:
          - Rules-based guards (low false-positive rate): enforce
          - AI-first guards (need SLM to be reliable): observe
        Users can override via shield.yaml.
        """
        gc = self.guards.config.get(guard_name)
        if gc is not None:
            return gc.mode
        # Rules-based guards default to enforce — low false-positive rate
        if guard_name in _ENFORCE_BY_DEFAULT:
            return "enforce"
        return "observe"

    def is_guard_enabled(self, guard_name: str) -> bool:
        """True if the guard is in the enabled list and not set to 'off'."""
        if guard_name not in self.guards.enabled:
            return False
        gc = self.guards.config.get(guard_name)
        return gc is None or gc.mode != "off"
