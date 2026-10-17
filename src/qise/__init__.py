"""Qise - AI-first runtime security framework for AI agents."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from qise.core.config import ShieldConfig
    from qise.core.models import GuardContext, GuardResult, GuardVerdict, PipelineResult, RiskAttribution, TrustBoundary
    from qise.core.shield import Shield

__version__ = "0.2.0"

__all__ = [
    "Shield",
    "ShieldConfig",
    "GuardContext",
    "GuardResult",
    "GuardVerdict",
    "PipelineResult",
    "RiskAttribution",
    "TrustBoundary",
    "__version__",
]


def __getattr__(name: str) -> Any:
    """Keep version/help and package discovery free of model/server imports."""
    if name not in __all__ or name == "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = "config" if name == "ShieldConfig" else "shield" if name == "Shield" else "models"
    value = getattr(import_module(f"qise.core.{module}"), name)
    globals()[name] = value
    return value
