"""EventLogger — structured JSON logging for security events.

Outputs to stderr or a file using Python's logging module + json.dumps.
Simple implementation — no external dependencies.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from qise.product.privacy import redact_evidence


class EventLogger:
    """Structured JSON logger for security events.

    Usage:
        logger = EventLogger(level="INFO", output="stderr")
        logger.log_guard_result("session-1", guard_result)
        logger.log_pipeline_result("session-1", pipeline_result)
    """

    def __init__(
        self,
        level: str = "INFO",
        output: str = "stderr",
        log_file: str | None = None,
    ) -> None:
        self._logger = logging.getLogger("qise")
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.handlers.clear()

        handler: logging.StreamHandler
        if output == "file" and log_file:
            handler = logging.FileHandler(log_file)
        else:
            handler = logging.StreamHandler(sys.stderr)

        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def log_guard_result(self, session_id: str, result: Any) -> None:
        """Log a guard result as structured JSON."""
        from qise.core.models import GuardResult

        if not isinstance(result, GuardResult):
            return

        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "guard_result",
            "session_id": session_id,
            "guard_name": result.guard_name,
            "verdict": result.verdict,
            "confidence": result.confidence,
            "latency_ms": result.latency_ms,
            "model_used": result.model_used,
            "message": result.message,
        }
        if result.risk_attribution:
            event["risk_attribution"] = result.risk_attribution.model_dump()

        self._logger.info(json.dumps(redact_evidence(event), default=str))

    def log_pipeline_result(self, session_id: str, result: Any) -> None:
        """Log a pipeline result as structured JSON."""
        from qise.core.models import PipelineResult

        if not isinstance(result, PipelineResult):
            return

        event: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": "pipeline_result",
            "session_id": session_id,
            "verdict": result.verdict,
            "blocked_by": result.blocked_by,
            "guard_count": len(result.results),
            "warnings": result.warnings,
        }
        self._logger.info(json.dumps(redact_evidence(event), default=str))

    def log_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Log a custom event as structured JSON."""
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event_type": event_type,
            **data,
        }
        self._logger.info(json.dumps(redact_evidence(event), default=str))
