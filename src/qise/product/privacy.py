"""Small, dependency-free redaction for local diagnostic evidence."""

from __future__ import annotations

import re
from typing import Any

_SECRET_KEYS = re.compile(r"(?:api.?key|access.?token|auth.?token|password|passwd|secret|authorization|private.?key)$", re.I)
_TOKEN_PATTERNS = (
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?is)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
_ASSIGNMENT = re.compile(
    r'''(?i)((?:["']?)(?:[A-Z0-9_]*(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|PASSWORD|SECRET)|apiKey|authorization)["']?\s*[:=]\s*)(["'])(.*?)\2'''
)


def redact_text(text: str) -> str:
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return _ASSIGNMENT.sub(lambda match: f'{match.group(1)}"[REDACTED]"', text)


def redact_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SECRET_KEYS.search(str(key)) else redact_evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_evidence(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value
