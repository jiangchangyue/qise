"""BaselineManager — SHA-256 hash baselines for tools, KB, and memory.

Detects unauthorized modifications (rug pulls, tampering) by comparing
current content hashes against previously recorded baselines.

Baselines are persisted as YAML files in baselines_dir/{item_type}_{item_id}.yaml.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from qise.core.baseline_db import BaselineDB
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class BaselineRecord(BaseModel):
    """A recorded hash baseline for a content item."""

    item_id: str
    item_type: str  # "tool" | "kb" | "memory"
    source: str = ""
    content_hash: str
    content_length: int
    registered_at: str = ""
    metadata: dict[str, Any] = {}


class BaselineCheckResult(BaseModel):
    """Result of comparing current content against a baseline."""

    item_id: str
    matches: bool
    previous_hash: str | None = None
    current_hash: str = ""
    changed: bool = False


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class BaselineManager:
    """Manage SHA-256 hash baselines for tools, knowledge bases, and memory.

    Usage:
        mgr = BaselineManager(Path("./data/baselines"))
        mgr.record_tool_baseline("bash", "Execute a bash command")
        result = mgr.check_tool_baseline("bash", "Execute a bash command")
        assert result.matches
    """

    def __init__(self, baselines_dir: Path | str | None = None, db: BaselineDB | None = None) -> None:
        self._baselines_dir = Path(baselines_dir) if baselines_dir else None
        # Reads tolerate a missing directory; _save creates it on the first write.
        # Initializing a Shield should not mutate (possibly bundled) data paths.
        self._db = db  # Optional SQLite persistence; None → YAML-only

    @staticmethod
    def compute_hash(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Tool baselines
    # ------------------------------------------------------------------

    def record_tool_baseline(
        self, tool_name: str, description: str, source: str = "", metadata: dict[str, Any] | None = None
    ) -> BaselineRecord:
        """Record a tool description hash baseline."""
        meta = metadata or {}
        if "description_preview" not in meta:
            meta["description_preview"] = description[:200]
        record = BaselineRecord(
            item_id=tool_name,
            item_type="tool",
            source=source,
            content_hash=self.compute_hash(description),
            content_length=len(description),
            registered_at=datetime.now(UTC).isoformat(),
            metadata=meta,
        )
        self._save(record)
        return record

    def check_tool_baseline(self, tool_name: str, description: str) -> BaselineCheckResult:
        """Check if a tool description matches its recorded baseline."""
        return self._check("tool", tool_name, description)

    # ------------------------------------------------------------------
    # Knowledge base baselines
    # ------------------------------------------------------------------

    def record_kb_baseline(
        self, doc_id: str, content: str, source: str = "", metadata: dict[str, Any] | None = None
    ) -> BaselineRecord:
        """Record a KB document hash baseline."""
        meta = metadata or {}
        if "content_preview" not in meta:
            meta["content_preview"] = content[:200]
        record = BaselineRecord(
            item_id=doc_id,
            item_type="kb",
            source=source,
            content_hash=self.compute_hash(content),
            content_length=len(content),
            registered_at=datetime.now(UTC).isoformat(),
            metadata=meta,
        )
        self._save(record)
        return record

    def check_kb_baseline(self, doc_id: str, content: str) -> BaselineCheckResult:
        """Check if a KB document matches its recorded baseline."""
        return self._check("kb", doc_id, content)

    # ------------------------------------------------------------------
    # Memory baselines
    # ------------------------------------------------------------------

    def record_memory_baseline(
        self, entry_id: str, content: str, source: str = "", metadata: dict[str, Any] | None = None
    ) -> BaselineRecord:
        """Record a memory entry hash baseline."""
        meta = metadata or {}
        if "content_preview" not in meta:
            meta["content_preview"] = content[:200]
        record = BaselineRecord(
            item_id=entry_id,
            item_type="memory",
            source=source,
            content_hash=self.compute_hash(content),
            content_length=len(content),
            registered_at=datetime.now(UTC).isoformat(),
            metadata=meta,
        )
        self._save(record)
        return record

    def check_memory_baseline(self, entry_id: str, content: str) -> BaselineCheckResult:
        """Check if a memory entry matches its recorded baseline."""
        return self._check("memory", entry_id, content)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _filepath(self, item_type: str, item_id: str) -> Path | None:
        """Return the YAML file path for a baseline record."""
        if not self._baselines_dir:
            return None
        safe_id = item_id.replace("/", "_").replace("\\", "_")
        return self._baselines_dir / f"{item_type}_{safe_id}.yaml"

    def _save(self, record: BaselineRecord) -> None:
        """Persist a baseline record to YAML and optionally to SQLite."""
        # SQLite first (more durable)
        if self._db is not None:
            self._save_to_db(record)

        # Also save to YAML if baselines_dir is set
        filepath = self._filepath(record.item_type, record.item_id)
        if filepath is None:
            return
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            yaml.safe_dump(record.model_dump(), f, default_flow_style=False)

    def _save_to_db(self, record: BaselineRecord) -> None:
        """Save a baseline record to SQLite."""
        preview = ""
        if record.item_type == "tool":
            preview = record.metadata.get("description_preview", "")
            self._db.record_tool_baseline(record.item_id, record.content_hash, preview, record.registered_at)
        elif record.item_type == "kb":
            preview = record.metadata.get("content_preview", "")
            self._db.record_kb_baseline(record.item_id, record.content_hash, preview, record.registered_at)
        elif record.item_type == "memory":
            preview = record.metadata.get("content_preview", "")
            self._db.record_memory_baseline(record.item_id, record.content_hash, preview, record.registered_at)

    def _load(self, item_type: str, item_id: str) -> BaselineRecord | None:
        """Load a baseline record from YAML, falling back to SQLite."""
        # Try YAML first
        filepath = self._filepath(item_type, item_id)
        if filepath is not None and filepath.exists():
            try:
                with open(filepath) as f:
                    raw = yaml.safe_load(f)
                return BaselineRecord(**raw) if raw else None
            except Exception:
                pass

        # Fallback to SQLite
        if self._db is not None:
            return self._load_from_db(item_type, item_id)

        return None

    def _load_from_db(self, item_type: str, item_id: str) -> BaselineRecord | None:
        """Load a baseline record from SQLite."""
        row = None
        if item_type == "tool":
            row = self._db.check_tool_baseline(item_id)
        elif item_type == "kb":
            row = self._db.check_kb_baseline(item_id)
        elif item_type == "memory":
            row = self._db.check_memory_baseline(item_id)

        if row is None:
            return None

        hash_key = "description_hash" if item_type == "tool" else "content_hash"
        return BaselineRecord(
            item_id=item_id,
            item_type=item_type,
            content_hash=row.get(hash_key, ""),
            content_length=0,
            registered_at=row.get("recorded_at", ""),
        )

    def _check(self, item_type: str, item_id: str, content: str) -> BaselineCheckResult:
        """Compare current content against stored baseline."""
        current_hash = self.compute_hash(content)
        previous = self._load(item_type, item_id)

        if previous is None:
            # No baseline recorded — not a match, but not "changed" either
            return BaselineCheckResult(
                item_id=item_id,
                matches=False,
                previous_hash=None,
                current_hash=current_hash,
                changed=False,
            )

        matches = previous.content_hash == current_hash
        return BaselineCheckResult(
            item_id=item_id,
            matches=matches,
            previous_hash=previous.content_hash,
            current_hash=current_hash,
            changed=not matches,
        )
