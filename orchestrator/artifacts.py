from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from orchestrator.models import ArtifactReference


class ArtifactStore:
    """Persists run artifacts and returns immutable artifact references."""

    def __init__(self, alert_id: str, run_id: str, base_dir: str = "runs"):
        self.alert_id = alert_id
        self.run_id = run_id
        self.base_path = Path(base_dir) / alert_id / run_id
        self.tool_results_path = self.base_path / "tool_results"
        self.meta_path = self.base_path / "meta"
        self.events_path = self.meta_path / "events.jsonl"
        self.tool_results_path.mkdir(parents=True, exist_ok=True)
        self.meta_path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _safe_name(value: str) -> str:
        return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in value)

    def write_json(self, category: str, artifact_name: str, payload: Dict[str, Any]) -> ArtifactReference:
        safe_category = self._safe_name(category)
        safe_name = self._safe_name(artifact_name)
        dest_dir = self.tool_results_path / safe_category
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / f"{safe_name}.json"

        encoded = json.dumps(payload, indent=2, default=str).encode("utf-8")
        path.write_bytes(encoded)

        return ArtifactReference(
            artifact_id=f"{safe_category}:{safe_name}:{self._sha256(encoded)[:12]}",
            path=str(path),
            content_type="application/json",
            sha256=self._sha256(encoded),
            size_bytes=len(encoded),
            created_at=datetime.now(timezone.utc),
        )

    def write_text(self, category: str, artifact_name: str, content: str) -> ArtifactReference:
        safe_category = self._safe_name(category)
        safe_name = self._safe_name(artifact_name)
        dest_dir = self.tool_results_path / safe_category
        dest_dir.mkdir(parents=True, exist_ok=True)
        path = dest_dir / f"{safe_name}.txt"

        encoded = content.encode("utf-8", errors="replace")
        path.write_bytes(encoded)

        return ArtifactReference(
            artifact_id=f"{safe_category}:{safe_name}:{self._sha256(encoded)[:12]}",
            path=str(path),
            content_type="text/plain",
            sha256=self._sha256(encoded),
            size_bytes=len(encoded),
            created_at=datetime.now(timezone.utc),
        )

    def write_run_metadata(self, payload: Dict[str, Any]) -> ArtifactReference:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self.write_json("meta", f"run_metadata_{timestamp}", payload)

    def absolute_base_path(self) -> str:
        return str(self.base_path.resolve())

    def append_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "payload": payload,
        }
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, default=str) + "\n")
