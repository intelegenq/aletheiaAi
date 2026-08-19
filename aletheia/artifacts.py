"""Artifact storage — persists raw output per engine per run."""

from __future__ import annotations
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")


@dataclass
class ArtifactStore:
    """Stores raw artifacts for a scan run."""
    run_id: str = ""
    base_dir: Path = None  # type: ignore
    artifacts: dict[str, Path] = field(default_factory=dict)

    def __post_init__(self):
        if not self.run_id:
            self.run_id = new_run_id()
        if self.base_dir is None:
            self.base_dir = Path("/mnt/data/results") / self.run_id

    def init(self) -> Path:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        return self.base_dir

    def save_artifact(self, engine: str, content: str, suffix: str) -> Path:
        """Save raw text content as artifact."""
        if not self.base_dir.exists():
            self.init()
        path = self.base_dir / f"{engine}_{suffix}"
        path.write_text(content, encoding="utf-8")
        self.artifacts[engine] = path
        return path

    def save_json(self, engine: str, obj: Any, suffix: str = "raw.json") -> Path:
        """Save object as JSON artifact."""
        if not self.base_dir.exists():
            self.init()
        path = self.base_dir / f"{engine}_{suffix}"
        path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
        self.artifacts[engine] = path
        return path

    def save_run(self, run_manifest: dict) -> Path:
        """Save the full run manifest."""
        if not self.base_dir.exists():
            self.init()
        path = self.base_dir / "run_manifest.json"
        path.write_text(json.dumps(run_manifest, indent=2, default=str), encoding="utf-8")
        return path