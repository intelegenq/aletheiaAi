"""Target acquisition, scope parsing, and reproducible artifact identity."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ScopeManifest:
    source: str = "none"
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


@dataclass
class ArtifactIdentity:
    root: str
    file_count: int
    total_bytes: int
    content_sha256: str
    files: list[dict[str, Any]] = field(default_factory=list)
    scope: ScopeManifest = field(default_factory=ScopeManifest)

    def to_dict(self):
        data = asdict(self)
        data["scope"] = self.scope.to_dict()
        return data


class TargetResolutionError(RuntimeError):
    pass


def parse_scope_text(text: str, *, source: str = "text") -> ScopeManifest:
    """Parse conservative scope lines without guessing ambiguous prose."""
    manifest = ScopeManifest(source=source)
    section = "notes"
    for raw in text.splitlines():
        line = raw.strip().strip("-*").strip()
        if not line:
            continue
        lower = line.lower().rstrip(":")
        if any(token in lower for token in ("in scope", "inscope", "included")):
            section = "in_scope"; continue
        if any(token in lower for token in ("out of scope", "out-of-scope", "excluded")):
            section = "out_of_scope"; continue
        if line.startswith(("http://", "https://", "./", "/", "src/", "contracts/")) or "/" in line:
            getattr(manifest, section).append(line)
        elif section == "notes":
            manifest.notes.append(line)
    return manifest


def load_scope(root: Path) -> ScopeManifest:
    for name in ("scope.json", "scope.yaml", "scope.yml", "SCOPE.md", "scope.md"):
        path = root / name
        if not path.is_file():
            continue
        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                return ScopeManifest(source=str(path), in_scope=list(data.get("in_scope", data.get("inScope", []))), out_of_scope=list(data.get("out_of_scope", data.get("outOfScope", []))), notes=list(data.get("notes", [])))
            except (OSError, json.JSONDecodeError) as exc:
                raise TargetResolutionError(f"invalid scope manifest: {path}: {exc}") from exc
        return parse_scope_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))
    return ScopeManifest()


def compute_identity(root: str | Path) -> ArtifactIdentity:
    root = Path(root).resolve()
    if not root.is_dir():
        raise TargetResolutionError(f"target directory not found: {root}")
    digest = hashlib.sha256()
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in {".git", "node_modules", "artifacts", "target"} for part in path.relative_to(root).parts):
            continue
        rel = str(path.relative_to(root)).replace(os.sep, "/")
        data = path.read_bytes()
        file_hash = hashlib.sha256(data).hexdigest()
        digest.update(rel.encode()); digest.update(b"\0"); digest.update(bytes.fromhex(file_hash))
        files.append({"path": rel, "bytes": len(data), "sha256": file_hash})
    return ArtifactIdentity(str(root), len(files), sum(f["bytes"] for f in files), digest.hexdigest(), files, load_scope(root))


def resolve_target(target: str, workspace: str | Path | None = None) -> tuple[Path, ArtifactIdentity]:
    """Resolve a local path or shallow-clone a Git URL into a controlled workspace."""
    candidate = Path(target).expanduser()
    if candidate.is_dir():
        return candidate.resolve(), compute_identity(candidate)
    if not re.match(r"^(https?|git)://|^git@", target):
        raise TargetResolutionError(f"target path does not exist: {target}")
    base = Path(workspace or os.environ.get("ALETHEIA_TARGETS_DIR", "/tmp/aletheia-targets"))
    base.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_.-]", "-", target.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")) or "target"
    destination = base / name
    if not destination.exists():
        result = subprocess.run(["git", "clone", "--depth", "1", target, str(destination)], capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise TargetResolutionError(result.stderr.strip() or "git clone failed")
    return destination.resolve(), compute_identity(destination)
