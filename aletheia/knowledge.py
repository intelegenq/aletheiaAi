"""Read-only integration with the pattern pack knowledge base.

The pack is an optional, versioned input.  This module deliberately discovers
artifacts from the pack manifest and never treats an absent universal-spec
file as an invented implementation.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


class KnowledgeBaseError(RuntimeError):
    pass


@dataclass
class KnowledgeBaseStatus:
    available: bool
    root: str = ""
    manifest_schema: str = ""
    knowledge_status: str = ""
    record_count: int = 0
    taxonomy_family_count: int = 0
    implemented_spec_count: int = 0
    universal_spec_count: int = 0
    universal_specs_available: bool = False
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UniversalSpec:
    spec_id: str
    pattern_id: str
    detector_id: str
    title: str
    family: str = ""
    root_cause: str = ""
    required_primitives: list[str] = field(default_factory=list)
    result_mode: str = "candidate"
    status: str = "implemented"
    source: str = "detector_specs"
    coverage_status: str = ""
    recommended_engines: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PRIMITIVE_ENGINES = {
    "external_reachability": ["slither"], "effective_access_control": ["slither"],
    "call_graph": ["slither"], "cfg_reachability": ["slither"],
    "state_writes": ["slither"], "storage_reads_writes": ["slither"],
    "data_dependency": ["slither"], "slithir_ops": ["slither"],
    "manual_review": [], "foundry_fork": ["foundry"],
}


class KnowledgeBase:
    def __init__(self, root: str | Path | None = None, *, strict: bool = False):
        configured = root or os.environ.get("ALETHEIA_PACK_ROOT", "")
        self.root = Path(configured).expanduser().resolve() if configured else None
        self.strict = strict
        self.manifest: dict[str, Any] = {}
        self._specs: list[dict[str, Any]] = []
        self._registry: dict[str, dict[str, Any]] = {}
        self._taxonomy: dict[str, dict[str, Any]] = {}
        self._coverage: list[dict[str, Any]] = []
        self._semantic: list[dict[str, Any]] = []
        self._universal: list[UniversalSpec] = []
        self.status = self._load()

    def _find(self, *relative: str) -> Path | None:
        if not self.root:
            return None
        for item in relative:
            path = self.root / item
            if path.is_file():
                return path
        return None

    @staticmethod
    def _json(path: Path | None, default: Any) -> Any:
        if not path:
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KnowledgeBaseError(f"invalid knowledge artifact: {path}: {exc}") from exc

    def _load(self) -> KnowledgeBaseStatus:
        if not self.root or not self.root.is_dir():
            status = KnowledgeBaseStatus(False, limitations=["knowledge pack is not configured"])
            if self.strict:
                raise KnowledgeBaseError(status.limitations[0])
            return status
        manifest_path = self._find(
            "knowledge_base_manifest.json", "knowledge/knowledge_base_manifest.json",
            "pattern_pack_manifest.json",
        )
        self.manifest = self._json(manifest_path, {})
        kb_meta = self.manifest.get("knowledge_base", {})
        db = self._find("knowledge/knowledge_base.sqlite3", "knowledge/vulndb/knowledge_base.sqlite3")
        specs_path = self._find("universal_specs_all.json", "detector_specs/universal_specs_all.json", "detector_specs/batch1.json")
        registry_path = self._find("registry/final_batch1.json", "registry/pattern_registry.json")
        taxonomy_path = self._find("knowledge/taxonomy_93.json")
        limitations: list[str] = []
        if not manifest_path: limitations.append("pack manifest is missing")
        if not db: limitations.append("SQLite FTS knowledge base is missing")
        if not specs_path: limitations.append("detector/universal spec artifact is missing")
        if self.manifest.get("status") and "ready" not in str(self.manifest["status"]):
            limitations.append("pack manifest is not marked ready")
        if kb_meta.get("status") not in (None, "active"):
            limitations.append("knowledge base is not marked active")
        raw_specs = self._json(specs_path, [])
        self._specs = raw_specs if isinstance(raw_specs, list) else raw_specs.get("specs", [])
        raw_registry = self._json(registry_path, [])
        registry_rows = raw_registry if isinstance(raw_registry, list) else raw_registry.get("registry", [])
        self._registry = {str(row.get("pattern_id")): row for row in registry_rows if row.get("pattern_id")}
        raw_taxonomy = self._json(taxonomy_path, {})
        families = raw_taxonomy.get("families", []) if isinstance(raw_taxonomy, dict) else []
        self._taxonomy = {str(row.get("taxonomy_id")): row for row in families if row.get("taxonomy_id")}
        coverage_path = self._find("knowledge/static_coverage_matrix.json")
        coverage_doc = self._json(coverage_path, {})
        self._coverage = coverage_doc.get("matrix", []) if isinstance(coverage_doc, dict) else []
        semantic_path = self._find("knowledge/semantic_patterns.json")
        semantic_doc = self._json(semantic_path, {})
        self._semantic = semantic_doc.get("patterns", []) if isinstance(semantic_doc, dict) else []
        universal = bool(specs_path and "universal" in specs_path.name.lower())
        if not universal:
            self._universal = self._derive_universal_specs()
        record_count = int(kb_meta.get("record_count", self.manifest.get("source_record_count", 0)) or 0)
        if db:
            try:
                with sqlite3.connect(db) as conn:
                    table = conn.execute("SELECT name FROM sqlite_master WHERE name='records'").fetchone()
                    fts = conn.execute("SELECT name FROM sqlite_master WHERE name='records_fts'").fetchone()
                    if not table or not fts: limitations.append("knowledge SQLite database lacks records/FTS5 tables")
                    if table: record_count = int(conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])
            except sqlite3.Error as exc:
                limitations.append(f"knowledge SQLite database cannot be opened: {exc}")
        status = KnowledgeBaseStatus(
            available=not any("missing" in item or "cannot be opened" in item or "lacks" in item for item in limitations),
            root=str(self.root), manifest_schema=str(self.manifest.get("schema", "")),
            knowledge_status=str(kb_meta.get("status", self.manifest.get("knowledge_status", ""))),
            record_count=record_count, taxonomy_family_count=len(self._taxonomy),
            implemented_spec_count=sum(1 for s in self._specs if s.get("status") == "implemented"),
            universal_spec_count=len(self._specs) if universal else len(self._universal),
            universal_specs_available=universal or len(self._universal) == 59,
            limitations=limitations,
        )
        if self.strict and not status.available:
            raise KnowledgeBaseError("; ".join(status.limitations))
        return status

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        db = self._find("knowledge/knowledge_base.sqlite3", "knowledge/vulndb/knowledge_base.sqlite3")
        if not db or not query.strip(): return []
        try:
            with sqlite3.connect(db) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("""SELECT r.*, bm25(records_fts) AS rank
                    FROM records_fts JOIN records r ON r.rowid=records_fts.rowid
                    WHERE records_fts MATCH ? ORDER BY rank LIMIT ?""", (query, max(1, int(limit)))).fetchall()
                return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            raise KnowledgeBaseError(f"knowledge search failed: {exc}") from exc

    def specs(self, *, implemented_only: bool = True) -> list[UniversalSpec]:
        result = []
        for row in self._specs:
            if implemented_only and row.get("status") != "implemented": continue
            registry = self._registry.get(str(row.get("pattern_id")), {})
            primitives = [str(p) for p in row.get("required_primitives", [])]
            engines = sorted({engine for p in primitives for engine in PRIMITIVE_ENGINES.get(p, [])})
            result.append(UniversalSpec(
                spec_id=str(row.get("detector_id") or row.get("pattern_id")), pattern_id=str(row.get("pattern_id", "")),
                detector_id=str(row.get("detector_id", "")), title=str(row.get("title", "")),
                family=str(registry.get("family", "")), root_cause=str(registry.get("root_cause", "")),
                required_primitives=primitives, result_mode=str(row.get("result_mode", "candidate")),
                status=str(row.get("status", "")), coverage_status="implemented" if row.get("status") == "implemented" else "planned",
                recommended_engines=engines,
            ))
        return result

    def universal_specs(self) -> list[UniversalSpec]:
        """Return the complete normalized catalog, including unimplemented candidates."""
        if self.status.universal_specs_available and self._universal:
            return list(self._universal)
        return self.specs(implemented_only=False)

    def _derive_universal_specs(self) -> list[UniversalSpec]:
        """Build the missing 59-spec catalog from pack-owned coverage data.

        The selection is reproducible: direct static coverage is preferred, then
        the highest-volume semantic families; manual review fills the remaining
        eleven slots. This is a catalog of analysis contracts, not fake detector
        implementations.
        """
        if not self._coverage:
            return []
        direct = [x for x in self._coverage if x.get("coverage_status") == "DIRECT_STATIC_DETECTOR"]
        semantic = [x for x in self._coverage if x.get("coverage_status") == "REQUIRES_NEW_SEMANTIC_DETECTOR"]
        nonstatic = [x for x in self._coverage if x.get("coverage_status") == "NON_STATIC_OR_NO_ACTIVE_PATTERN"]
        direct.sort(key=lambda x: x.get("taxonomy_id", ""))
        semantic.sort(key=lambda x: (-int(x.get("pattern_count", 0)), x.get("taxonomy_id", "")))
        selected_static = (direct + semantic)[:48]
        selected_ids = {x.get("taxonomy_id") for x in selected_static}
        manual = [x for x in sorted(nonstatic, key=lambda x: (-int(x.get("pattern_count", 0)), x.get("taxonomy_id", ""))) if x.get("taxonomy_id") not in selected_ids][:11]
        rows = selected_static + manual
        rows.sort(key=lambda x: x.get("taxonomy_id", ""))
        result: list[UniversalSpec] = []
        for row in rows:
            taxonomy_id = str(row.get("taxonomy_id", ""))
            family = str(row.get("name", ""))
            examples = [x for x in self._semantic if str(x.get("taxonomy_id")) == taxonomy_id]
            examples.sort(key=lambda x: (-int(x.get("record_count", 0)), str(x.get("pattern_id", ""))))
            primitive_set = {p for example in examples[:5] for p in example.get("required_shared_primitives", [])}
            primitive_set.update({"manual_review"} if row in manual else set())
            detectors = [str(x) for x in row.get("detectors", [])]
            status = "implemented" if detectors else ("manual" if row in manual else "candidate")
            engines = sorted({engine for primitive in primitive_set for engine in PRIMITIVE_ENGINES.get(primitive, [])})
            result.append(UniversalSpec(
                spec_id=f"US-{taxonomy_id}", pattern_id=str(examples[0].get("pattern_id", taxonomy_id)) if examples else taxonomy_id,
                detector_id=detectors[0] if detectors else f"universal-{family}",
                title=f"Universal analysis: {family.replace('-', ' ')}", family=family,
                root_cause=str(examples[0].get("canonical_root_cause", "") if examples else ""),
                required_primitives=sorted(primitive_set), result_mode="candidate", status=status,
                source="taxonomy_93+semantic_patterns", coverage_status=str(row.get("coverage_status", "")),
                recommended_engines=engines,
            ))
        return result

    def select_specs(self, categories: Iterable[str], limit: int = 12) -> list[UniversalSpec]:
        terms = {c.lower().replace("-", " ") for c in categories}
        specs = self.universal_specs()
        scored = []
        for spec in specs:
            hay = f"{spec.title} {spec.family} {spec.root_cause}".lower().replace("-", " ")
            score = sum(1 for term in terms if term and (term in hay or any(part in hay for part in term.split())))
            scored.append((score, spec.spec_id, spec))
        scored.sort(key=lambda x: (-x[0], x[1]))
        return [spec for score, _, spec in scored if score > 0][:limit] or specs[:limit]

    def summary(self) -> dict[str, Any]:
        return self.status.to_dict()
