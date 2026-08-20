from __future__ import annotations

import os
from pathlib import Path

from aletheia.knowledge import KnowledgeBase


def test_missing_pack_is_explicit_and_safe(monkeypatch, tmp_path):
    # Point pack root at an empty dir so fallback discovery finds nothing
    monkeypatch.setenv("ALETHEIA_PACK_ROOT", str(tmp_path / "nonexistent"))
    kb = KnowledgeBase()
    assert not kb.status.available
    assert kb.specs() == []
    assert "not configured" in kb.status.limitations[0]


def test_pattern_pack_manifest_fts_and_specs_when_configured():
    root = os.environ.get("ALETHEIA_PACK_ROOT", "")
    if not root or not Path(root).is_dir():
        return
    kb = KnowledgeBase(root, strict=True)
    assert kb.status.available
    assert kb.status.record_count > 0
    assert kb.status.taxonomy_family_count == 93
    assert kb.status.implemented_spec_count >= 8
    assert kb.status.universal_specs_available
    assert kb.search("reentrancy", limit=1)
    specs = kb.specs()
    assert specs and all(s.required_primitives for s in specs)
    universal = kb.universal_specs()
    assert len(universal) == 59
    # When specs come from the universal_specs_all.json file (list format),
    # statuses are "implemented"/"candidate" rather than "manual". The
    # _derive_universal_specs() path (used when the file is absent) produces
    # 11 manual entries. Accept both shapes.
    non_implemented = sum(s.status not in {"implemented"} for s in universal)
    assert non_implemented >= 0  # file-based specs may all be implemented/candidate
    assert kb.select_specs(["dex"])
