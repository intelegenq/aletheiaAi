from __future__ import annotations

import os
from pathlib import Path

import pytest

from aletheia.knowledge import KnowledgeBase, UniversalSpec
from aletheia.spec_compiler import SpecCompilationError, compile_catalog, compile_spec


def test_compiler_preserves_execution_boundaries():
    detector = UniversalSpec("US-1", "PAT-1", "detector-1", "detector", status="implemented", recommended_engines=["slither"])
    candidate = UniversalSpec("US-2", "PAT-2", "universal-2", "candidate", status="candidate", required_primitives=["call_graph"])
    manual = UniversalSpec("US-3", "PAT-3", "universal-3", "manual", status="manual", required_primitives=["manual_review"])
    assert compile_spec(detector, available_engines=["slither"]).execution_mode == "detector"
    assert compile_spec(candidate).execution_mode == "analysis_task"
    assert compile_spec(manual).execution_mode == "manual_review"


def test_compiler_rejects_invalid_identity():
    with pytest.raises(SpecCompilationError):
        compile_spec(UniversalSpec("", "PAT-1", "x", "bad"))


def test_full_pack_catalog_compiles_to_59_unique_actions():
    root = os.environ.get("ALETHEIA_PACK_ROOT", "")
    if not root or not Path(root).is_dir():
        return
    compiled = compile_catalog(KnowledgeBase(root), available_engines=["slither", "foundry"])
    assert len(compiled) == 59
    assert len({item.spec_id for item in compiled}) == 59
    assert sum(item.execution_mode == "detector" for item in compiled) == 23
    assert sum(item.execution_mode == "analysis_task" for item in compiled) == 25
    assert sum(item.execution_mode == "manual_review" for item in compiled) == 11
