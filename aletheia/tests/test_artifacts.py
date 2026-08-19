"""Tests for artifact storage."""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.artifacts import ArtifactStore


def test_store_new_run_id():
    store = ArtifactStore()
    assert store.run_id
    assert len(store.run_id) >= 8


def test_store_init_creates_dir(tmp_path):
    store = ArtifactStore(run_id="test-001", base_dir=tmp_path)
    d = store.init()
    assert d == tmp_path
    assert tmp_path.exists()


def test_store_save_artifact(tmp_path):
    store = ArtifactStore(run_id="test-002", base_dir=tmp_path)
    store.init()
    p = store.save_artifact("slither", "hello world", "stdout.txt")
    assert p.exists()
    assert p.read_text() == "hello world"
    assert "slither" in store.artifacts


def test_store_save_json(tmp_path):
    store = ArtifactStore(run_id="test-003", base_dir=tmp_path)
    store.init()
    p = store.save_json("mythril", {"a": 1, "b": [2]})
    assert p.exists()
    import json
    data = json.loads(p.read_text())
    assert data["a"] == 1


def test_store_save_run(tmp_path):
    store = ArtifactStore(run_id="test-004", base_dir=tmp_path)
    store.init()
    manifest = {"run_id": "test-004", "findings": 42}
    p = store.save_run(manifest)
    assert p.exists()
    import json
    data = json.loads(p.read_text())
    assert data["findings"] == 42