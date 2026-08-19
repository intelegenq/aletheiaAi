"""Tests for intake module."""

from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aletheia.intake import (
    detect_foundry, detect_solc_version, find_sol_files,
    classify_contracts, intake,
)


def test_intake_nonexistent():
    ctx = intake("/nonexistent/path/xyz", with_build=False)
    assert ctx.error
    assert "not exist" in ctx.error


def test_intake_file_not_dir(tmp_path):
    f = tmp_path / "file.txt"
    f.write_text("x")
    ctx = intake(str(f), with_build=False)
    assert ctx.error
    assert "not a directory" in ctx.error


def test_intake_empty_dir(tmp_path):
    ctx = intake(str(tmp_path), with_build=False)
    assert ctx.error
    assert "no .sol files" in ctx.error


def test_intake_with_sol(tmp_path):
    sol = tmp_path / "contracts" / "Test.sol"
    sol.parent.mkdir(parents=True)
    sol.write_text("pragma solidity 0.8.20;\ncontract Test {}")
    ctx = intake(str(tmp_path), with_build=False)
    assert not ctx.error
    assert len(ctx.sol_files) == 1
    assert ctx.solc_version == "0.8.20"


def test_detect_foundry(tmp_path):
    has, toml = detect_foundry(tmp_path)
    assert not has
    assert toml is None

    toml_path = tmp_path / "foundry.toml"
    toml_path.write_text("[profile.default]\nsolc = '0.8.20'")
    has, toml = detect_foundry(tmp_path)
    assert has
    assert toml == toml_path


def test_detect_solc_from_pragma():
    # test via intent
    pass


def test_classify_contracts(tmp_path):
    # Create contract
    c = tmp_path / "src" / "Main.sol"
    c.parent.mkdir()
    c.write_text("contract Main {}")
    # Create test
    t = tmp_path / "test" / "Main.t.sol"
    t.parent.mkdir()
    t.write_text("contract Test {}")
    # Create lib
    l = tmp_path / "lib" / "forge-std" / "Test.sol"
    l.parent.mkdir(parents=True)
    l.write_text("contract Test {}")

    sols = [c, t, l]
    contracts, tests, libs = classify_contracts(tmp_path, sols)
    assert len(contracts) == 1
    assert len(tests) == 1
    assert len(libs) == 1