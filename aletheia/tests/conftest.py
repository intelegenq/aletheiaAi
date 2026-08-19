"""Pytest configuration — set environment for all tests."""
import os
import pytest


@pytest.fixture(autouse=True, scope="session")
def _set_pack_root():
    """Ensure ALETHEIA_PACK_ROOT points to the actual slither-vulndb pack.

    The default in analysis_wiring.py is a relative path that only works when
    the repo is cloned alongside the pack.  On this machine the pack lives at
    /mnt/data/slither-vulndb (symlinked from /root/slither_vulndb).
    """
    if "ALETHEIA_PACK_ROOT" not in os.environ:
        for candidate in ("/mnt/data/slither-vulndb", "/root/slither_vulndb"):
            if os.path.isdir(candidate):
                os.environ["ALETHEIA_PACK_ROOT"] = candidate
                break