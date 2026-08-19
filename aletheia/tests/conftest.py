"""Pytest configuration — set environment for all tests.

Conftest is imported before any test module, so setting ALETHEIA_PACK_ROOT
here at module level ensures ``analysis_wiring.PACK_ROOT`` picks it up before
``load_analysis`` is called (a session fixture runs too late: the package is
already imported during collection).
"""
import os

if "ALETHEIA_PACK_ROOT" not in os.environ:
    for candidate in ("/mnt/data/slither-vulndb", "/root/slither_vulndb"):
        if os.path.isdir(candidate):
            os.environ["ALETHEIA_PACK_ROOT"] = candidate
            break
