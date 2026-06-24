"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"


@pytest.fixture
def insecure_dir() -> Path:
    return EXAMPLES / "insecure"


@pytest.fixture
def hardened_dir() -> Path:
    return EXAMPLES / "hardened"
