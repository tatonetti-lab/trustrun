"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def test_policy_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "test_policy.yaml"


@pytest.fixture
def simple_policy_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "simple_policy.yaml"


@pytest.fixture
def simple_policy() -> Policy:
    return Policy(
        name="test",
        rules=(
            Rule(match="*.allowed.com", action=Action.ALERT, reason="Allowed"),
            Rule(match="*.blocked.com", action=Action.BLOCK, reason="Blocked"),
            Rule(match="10.0.0.0/8", action=Action.ALERT, reason="Private"),
        ),
        defaults=PolicyDefaults(action=Action.ALERT),
    )


@pytest.fixture
def block_all_policy() -> Policy:
    return Policy(
        name="block-all",
        rules=(),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )
