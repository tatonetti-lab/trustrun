"""Tests for the TUI policy mutator."""

from __future__ import annotations

from pathlib import Path

from trustrun.policy.loader import load_policy_from_string
from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule
from trustrun.session.models import ConnectionEvent
from trustrun.tui.policy_mutator import (
    _generalize_pattern,
    _overrides_path,
    add_allow_rule,
    add_block_rule,
    export_policy,
    load_overrides,
    merge_overrides,
    save_overrides,
)


def _make_event(
    remote_ip: str = "1.2.3.4",
    hostname: str = "",
    remote_port: int = 443,
) -> ConnectionEvent:
    return ConnectionEvent(
        pid=1234,
        process_name="test",
        remote_ip=remote_ip,
        remote_port=remote_port,
        hostname=hostname,
    )


def _make_policy() -> Policy:
    return Policy(
        name="test-policy",
        rules=(
            Rule(match="*.allowed.com", action=Action.ALERT, reason="Allowed"),
        ),
        defaults=PolicyDefaults(action=Action.BLOCK),
        description="Test policy",
    )


def test_add_allow_rule_prepends():
    policy = _make_policy()
    event = _make_event(hostname="api.openai.com")

    new_policy = add_allow_rule(policy, event)

    assert len(new_policy.rules) == 2
    assert new_policy.rules[0].action == Action.ALERT
    assert new_policy.rules[0].match == "*.openai.com"
    assert "interactively via TUI" in new_policy.rules[0].reason
    # Original rule preserved
    assert new_policy.rules[1].match == "*.allowed.com"


def test_add_allow_rule_does_not_mutate_original():
    policy = _make_policy()
    event = _make_event(hostname="api.openai.com")

    add_allow_rule(policy, event)

    assert len(policy.rules) == 1


def test_add_block_rule_prepends():
    policy = _make_policy()
    event = _make_event(hostname="bad.example.com")

    new_policy = add_block_rule(policy, event)

    assert len(new_policy.rules) == 2
    assert new_policy.rules[0].action == Action.BLOCK
    assert new_policy.rules[0].match == "*.example.com"


def test_add_block_rule_preserves_policy_metadata():
    policy = _make_policy()
    event = _make_event(hostname="bad.example.com")

    new_policy = add_block_rule(policy, event)

    assert new_policy.name == policy.name
    assert new_policy.defaults == policy.defaults
    assert new_policy.description == policy.description
    assert new_policy.capture_level == policy.capture_level
    assert new_policy.inherit == policy.inherit


def test_generalize_pattern_hostname_with_subdomain():
    event = _make_event(hostname="api.openai.com")
    assert _generalize_pattern(event) == "*.openai.com"


def test_generalize_pattern_hostname_deep_subdomain():
    event = _make_event(hostname="us-east.api.openai.com")
    assert _generalize_pattern(event) == "*.openai.com"


def test_generalize_pattern_bare_domain():
    event = _make_event(hostname="example.com")
    assert _generalize_pattern(event) == "example.com"


def test_generalize_pattern_ip_stays_exact():
    event = _make_event(remote_ip="10.0.1.50")
    assert _generalize_pattern(event) == "10.0.1.50"


def test_generalize_pattern_ipv6_stays_exact():
    event = _make_event(remote_ip="::1")
    assert _generalize_pattern(event) == "::1"


def test_generalize_pattern_hostname_preferred_over_ip():
    event = _make_event(remote_ip="1.2.3.4", hostname="api.service.io")
    assert _generalize_pattern(event) == "*.service.io"


def test_export_policy_writes_valid_yaml(tmp_path: Path, monkeypatch: object):
    """Exported YAML should roundtrip through load_policy_from_string."""
    import trustrun.tui.policy_mutator as pm

    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]

    policy = Policy(
        name="export-test",
        rules=(
            Rule(match="*.azure.com", action=Action.ALERT, reason="Azure BAA"),
            Rule(match="*.bad.com", action=Action.BLOCK, reason="Blocked via TUI"),
        ),
        defaults=PolicyDefaults(action=Action.BLOCK),
        description="Test export",
    )

    filename = export_policy(policy)
    filepath = tmp_path / filename

    assert filepath.exists()

    # Roundtrip: load the exported YAML and verify it produces an equivalent policy
    text = filepath.read_text(encoding="utf-8")
    loaded = load_policy_from_string(text)

    assert loaded.name == "export-test"
    assert len(loaded.rules) == 2
    assert loaded.rules[0].match == "*.azure.com"
    assert loaded.rules[0].action == Action.ALERT
    assert loaded.rules[1].match == "*.bad.com"
    assert loaded.rules[1].action == Action.BLOCK
    assert loaded.defaults.action == Action.BLOCK


def test_export_policy_includes_inherit(tmp_path: Path, monkeypatch: object):
    import trustrun.tui.policy_mutator as pm

    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]

    policy = Policy(
        name="inherit-test",
        rules=(),
        defaults=PolicyDefaults(action=Action.ALERT),
        inherit=("preset:azure",),
    )

    filename = export_policy(policy)
    filepath = tmp_path / filename
    text = filepath.read_text(encoding="utf-8")

    assert "preset:azure" in text


def test_export_policy_includes_ports(tmp_path: Path, monkeypatch: object):
    monkeypatch.chdir(tmp_path)  # type: ignore[attr-defined]

    policy = Policy(
        name="ports-test",
        rules=(
            Rule(match="*.example.com", action=Action.ALERT, ports=(80, 443)),
        ),
        defaults=PolicyDefaults(action=Action.ALERT),
    )

    filename = export_policy(policy)
    filepath = tmp_path / filename
    text = filepath.read_text(encoding="utf-8")

    assert "80" in text
    assert "443" in text


# --- Override persistence tests ---


def test_save_and_load_overrides(tmp_path: Path, monkeypatch):
    """TUI-added rules should roundtrip through save/load."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    policy = Policy(
        name="persist-test",
        rules=(
            Rule(
                match="*.openai.com",
                action=Action.ALERT,
                reason="Allowed interactively via TUI",
            ),
            Rule(
                match="*.evil.com",
                action=Action.BLOCK,
                reason="Blocked interactively via TUI",
            ),
            Rule(match="*.azure.com", action=Action.ALERT, reason="Original"),
        ),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )

    save_overrides(policy)

    rules = load_overrides("persist-test")
    assert len(rules) == 2
    assert rules[0].match == "*.openai.com"
    assert rules[0].action == Action.ALERT
    assert rules[1].match == "*.evil.com"
    assert rules[1].action == Action.BLOCK


def test_load_overrides_returns_empty_when_no_file(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    rules = load_overrides("nonexistent-policy")
    assert rules == ()


def test_save_overrides_skips_when_no_tui_rules(tmp_path: Path, monkeypatch):
    """If no rules have the TUI marker, nothing should be written."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    policy = Policy(
        name="no-tui-rules",
        rules=(
            Rule(match="*.azure.com", action=Action.ALERT, reason="Original"),
        ),
        defaults=PolicyDefaults(action=Action.ALERT),
    )

    save_overrides(policy)

    path = _overrides_path("no-tui-rules")
    assert not path.exists()


def test_merge_overrides_prepends_saved_rules(tmp_path: Path, monkeypatch):
    """merge_overrides should prepend saved TUI rules to the base policy."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    # Save some overrides
    modified = Policy(
        name="merge-test",
        rules=(
            Rule(
                match="*.openai.com",
                action=Action.ALERT,
                reason="Allowed interactively via TUI",
            ),
        ),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )
    save_overrides(modified)

    # Load base policy (no TUI rules)
    base = Policy(
        name="merge-test",
        rules=(
            Rule(match="*.azure.com", action=Action.ALERT, reason="Azure"),
        ),
        defaults=PolicyDefaults(action=Action.BLOCK),
    )

    merged = merge_overrides(base)

    assert len(merged.rules) == 2
    assert merged.rules[0].match == "*.openai.com"
    assert merged.rules[1].match == "*.azure.com"


def test_merge_overrides_noop_when_no_file(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    base = Policy(
        name="clean-policy",
        rules=(
            Rule(match="*.azure.com", action=Action.ALERT, reason="Azure"),
        ),
        defaults=PolicyDefaults(action=Action.ALERT),
    )

    merged = merge_overrides(base)

    assert merged is base  # same object, no change


def test_merge_overrides_deduplicates(tmp_path: Path, monkeypatch):
    """If the override rule already exists in the policy, don't duplicate."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))

    rule = Rule(
        match="*.openai.com",
        action=Action.ALERT,
        reason="Allowed interactively via TUI",
    )
    modified = Policy(name="dedup-test", rules=(rule,))
    save_overrides(modified)

    # Base policy already has this rule (from previous merge)
    base = Policy(name="dedup-test", rules=(rule,))
    merged = merge_overrides(base)

    assert merged is base  # no new rules added
