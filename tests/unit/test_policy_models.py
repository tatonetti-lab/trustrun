"""Tests for policy data models."""

from trustrun.policy.models import Action, CaptureLevel, Policy, PolicyDefaults, Rule


def test_action_values():
    assert Action.ALERT.value == "alert"
    assert Action.BLOCK.value == "block"
    assert Action.KILL.value == "kill"


def test_capture_level_values():
    assert CaptureLevel.METADATA.value == "metadata"
    assert CaptureLevel.HEADERS.value == "headers"
    assert CaptureLevel.FULL.value == "full"


def test_rule_frozen():
    rule = Rule(match="*.example.com", action=Action.ALERT, reason="test")
    assert rule.match == "*.example.com"
    assert rule.ports == ()


def test_rule_with_ports():
    rule = Rule(match="*.example.com", action=Action.BLOCK, ports=(443, 8443))
    assert rule.ports == (443, 8443)


def test_policy_defaults():
    defaults = PolicyDefaults()
    assert defaults.action == Action.ALERT


def test_policy_immutable():
    policy = Policy(name="test", rules=(), defaults=PolicyDefaults())
    assert policy.name == "test"
    assert policy.rules == ()
    assert policy.capture_level == CaptureLevel.METADATA


def test_policy_with_rules():
    rules = (
        Rule(match="*.foo.com", action=Action.ALERT),
        Rule(match="*.bar.com", action=Action.BLOCK),
    )
    policy = Policy(name="multi", rules=rules)
    assert len(policy.rules) == 2
    assert policy.rules[0].match == "*.foo.com"
