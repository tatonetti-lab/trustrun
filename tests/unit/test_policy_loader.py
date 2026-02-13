"""Tests for policy YAML loading and inheritance."""

from pathlib import Path

import pytest

from trustrun.policy.loader import load_policy, load_policy_from_string
from trustrun.policy.models import Action


def test_load_simple_policy(simple_policy_path: Path):
    policy = load_policy(simple_policy_path)
    assert policy.name == "simple-test"
    assert len(policy.rules) == 2
    assert policy.rules[0].match == "*.allowed.com"
    assert policy.rules[0].action == Action.ALERT
    assert policy.rules[1].match == "*.blocked.com"
    assert policy.rules[1].action == Action.BLOCK


def test_load_policy_with_inheritance(test_policy_path: Path):
    policy = load_policy(test_policy_path)
    assert policy.name == "test-hipaa"
    # Own rules come first, then inherited azure rules
    assert policy.rules[0].match == "*.openai.com"
    assert policy.rules[0].action == Action.BLOCK
    # Should have inherited rules from azure preset
    azure_matches = [r.match for r in policy.rules if "azure" in r.match]
    assert len(azure_matches) > 0


def test_load_policy_from_string():
    yaml_str = """
name: inline-test
rules:
  - match: "*.test.com"
    action: alert
    reason: "Test"
defaults:
  action: block
"""
    policy = load_policy_from_string(yaml_str)
    assert policy.name == "inline-test"
    assert len(policy.rules) == 1
    assert policy.defaults.action == Action.BLOCK


def test_load_preset_azure():
    yaml_str = """
name: uses-azure
inherit:
  - preset:azure
rules: []
defaults:
  action: alert
"""
    policy = load_policy_from_string(yaml_str)
    azure_rules = [r for r in policy.rules if "azure" in r.match.lower() or "windows" in r.match.lower()]
    assert len(azure_rules) > 0


def test_load_preset_aws():
    yaml_str = """
name: uses-aws
inherit:
  - preset:aws
rules: []
defaults:
  action: alert
"""
    policy = load_policy_from_string(yaml_str)
    aws_rules = [r for r in policy.rules if "amazonaws" in r.match]
    assert len(aws_rules) > 0


def test_own_rules_before_inherited():
    yaml_str = """
name: priority-test
inherit:
  - preset:azure
rules:
  - match: "*.my-rule.com"
    action: block
    reason: "My rule"
defaults:
  action: alert
"""
    policy = load_policy_from_string(yaml_str)
    assert policy.rules[0].match == "*.my-rule.com"


def test_circular_inheritance_detected(tmp_path: Path):
    # Create two policies that reference each other
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"
    a.write_text(f"name: a\ninherit:\n  - {b}\nrules: []\ndefaults:\n  action: alert\n")
    b.write_text(f"name: b\ninherit:\n  - {a}\nrules: []\ndefaults:\n  action: alert\n")

    with pytest.raises(ValueError, match="Circular"):
        load_policy(a)


def test_invalid_yaml_raises():
    with pytest.raises(ValueError, match="mapping"):
        load_policy_from_string("just a string")


def test_rule_with_ports():
    yaml_str = """
name: ports-test
rules:
  - match: "*.example.com"
    action: alert
    ports: [443, 8443]
defaults:
  action: alert
"""
    policy = load_policy_from_string(yaml_str)
    assert policy.rules[0].ports == (443, 8443)
