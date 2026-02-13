"""Tests for the policy evaluator — hot path matching logic."""

from trustrun.policy.evaluator import PolicyEvaluator
from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule


def test_hostname_glob_match(simple_policy: Policy):
    evaluator = PolicyEvaluator(simple_policy)

    verdict = evaluator.evaluate(ip="1.2.3.4", hostname="api.allowed.com")
    assert verdict.action == Action.ALERT
    assert not verdict.is_default
    assert verdict.matched_rule is not None
    assert verdict.matched_rule.match == "*.allowed.com"


def test_hostname_glob_block(simple_policy: Policy):
    evaluator = PolicyEvaluator(simple_policy)

    verdict = evaluator.evaluate(ip="5.6.7.8", hostname="evil.blocked.com")
    assert verdict.action == Action.BLOCK
    assert not verdict.is_default


def test_cidr_match(simple_policy: Policy):
    evaluator = PolicyEvaluator(simple_policy)

    verdict = evaluator.evaluate(ip="10.1.2.3")
    assert verdict.action == Action.ALERT
    assert not verdict.is_default
    assert verdict.matched_rule is not None
    assert verdict.matched_rule.match == "10.0.0.0/8"


def test_cidr_no_match(simple_policy: Policy):
    evaluator = PolicyEvaluator(simple_policy)

    verdict = evaluator.evaluate(ip="192.168.1.1")
    assert verdict.is_default


def test_default_action(simple_policy: Policy):
    evaluator = PolicyEvaluator(simple_policy)

    verdict = evaluator.evaluate(ip="99.99.99.99", hostname="unknown.org")
    assert verdict.action == Action.ALERT
    assert verdict.is_default
    assert verdict.matched_rule is None


def test_default_block_all(block_all_policy: Policy):
    evaluator = PolicyEvaluator(block_all_policy)

    verdict = evaluator.evaluate(ip="1.2.3.4")
    assert verdict.action == Action.BLOCK
    assert verdict.is_default


def test_first_match_wins():
    policy = Policy(
        name="first-wins",
        rules=(
            Rule(match="*.example.com", action=Action.BLOCK, reason="Block first"),
            Rule(match="*.example.com", action=Action.ALERT, reason="Alert second"),
        ),
    )
    evaluator = PolicyEvaluator(policy)

    verdict = evaluator.evaluate(ip="1.2.3.4", hostname="api.example.com")
    assert verdict.action == Action.BLOCK
    assert verdict.matched_rule is not None
    assert verdict.matched_rule.reason == "Block first"


def test_port_constraint():
    policy = Policy(
        name="port-test",
        rules=(
            Rule(match="*.example.com", action=Action.BLOCK, ports=(8080,)),
            Rule(match="*.example.com", action=Action.ALERT),
        ),
    )
    evaluator = PolicyEvaluator(policy)

    # Port 8080 matches first rule
    verdict = evaluator.evaluate(ip="1.2.3.4", hostname="api.example.com", port=8080)
    assert verdict.action == Action.BLOCK

    # Port 443 skips first rule, matches second
    verdict = evaluator.evaluate(ip="1.2.3.4", hostname="api.example.com", port=443)
    assert verdict.action == Action.ALERT


def test_case_insensitive_hostname():
    policy = Policy(
        name="case-test",
        rules=(Rule(match="*.Example.COM", action=Action.BLOCK),),
    )
    evaluator = PolicyEvaluator(policy)

    verdict = evaluator.evaluate(ip="1.2.3.4", hostname="api.example.com")
    assert verdict.action == Action.BLOCK
    assert not verdict.is_default


def test_ip_matches_glob():
    """IP addresses should also be matched against hostname glob patterns."""
    policy = Policy(
        name="ip-glob",
        rules=(Rule(match="1.2.3.*", action=Action.BLOCK),),
    )
    evaluator = PolicyEvaluator(policy)

    verdict = evaluator.evaluate(ip="1.2.3.4")
    assert verdict.action == Action.BLOCK
