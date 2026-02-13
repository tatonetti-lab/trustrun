"""Policy evaluator — hot path, matches connections against compiled rules."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass

from trustrun.policy.models import Action, Policy, Rule


@dataclass(frozen=True)
class Verdict:
    """Result of evaluating a connection against a policy."""

    action: Action
    matched_rule: Rule | None
    is_default: bool


@dataclass
class _CompiledRule:
    """A rule with pre-compiled matching patterns for fast evaluation."""

    rule: Rule
    hostname_regex: re.Pattern[str] | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    ports: frozenset[int] = frozenset()


class PolicyEvaluator:
    """Evaluates connections against a compiled policy. First-match-wins."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._compiled: list[_CompiledRule] = []
        for rule in policy.rules:
            self._compiled.append(_compile_rule(rule))

    def evaluate(
        self,
        ip: str,
        hostname: str = "",
        port: int = 0,
    ) -> Verdict:
        """Evaluate a connection. Returns the verdict (action + matched rule).

        First-match-wins: rules are checked in order (own rules before inherited).
        Falls back to policy defaults if nothing matches.
        """
        for cr in self._compiled:
            if _matches(cr, ip, hostname, port):
                return Verdict(
                    action=cr.rule.action,
                    matched_rule=cr.rule,
                    is_default=False,
                )

        return Verdict(
            action=self.policy.defaults.action,
            matched_rule=None,
            is_default=True,
        )


def _compile_rule(rule: Rule) -> _CompiledRule:
    pattern = rule.match
    network = None
    hostname_regex = None

    # Try parsing as CIDR network
    try:
        network = ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        # It's a hostname glob pattern
        regex_str = fnmatch.translate(pattern)
        hostname_regex = re.compile(regex_str, re.IGNORECASE)

    return _CompiledRule(
        rule=rule,
        hostname_regex=hostname_regex,
        network=network,
        ports=frozenset(rule.ports),
    )


def _matches(cr: _CompiledRule, ip: str, hostname: str, port: int) -> bool:
    # Check port constraint first (cheapest check)
    if cr.ports and port not in cr.ports:
        return False

    # CIDR match
    if cr.network is not None:
        try:
            addr = ipaddress.ip_address(ip)
            return addr in cr.network
        except ValueError:
            return False

    # Hostname glob match — check against both hostname and IP
    if cr.hostname_regex is not None:
        if hostname and cr.hostname_regex.match(hostname):
            return True
        if cr.hostname_regex.match(ip):
            return True

    return False
