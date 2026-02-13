"""Runtime policy mutation — add allow/block rules and export to YAML."""

from __future__ import annotations

import ipaddress
import logging
import time
from pathlib import Path

import yaml

from trustrun.config import TrustRunConfig
from trustrun.policy.models import Action, Policy, Rule
from trustrun.session.models import ConnectionEvent

logger = logging.getLogger(__name__)

_TUI_RULE_MARKER = "interactively via TUI"


def add_allow_rule(policy: Policy, event: ConnectionEvent) -> Policy:
    """Return a new Policy with an allow rule prepended for the event's destination."""
    pattern = _generalize_pattern(event)
    rule = Rule(
        match=pattern,
        action=Action.ALERT,
        reason="Allowed interactively via TUI",
    )
    return Policy(
        name=policy.name,
        rules=(rule,) + policy.rules,
        defaults=policy.defaults,
        description=policy.description,
        capture_level=policy.capture_level,
        inherit=policy.inherit,
    )


def add_block_rule(policy: Policy, event: ConnectionEvent) -> Policy:
    """Return a new Policy with a block rule prepended for the event's destination."""
    pattern = _generalize_pattern(event)
    rule = Rule(
        match=pattern,
        action=Action.BLOCK,
        reason="Blocked interactively via TUI",
    )
    return Policy(
        name=policy.name,
        rules=(rule,) + policy.rules,
        defaults=policy.defaults,
        description=policy.description,
        capture_level=policy.capture_level,
        inherit=policy.inherit,
    )


def export_policy(policy: Policy) -> str:
    """Serialize the policy to YAML and write to a timestamped file.

    Returns the filename written.
    """
    data: dict = {
        "name": policy.name,
        "description": policy.description,
        "capture_level": policy.capture_level.value,
        "defaults": {"action": policy.defaults.action.value},
        "rules": [],
    }
    if policy.inherit:
        data["inherit"] = list(policy.inherit)

    for rule in policy.rules:
        entry: dict = {
            "match": rule.match,
            "action": rule.action.value,
        }
        if rule.reason:
            entry["reason"] = rule.reason
        if rule.ports:
            entry["ports"] = list(rule.ports)
        data["rules"].append(entry)

    text: str = yaml.dump(data, default_flow_style=False, sort_keys=False)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"{policy.name}-modified-{timestamp}.yaml"
    Path(filename).write_text(text, encoding="utf-8")
    return filename


def save_overrides(policy: Policy) -> None:
    """Persist TUI-added rules to the overrides directory.

    Only rules whose reason contains the TUI marker are saved.
    Overwrites any previous overrides for this policy name.
    """
    tui_rules = [r for r in policy.rules if _TUI_RULE_MARKER in r.reason]
    if not tui_rules:
        return

    path = _overrides_path(policy.name)
    path.parent.mkdir(parents=True, exist_ok=True)

    entries = []
    for rule in tui_rules:
        entry: dict = {
            "match": rule.match,
            "action": rule.action.value,
            "reason": rule.reason,
        }
        if rule.ports:
            entry["ports"] = list(rule.ports)
        entries.append(entry)

    data = {"rules": entries}
    path.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    logger.debug("Saved %d override(s) to %s", len(entries), path)


def load_overrides(policy_name: str) -> tuple[Rule, ...]:
    """Load previously saved TUI overrides for a policy.

    Returns an empty tuple if no overrides file exists.
    """
    path = _overrides_path(policy_name)
    if not path.is_file():
        return ()

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        logger.warning("Failed to load overrides from %s", path)
        return ()

    if not isinstance(data, dict):
        return ()

    rules: list[Rule] = []
    for r in data.get("rules", []):
        if not isinstance(r, dict):
            continue
        ports_raw = r.get("ports", ())
        if isinstance(ports_raw, int):
            ports_raw = (ports_raw,)
        rules.append(
            Rule(
                match=r["match"],
                action=Action(r.get("action", "alert")),
                reason=r.get("reason", ""),
                ports=tuple(int(p) for p in ports_raw),
            )
        )

    logger.debug("Loaded %d override(s) from %s", len(rules), path)
    return tuple(rules)


def merge_overrides(policy: Policy) -> Policy:
    """Load any saved overrides and prepend them to the policy.

    Returns the original policy unchanged if no overrides exist.
    """
    overrides = load_overrides(policy.name)
    if not overrides:
        return policy

    # Filter out any override rules that already exist in the policy
    # (e.g., from a previous merge in the same session)
    existing = {(r.match, r.action) for r in policy.rules}
    new_rules = tuple(
        r for r in overrides if (r.match, r.action) not in existing
    )
    if not new_rules:
        return policy

    return Policy(
        name=policy.name,
        rules=new_rules + policy.rules,
        defaults=policy.defaults,
        description=policy.description,
        capture_level=policy.capture_level,
        inherit=policy.inherit,
    )


def _overrides_path(policy_name: str) -> Path:
    """Path to the overrides YAML file for a given policy."""
    config = TrustRunConfig.load()
    return config.data_dir / "overrides" / f"{policy_name}.yaml"


def _generalize_pattern(event: ConnectionEvent) -> str:
    """Convert a connection event destination into a match pattern.

    Hostnames become *.domain.com (wildcard subdomain).
    IPs stay exact.
    """
    dest = event.hostname or event.remote_ip

    # Check if it's an IP address
    try:
        ipaddress.ip_address(dest)
        return dest
    except ValueError:
        pass

    # Hostname: generalize to *.domain.com
    parts = dest.split(".")
    if len(parts) > 2:
        return "*." + ".".join(parts[-2:])
    return dest
