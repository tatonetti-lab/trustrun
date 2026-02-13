"""Load and resolve Policy objects from YAML files."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import yaml

from trustrun.policy.models import (
    Action,
    CaptureLevel,
    Policy,
    PolicyDefaults,
    Rule,
)

_PRESET_PREFIX = "preset:"


def load_policy(path: str | Path, _resolved: set[str] | None = None) -> Policy:
    """Load a policy from a YAML file path."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must be a mapping")
    return _build_policy(data, _resolved=_resolved if _resolved is not None else set())


def load_policy_from_string(text: str) -> Policy:
    """Parse a YAML string into a Policy, resolving inheritance."""
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must be a mapping")
    return _build_policy(data, _resolved=set())


def _build_policy(data: dict, _resolved: set[str]) -> Policy:
    name = data.get("name", "unnamed")

    # Circular inheritance detection
    if name in _resolved:
        raise ValueError(f"Circular policy inheritance detected: {name}")
    _resolved.add(name)

    # Parse own rules
    own_rules = _parse_rules(data.get("rules", []))

    # Resolve inherited rules
    inherited_rules: list[Rule] = []
    inherit_list = data.get("inherit", [])
    if isinstance(inherit_list, str):
        inherit_list = [inherit_list]

    for ref in inherit_list:
        parent = _load_ref(ref, _resolved)
        inherited_rules.extend(parent.rules)

    # Own rules first (higher priority in first-match-wins)
    all_rules = tuple(own_rules) + tuple(inherited_rules)

    # Parse defaults
    defaults_data = data.get("defaults", {})
    defaults = PolicyDefaults(
        action=Action(defaults_data.get("action", "alert")),
    )

    # Parse capture level
    capture_level = CaptureLevel(data.get("capture_level", "metadata"))

    return Policy(
        name=name,
        rules=all_rules,
        defaults=defaults,
        description=data.get("description", ""),
        capture_level=capture_level,
        inherit=tuple(inherit_list),
    )


def _parse_rules(rules_data: list) -> list[Rule]:
    rules: list[Rule] = []
    for r in rules_data:
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
    return rules


def _load_ref(ref: str, _resolved: set[str]) -> Policy:
    if ref.startswith(_PRESET_PREFIX):
        preset_name = ref[len(_PRESET_PREFIX) :]
        return _load_preset(preset_name, _resolved)
    # Treat as file path
    return load_policy(ref, _resolved=_resolved)


def _load_preset(name: str, _resolved: set[str]) -> Policy:
    filename = f"{name}.yaml"
    pkg = importlib.resources.files("trustrun.policy.presets")
    resource = pkg.joinpath(filename)
    text = resource.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    return _build_policy(data, _resolved)
