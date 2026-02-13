"""Auto-learn mode — observe network activity and generate a policy."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import yaml

from trustrun.policy.models import Action, Policy, PolicyDefaults, Rule
from trustrun.session.models import ConnectionEvent

logger = logging.getLogger(__name__)


@dataclass
class LearnedEndpoint:
    """An endpoint observed during learning mode."""

    hostname: str
    ip: str
    ports: set[int] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    count: int = 0


class PolicyLearner:
    """Observes network connections and builds a policy profile.

    Usage:
        1. Create a learner
        2. Feed it ConnectionEvents via observe()
        3. Call generate_policy() to produce a Policy
        4. Call export_yaml() to get the YAML string
    """

    def __init__(self, name: str = "learned-policy") -> None:
        self._name = name
        self._endpoints: dict[str, LearnedEndpoint] = {}

    @property
    def endpoint_count(self) -> int:
        return len(self._endpoints)

    def observe(self, event: ConnectionEvent) -> None:
        """Record a connection event."""
        key = event.hostname or event.remote_ip
        if key in self._endpoints:
            ep = self._endpoints[key]
            ep.ports.add(event.remote_port)
            ep.last_seen = time.time()
            ep.count += 1
        else:
            self._endpoints[key] = LearnedEndpoint(
                hostname=event.hostname,
                ip=event.remote_ip,
                ports={event.remote_port},
                count=1,
            )

    def generate_policy(
        self,
        default_action: Action = Action.BLOCK,
    ) -> Policy:
        """Generate a policy that allows all observed endpoints."""
        rules: list[Rule] = []

        for key, ep in sorted(
            self._endpoints.items(), key=lambda x: x[1].count, reverse=True
        ):
            pattern = self._endpoint_to_pattern(ep)
            rules.append(
                Rule(
                    match=pattern,
                    action=Action.ALERT,
                    reason=f"Learned: seen {ep.count} time(s)",
                )
            )

        return Policy(
            name=self._name,
            rules=tuple(rules),
            defaults=PolicyDefaults(action=default_action),
            description=(f"Auto-learned policy with {len(rules)} allowed endpoints"),
        )

    def export_yaml(self, default_action: Action = Action.BLOCK) -> str:
        """Export the learned policy as a YAML string."""
        policy = self.generate_policy(default_action)

        data: dict = {
            "name": policy.name,
            "description": policy.description,
            "rules": [],
            "defaults": {"action": policy.defaults.action.value},
        }

        for rule in policy.rules:
            data["rules"].append(
                {
                    "match": rule.match,
                    "action": rule.action.value,
                    "reason": rule.reason,
                }
            )

        result: str = yaml.dump(data, default_flow_style=False, sort_keys=False)
        return result

    def _endpoint_to_pattern(self, ep: LearnedEndpoint) -> str:
        """Convert a learned endpoint to a glob pattern."""
        if ep.hostname:
            # Try to generalize: *.domain.com
            parts = ep.hostname.split(".")
            if len(parts) > 2:
                return "*." + ".".join(parts[-2:])
            return ep.hostname
        return ep.ip
