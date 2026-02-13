"""Global configuration — XDG paths, env vars, defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "trustrun"
    return Path.home() / ".local" / "share" / "trustrun"


def _default_config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "trustrun"
    return Path.home() / ".config" / "trustrun"


@dataclass
class TrustRunConfig:
    """Application-wide configuration."""

    data_dir: Path = field(default_factory=_default_data_dir)
    config_dir: Path = field(default_factory=_default_config_dir)
    policy_dirs: list[Path] = field(default_factory=list)
    poll_interval: float = 0.5
    web_host: str = "127.0.0.1"  # Hardcoded — never 0.0.0.0
    web_port: int = 8470
    verbose: bool = False

    @classmethod
    def load(cls) -> TrustRunConfig:
        """Load config from environment variables with XDG defaults."""
        config = cls()

        env_interval = os.environ.get("TRUSTRUN_POLL_INTERVAL")
        if env_interval:
            config.poll_interval = float(env_interval)

        env_port = os.environ.get("TRUSTRUN_WEB_PORT")
        if env_port:
            config.web_port = int(env_port)

        # Add config dir's policies/ subdirectory if it exists
        policies_dir = config.config_dir / "policies"
        if policies_dir.is_dir():
            config.policy_dirs.append(policies_dir)

        return config
