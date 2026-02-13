"""Block action — inject temporary firewall rules to block connections."""

from __future__ import annotations

import logging
import platform
import subprocess

from trustrun.session.models import ConnectionEvent, Violation

logger = logging.getLogger(__name__)


class BlockAction:
    """Blocks connections by injecting temporary firewall rules.

    Uses iptables on Linux and pfctl on macOS. Rules are tracked
    for cleanup when the session ends.
    """

    def __init__(self) -> None:
        self._blocked_ips: set[str] = set()
        self._system = platform.system()

    def execute(self, event: ConnectionEvent, violation: Violation) -> bool:
        ip = event.remote_ip
        if ip in self._blocked_ips:
            return True  # Already blocked

        logger.warning(
            "BLOCKING connection to %s:%d — %s",
            ip,
            event.remote_port,
            violation.reason,
        )

        success = False
        if self._system == "Linux":
            success = self._block_iptables(ip)
        elif self._system == "Darwin":
            success = self._block_pf(ip)
        else:
            logger.error("Blocking not supported on %s", self._system)
            return False

        if success:
            self._blocked_ips.add(ip)
        return success

    def cleanup(self) -> None:
        """Remove all temporary firewall rules."""
        for ip in list(self._blocked_ips):
            if self._system == "Linux":
                self._unblock_iptables(ip)
            elif self._system == "Darwin":
                self._unblock_pf(ip)
        self._blocked_ips.clear()
        logger.info("Cleaned up %d firewall rules", len(self._blocked_ips))

    def _block_iptables(self, ip: str) -> bool:
        try:
            subprocess.run(
                [
                    "iptables",
                    "-A",
                    "OUTPUT",
                    "-d",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    "trustrun-block",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error("Failed to block %s via iptables: %s", ip, e)
            return False

    def _unblock_iptables(self, ip: str) -> bool:
        try:
            subprocess.run(
                [
                    "iptables",
                    "-D",
                    "OUTPUT",
                    "-d",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    "trustrun-block",
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _block_pf(self, ip: str) -> bool:
        """Add a block rule to macOS pf (packet filter)."""
        rule = f"block drop out quick to {ip}\n"
        try:
            # Add to a trustrun anchor
            proc = subprocess.run(
                ["pfctl", "-a", "trustrun", "-f", "-"],
                input=rule,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error("Failed to block %s via pf: %s", ip, e)
            return False

    def _unblock_pf(self, ip: str) -> bool:
        """Flush the trustrun pf anchor."""
        try:
            subprocess.run(
                ["pfctl", "-a", "trustrun", "-F", "rules"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
