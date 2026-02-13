"""macOS-specific capture helpers."""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)


def get_connections_lsof(pid: int) -> list[dict]:
    """Get network connections via lsof -i -n -P for a given PID."""
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P", "-a", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    connections = []
    for line in result.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 9:
            continue

        name_field = parts[8]  # e.g., "192.168.1.1:443->10.0.0.1:54321"
        if "->" in name_field:
            local, remote = name_field.split("->")
        elif ":" in name_field:
            remote = name_field
            local = ""
        else:
            continue

        try:
            remote_ip, remote_port = _parse_addr(remote)
            local_ip, local_port = _parse_addr(local) if local else ("", 0)
        except ValueError:
            continue

        proto = parts[7].lower() if len(parts) > 7 else "tcp"
        connections.append(
            {
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_ip": local_ip,
                "local_port": local_port,
                "protocol": "udp" if "udp" in proto.lower() else "tcp",
                "status": parts[9] if len(parts) > 9 else "ESTABLISHED",
            }
        )

    return connections


def _parse_addr(addr: str) -> tuple[str, int]:
    """Parse 'ip:port' or '[ipv6]:port' string."""
    if addr.startswith("["):
        # IPv6: [::1]:8080
        bracket_end = addr.index("]")
        ip = addr[1:bracket_end]
        port = int(addr[bracket_end + 2 :])
    else:
        parts = addr.rsplit(":", 1)
        ip = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 0
    return ip, port


def check_bpf_access() -> bool:
    """Check if we have access to BPF devices for packet capture."""
    import os

    return os.access("/dev/bpf0", os.R_OK)
