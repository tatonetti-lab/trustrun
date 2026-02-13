"""Linux-specific capture helpers."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def get_connections_proc(pid: int) -> list[dict]:
    """Get network connections from /proc/<pid>/net/tcp."""
    connections = []

    for proto_file, proto_name in [("tcp", "tcp"), ("udp", "udp")]:
        path = Path(f"/proc/{pid}/net/{proto_file}")
        if not path.exists():
            continue

        try:
            content = path.read_text()
        except (PermissionError, OSError):
            continue

        for line in content.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue

            local_addr = _parse_hex_addr(parts[1])
            remote_addr = _parse_hex_addr(parts[2])

            if remote_addr is None or local_addr is None:
                continue

            local_ip, local_port = local_addr
            remote_ip, remote_port = remote_addr

            # Skip if no remote connection
            if remote_ip == "0.0.0.0" and remote_port == 0:
                continue

            connections.append(
                {
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "protocol": proto_name,
                    "status": (
                        _tcp_state(parts[3]) if proto_name == "tcp" else "ESTABLISHED"
                    ),
                }
            )

    return connections


def get_connections_ss(pid: int) -> list[dict]:
    """Get network connections via ss -tnp for a given PID."""
    try:
        result = subprocess.run(
            ["ss", "-tnp", f"--processes=pid={pid}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    connections = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue

        # ss output: State  Recv-Q  Send-Q  LocalAddr:Port  PeerAddr:Port
        remote = parts[4]
        local = parts[3]

        try:
            remote_ip, remote_port = _parse_ss_addr(remote)
            local_ip, local_port = _parse_ss_addr(local)
        except ValueError:
            continue

        connections.append(
            {
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "local_ip": local_ip,
                "local_port": local_port,
                "protocol": "tcp",
                "status": parts[0],
            }
        )

    return connections


def _parse_hex_addr(hex_addr: str) -> tuple[str, int] | None:
    """Parse /proc/net/tcp hex address like '0100007F:1F90'."""
    try:
        addr_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        # Convert little-endian hex to IP
        addr_int = int(addr_hex, 16)
        ip = ".".join(str((addr_int >> (8 * i)) & 0xFF) for i in range(4))
        return ip, port
    except (ValueError, IndexError):
        return None


def _parse_ss_addr(addr: str) -> tuple[str, int]:
    """Parse ss address like '192.168.1.1:443'."""
    parts = addr.rsplit(":", 1)
    return parts[0], int(parts[1])


def _tcp_state(state_hex: str) -> str:
    """Convert /proc/net/tcp state hex to human-readable."""
    states = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }
    return states.get(state_hex, "UNKNOWN")


def check_capabilities() -> bool:
    """Check if we have CAP_NET_RAW for packet capture."""
    import os

    return os.geteuid() == 0
