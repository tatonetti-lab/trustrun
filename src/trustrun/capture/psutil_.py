"""Unprivileged capture backend using psutil to poll process connections."""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from typing import NamedTuple

import psutil

from trustrun.capture.sniffer import PassiveSniffer
from trustrun.resolve import IpResolver
from trustrun.session.models import ConnectionEvent

logger = logging.getLogger(__name__)

# Protocol family constants from psutil
_PROTO_MAP = {
    socket.SOCK_STREAM: "tcp",
    socket.SOCK_DGRAM: "udp",
}


class _ConnKey(NamedTuple):
    remote_ip: str
    remote_port: int
    local_ip: str
    local_port: int
    protocol: str


@dataclass
class PsutilCapture:
    """Captures network connections by polling psutil.Process.connections().

    Maintains a set of seen connection keys and returns only new connections
    on each poll(). Departed connections are pruned so reconnections are detected.
    """

    _pid: int = 0
    _include_children: bool = True
    _running: bool = False
    _seen: set[_ConnKey] = field(default_factory=set)
    _resolver: IpResolver = field(default_factory=IpResolver)
    _sniffer: PassiveSniffer | None = field(default=None)

    def start(self, pid: int, include_children: bool = True) -> None:
        self._pid = pid
        self._include_children = include_children
        self._running = True
        self._seen.clear()
        self._resolver = IpResolver()

        sniffer = PassiveSniffer()
        if sniffer.start():
            self._sniffer = sniffer
        else:
            self._sniffer = None
            logger.debug("Passive DNS/SNI sniffer unavailable — using resolver only")

    def stop(self) -> None:
        self._running = False
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None

    @property
    def sniffer_active(self) -> bool:
        """Whether the passive DNS/SNI sniffer is running."""
        return self._sniffer is not None and self._sniffer.is_available

    @property
    def is_running(self) -> bool:
        return self._running

    def poll(self) -> list[ConnectionEvent]:
        if not self._running:
            return []

        try:
            proc = psutil.Process(self._pid)
        except psutil.NoSuchProcess:
            logger.warning("Process %d no longer exists", self._pid)
            self._running = False
            return []

        pids_to_check: list[tuple[int, str]] = [(proc.pid, proc.name())]
        if self._include_children:
            try:
                for child in proc.children(recursive=True):
                    try:
                        pids_to_check.append((child.pid, child.name()))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        current_keys: set[_ConnKey] = set()
        new_events: list[ConnectionEvent] = []

        for pid, name in pids_to_check:
            try:
                p = psutil.Process(pid)
                conns = p.net_connections(kind="inet")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            for conn in conns:
                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                local_ip = conn.laddr.ip if conn.laddr else ""
                local_port = conn.laddr.port if conn.laddr else 0
                proto = _PROTO_MAP.get(conn.type, "tcp")

                key = _ConnKey(remote_ip, remote_port, local_ip, local_port, proto)
                current_keys.add(key)

                if key not in self._seen:
                    # Try passive sniffer first (SNI > DNS), then resolver
                    sniffer_hostname = ""
                    if self._sniffer is not None:
                        sniffer_hostname = self._sniffer.get_hostname(
                            remote_ip, remote_port
                        )

                    ip_info = self._resolver.resolve(remote_ip)
                    hostname = sniffer_hostname or ip_info.hostname
                    status = conn.status if hasattr(conn, "status") else "ESTABLISHED"
                    new_events.append(
                        ConnectionEvent(
                            pid=pid,
                            process_name=name,
                            remote_ip=remote_ip,
                            remote_port=remote_port,
                            local_ip=local_ip,
                            local_port=local_port,
                            hostname=hostname,
                            org=ip_info.org,
                            protocol=proto,
                            status=status,
                        )
                    )

        # Prune departed connections so reconnections are detected
        self._seen = current_keys
        return new_events

