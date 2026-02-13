"""Elevated capture backend using scapy for real packet capture."""

from __future__ import annotations

import logging
import threading
from typing import Any

from trustrun.session.models import ConnectionEvent

logger = logging.getLogger(__name__)


class PcapCapture:
    """Packet capture backend using scapy's AsyncSniffer.

    Requires root/sudo privileges. Extracts TLS SNI for hostname
    identification. Falls back gracefully if scapy is not installed.
    """

    def __init__(self) -> None:
        self._pid: int = 0
        self._include_children: bool = True
        self._running: bool = False
        self._sniffer: Any = None
        self._events: list[ConnectionEvent] = []
        self._lock = threading.Lock()
        self._seen: set[tuple[str, int, str, int]] = set()

    def start(self, pid: int, include_children: bool = True) -> None:
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            raise RuntimeError(
                "scapy is required for pcap capture. "
                "Install with: pip install trustrun[capture]"
            )

        self._pid = pid
        self._include_children = include_children
        self._events.clear()
        self._seen.clear()

        self._sniffer = AsyncSniffer(
            filter="tcp or udp",
            prn=self._packet_handler,
            store=False,
        )
        self._sniffer.start()
        self._running = True
        logger.info("Pcap capture started for PID %d", pid)

    def stop(self) -> None:
        if self._sniffer and self._running:
            self._sniffer.stop()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def poll(self) -> list[ConnectionEvent]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events

    def _packet_handler(self, packet) -> None:
        """Process each captured packet."""
        try:
            from scapy.layers.inet import IP, TCP, UDP
        except ImportError:
            return

        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        dst_ip = ip_layer.dst
        src_ip = ip_layer.src

        dst_port = 0
        src_port = 0
        proto = "tcp"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            dst_port = tcp.dport
            src_port = tcp.sport
            proto = "tcp"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            dst_port = udp.dport
            src_port = udp.sport
            proto = "udp"
        else:
            return

        # Deduplicate
        key = (dst_ip, dst_port, src_ip, src_port)
        if key in self._seen:
            return
        self._seen.add(key)

        # Try TLS SNI extraction
        hostname = self._extract_sni(packet) or ""

        event = ConnectionEvent(
            pid=self._pid,
            process_name="",
            remote_ip=dst_ip,
            remote_port=dst_port,
            local_ip=src_ip,
            local_port=src_port,
            hostname=hostname,
            protocol=proto,
            status="CAPTURED",
        )

        with self._lock:
            self._events.append(event)

    def _extract_sni(self, packet) -> str | None:
        """Try to extract TLS SNI from a Client Hello packet."""
        try:
            from scapy.layers.inet import TCP

            if not packet.haslayer(TCP):
                return None

            tcp = packet[TCP]
            payload = bytes(tcp.payload)

            # TLS Client Hello: content type 0x16, version, then
            # handshake type 0x01
            if len(payload) < 6:
                return None
            if payload[0] != 0x16:
                return None
            if payload[5] != 0x01:
                return None

            # Parse extensions to find SNI
            return self._parse_sni_from_client_hello(payload)
        except Exception:
            return None

    def _parse_sni_from_client_hello(self, data: bytes) -> str | None:
        """Parse TLS Client Hello for SNI extension."""
        try:
            # Skip TLS record header (5 bytes) + handshake header (4)
            pos = 5 + 4
            if pos + 2 > len(data):
                return None

            # Skip client version (2) + random (32)
            pos += 2 + 32

            # Skip session ID
            if pos + 1 > len(data):
                return None
            session_id_len = data[pos]
            pos += 1 + session_id_len

            # Skip cipher suites
            if pos + 2 > len(data):
                return None
            cs_len = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2 + cs_len

            # Skip compression methods
            if pos + 1 > len(data):
                return None
            comp_len = data[pos]
            pos += 1 + comp_len

            # Extensions
            if pos + 2 > len(data):
                return None
            ext_len = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2
            ext_end = pos + ext_len

            while pos + 4 <= ext_end:
                ext_type = int.from_bytes(data[pos : pos + 2], "big")
                ext_data_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
                pos += 4

                if ext_type == 0:  # SNI extension
                    # SNI list length (2) + type (1) + name length (2)
                    if pos + 5 <= pos + ext_data_len:
                        name_len = int.from_bytes(data[pos + 3 : pos + 5], "big")
                        name = data[pos + 5 : pos + 5 + name_len]
                        return name.decode("ascii", errors="ignore")

                pos += ext_data_len

        except (IndexError, ValueError):
            pass
        return None
