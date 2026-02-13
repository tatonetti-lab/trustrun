"""Passive DNS and TLS SNI sniffer for hostname enrichment.

Runs a background scapy AsyncSniffer that watches:
- UDP port 53 (DNS) — caches IP→hostname from A/AAAA response records
- TCP port 443 (TLS) — caches (IP, port)→hostname from ClientHello SNI

Requires elevated privileges (root/sudo) and scapy. Falls back gracefully
when either is unavailable.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class PassiveSniffer:
    """Passively captures DNS responses and TLS SNI to map IPs to hostnames.

    Thread-safe: all cache access is guarded by a lock.
    """

    def __init__(self) -> None:
        self._sniffer: Any = None
        self._dns_cache: dict[str, str] = {}  # IP → hostname
        self._sni_cache: dict[tuple[str, int], str] = {}  # (IP, port) → hostname
        self._lock = threading.Lock()
        self._active = False

    def start(self) -> bool:
        """Start the background sniffer.

        Returns True if started successfully, False if scapy is unavailable
        or privileges are insufficient.
        """
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            logger.debug("scapy not available — passive sniffer disabled")
            return False

        try:
            self._sniffer = AsyncSniffer(
                filter="udp port 53 or tcp port 443",
                prn=self._packet_handler,
                store=False,
            )
            self._sniffer.start()
            self._active = True
            logger.info("Passive DNS/SNI sniffer started")
            return True
        except (PermissionError, OSError) as exc:
            logger.debug("Cannot start passive sniffer: %s", exc)
            return False

    def stop(self) -> None:
        """Stop the background sniffer."""
        if self._sniffer and self._active:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        self._active = False

    @property
    def is_available(self) -> bool:
        """Whether the sniffer started successfully."""
        return self._active

    def get_hostname(self, ip: str, port: int) -> str:
        """Return the best hostname for an IP/port pair.

        Priority: SNI (strongest) > DNS query name > empty string.
        """
        with self._lock:
            # SNI is the strongest signal — it's what the client actually requested
            sni = self._sni_cache.get((ip, port), "")
            if sni:
                return sni
            # DNS cache is next best
            return self._dns_cache.get(ip, "")

    def _packet_handler(self, packet: Any) -> None:
        """Dispatch captured packets to DNS or TLS handlers."""
        try:
            from scapy.layers.inet import TCP, UDP

            if packet.haslayer(UDP):
                self._handle_dns(packet)
            elif packet.haslayer(TCP):
                self._handle_tls(packet)
        except Exception:
            pass

    def _handle_dns(self, packet: Any) -> None:
        """Extract IP→hostname mappings from DNS response A/AAAA records."""
        try:
            from scapy.layers.dns import DNSRR

            if not packet.haslayer(DNSRR):
                return

            dns = packet.getlayer("DNS")
            if dns is None or dns.ancount == 0:
                return

            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                except (IndexError, TypeError):
                    break

                # Type 1 = A record, Type 28 = AAAA record
                if rr.type not in (1, 28):
                    continue

                hostname = rr.rrname
                if isinstance(hostname, bytes):
                    hostname = hostname.decode("utf-8", errors="ignore")
                # Strip trailing dot from DNS names
                hostname = hostname.rstrip(".")
                if not hostname:
                    continue

                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")

                with self._lock:
                    self._dns_cache[rdata] = hostname

        except Exception:
            pass

    def _handle_tls(self, packet: Any) -> None:
        """Extract SNI hostname from TLS ClientHello packets."""
        try:
            from scapy.layers.inet import IP, TCP

            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                return

            tcp = packet[TCP]
            payload = bytes(tcp.payload)

            # TLS record: content type 0x16 (handshake)
            if len(payload) < 6:
                return
            if payload[0] != 0x16:
                return
            # Handshake type 0x01 (ClientHello)
            if payload[5] != 0x01:
                return

            sni = self._parse_sni_from_client_hello(payload)
            if not sni:
                return

            ip_layer = packet[IP]
            dst_ip = ip_layer.dst
            dst_port = tcp.dport

            with self._lock:
                self._sni_cache[(dst_ip, dst_port)] = sni

        except Exception:
            pass

    @staticmethod
    def _parse_sni_from_client_hello(data: bytes) -> str | None:
        """Parse TLS ClientHello for the SNI extension.

        Mirrors the logic in pcap.py for consistency.
        """
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
