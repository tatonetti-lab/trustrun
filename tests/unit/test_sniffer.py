"""Tests for the passive DNS/TLS SNI sniffer."""

from __future__ import annotations

import sys
import threading
import types
from unittest.mock import MagicMock, patch

import pytest

from trustrun.capture.sniffer import PassiveSniffer


# ---------------------------------------------------------------------------
# Mock scapy layer classes — needed because scapy is not installed in tests.
# The handlers import scapy inside try/except, so we install mock modules.
# ---------------------------------------------------------------------------

class _MockUDP:
    """Stand-in for scapy.layers.inet.UDP."""


class _MockTCP:
    """Stand-in for scapy.layers.inet.TCP."""


class _MockIP:
    """Stand-in for scapy.layers.inet.IP."""


class _MockDNSRR:
    """Stand-in for scapy.layers.dns.DNSRR."""


@pytest.fixture(autouse=True)
def _mock_scapy_modules():
    """Install fake scapy modules so handler imports succeed."""
    inet_mod = types.ModuleType("scapy.layers.inet")
    inet_mod.UDP = _MockUDP
    inet_mod.TCP = _MockTCP
    inet_mod.IP = _MockIP

    dns_mod = types.ModuleType("scapy.layers.dns")
    dns_mod.DNSRR = _MockDNSRR

    layers_mod = types.ModuleType("scapy.layers")

    scapy_mod = types.ModuleType("scapy")
    scapy_all_mod = types.ModuleType("scapy.all")

    saved = {}
    mods = {
        "scapy": scapy_mod,
        "scapy.all": scapy_all_mod,
        "scapy.layers": layers_mod,
        "scapy.layers.inet": inet_mod,
        "scapy.layers.dns": dns_mod,
    }
    for name, mod in mods.items():
        saved[name] = sys.modules.get(name)
        sys.modules[name] = mod

    yield

    for name, original in saved.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


# ---------------------------------------------------------------------------
# Helpers — build mock packets
# ---------------------------------------------------------------------------

def _make_dns_response_packet(
    qname: str = "api.openai.com.",
    rdata: str = "104.16.6.34",
    rtype: int = 1,
) -> MagicMock:
    """Build a mock scapy packet with a DNS answer record."""
    rr = MagicMock()
    rr.type = rtype
    rr.rrname = qname.encode()
    rr.rdata = rdata

    dns = MagicMock()
    dns.ancount = 1
    dns.an.__getitem__ = lambda self, i: rr

    packet = MagicMock()
    packet.getlayer.return_value = dns

    def haslayer_side_effect(layer):
        return layer in (_MockUDP, _MockDNSRR)

    packet.haslayer = haslayer_side_effect
    return packet


def _build_client_hello(sni_hostname: str = "api.openai.com") -> bytes:
    """Build a minimal TLS ClientHello with SNI extension."""
    sni_bytes = sni_hostname.encode("ascii")
    sni_name_len = len(sni_bytes)

    # SNI extension data: list_len(2) + type(1) + name_len(2) + name
    sni_list_len = 1 + 2 + sni_name_len  # type + name_len + name
    sni_ext_data = (
        sni_list_len.to_bytes(2, "big")
        + b"\x00"  # host_name type
        + sni_name_len.to_bytes(2, "big")
        + sni_bytes
    )

    # Extension: type(2) + length(2) + data
    ext_entry = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data

    # Extensions block: total_len(2) + entries
    extensions = len(ext_entry).to_bytes(2, "big") + ext_entry

    # ClientHello body:
    # client_version(2) + random(32) + session_id_len(1) + cipher_suites_len(2)
    # + cipher_suite(2) + compression_len(1) + compression(1) + extensions
    client_hello_body = (
        b"\x03\x03"           # TLS 1.2
        + b"\x00" * 32        # random
        + b"\x00"             # session ID length = 0
        + b"\x00\x02"         # cipher suites length = 2
        + b"\x00\x2f"         # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01"             # compression methods length = 1
        + b"\x00"             # null compression
        + extensions
    )

    # Handshake header: type(1) + length(3)
    handshake = b"\x01" + len(client_hello_body).to_bytes(3, "big") + client_hello_body

    # TLS record: content_type(1) + version(2) + length(2) + handshake
    tls_record = (
        b"\x16"               # content type: handshake
        + b"\x03\x01"         # TLS 1.0 record version
        + len(handshake).to_bytes(2, "big")
        + handshake
    )

    return tls_record


def _make_tls_packet(
    sni_hostname: str = "api.openai.com",
    dst_ip: str = "104.16.6.34",
    dst_port: int = 443,
) -> MagicMock:
    """Build a mock scapy packet with a TLS ClientHello containing SNI."""
    payload_bytes = _build_client_hello(sni_hostname)

    tcp = MagicMock()
    tcp.dport = dst_port
    tcp.payload = payload_bytes

    ip = MagicMock()
    ip.dst = dst_ip

    layer_map = {_MockTCP: tcp, _MockIP: ip}

    packet = MagicMock()
    packet.haslayer.side_effect = lambda layer: layer in (_MockTCP, _MockIP)
    packet.__getitem__ = MagicMock(side_effect=lambda layer: layer_map[layer])

    return packet


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHandleDns:
    def test_caches_a_record(self):
        sniffer = PassiveSniffer()
        packet = _make_dns_response_packet(
            qname="api.openai.com.", rdata="104.16.6.34", rtype=1,
        )
        sniffer._handle_dns(packet)
        assert sniffer.get_hostname("104.16.6.34", 443) == "api.openai.com"

    def test_caches_aaaa_record(self):
        sniffer = PassiveSniffer()
        packet = _make_dns_response_packet(
            qname="example.com.", rdata="2606:4700::1", rtype=28,
        )
        sniffer._handle_dns(packet)
        assert sniffer.get_hostname("2606:4700::1", 443) == "example.com"

    def test_strips_trailing_dot(self):
        sniffer = PassiveSniffer()
        packet = _make_dns_response_packet(qname="trailing.dot.com.")
        sniffer._handle_dns(packet)
        assert sniffer.get_hostname("104.16.6.34", 80) == "trailing.dot.com"


class TestHandleTls:
    def test_extracts_sni(self):
        sniffer = PassiveSniffer()
        packet = _make_tls_packet(
            sni_hostname="api.openai.com", dst_ip="104.16.6.34", dst_port=443,
        )
        sniffer._handle_tls(packet)
        assert sniffer.get_hostname("104.16.6.34", 443) == "api.openai.com"

    def test_different_ports(self):
        sniffer = PassiveSniffer()
        packet = _make_tls_packet(
            sni_hostname="secure.example.com", dst_ip="10.0.0.1", dst_port=8443,
        )
        sniffer._handle_tls(packet)
        assert sniffer.get_hostname("10.0.0.1", 8443) == "secure.example.com"
        # Different port should not match
        assert sniffer.get_hostname("10.0.0.1", 443) == ""


class TestParseSniFromClientHello:
    def test_parses_known_bytes(self):
        data = _build_client_hello("docs.cloudflare.com")
        result = PassiveSniffer._parse_sni_from_client_hello(data)
        assert result == "docs.cloudflare.com"

    def test_various_hostnames(self):
        for hostname in ["a.b.c.d.example.com", "short.io", "x"]:
            data = _build_client_hello(hostname)
            result = PassiveSniffer._parse_sni_from_client_hello(data)
            assert result == hostname

    def test_returns_none_for_non_tls(self):
        assert PassiveSniffer._parse_sni_from_client_hello(b"\x00" * 10) is None

    def test_returns_none_for_truncated(self):
        data = _build_client_hello("example.com")
        assert PassiveSniffer._parse_sni_from_client_hello(data[:20]) is None


class TestGetHostnamePriority:
    def test_sni_preferred_over_dns(self):
        sniffer = PassiveSniffer()
        with sniffer._lock:
            sniffer._dns_cache["10.0.0.1"] = "dns-name.example.com"
            sniffer._sni_cache[("10.0.0.1", 443)] = "sni-name.example.com"

        assert sniffer.get_hostname("10.0.0.1", 443) == "sni-name.example.com"

    def test_dns_used_when_no_sni(self):
        sniffer = PassiveSniffer()
        with sniffer._lock:
            sniffer._dns_cache["10.0.0.1"] = "dns-name.example.com"

        assert sniffer.get_hostname("10.0.0.1", 443) == "dns-name.example.com"

    def test_empty_when_nothing_cached(self):
        sniffer = PassiveSniffer()
        assert sniffer.get_hostname("10.0.0.1", 443) == ""


class TestGracefulFallback:
    def test_start_returns_false_without_scapy(self):
        """When scapy.all import fails, start() returns False."""
        sniffer = PassiveSniffer()
        # Remove mock scapy.all so the import fails inside start()
        saved = sys.modules.pop("scapy.all", None)
        try:
            result = sniffer.start()
            assert result is False
            assert not sniffer.is_available
        finally:
            if saved is not None:
                sys.modules["scapy.all"] = saved

    def test_get_hostname_works_without_start(self):
        sniffer = PassiveSniffer()
        assert sniffer.get_hostname("1.2.3.4", 443) == ""
        assert not sniffer.is_available


class TestThreadSafety:
    def test_concurrent_reads_and_writes(self):
        sniffer = PassiveSniffer()
        errors: list[Exception] = []

        def writer():
            try:
                for i in range(100):
                    with sniffer._lock:
                        sniffer._dns_cache[f"10.0.0.{i % 256}"] = f"host-{i}.example.com"
                        sniffer._sni_cache[(f"10.0.0.{i % 256}", 443)] = f"sni-{i}.example.com"
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for i in range(100):
                    sniffer.get_hostname(f"10.0.0.{i % 256}", 443)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
