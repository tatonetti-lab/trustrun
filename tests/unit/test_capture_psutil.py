"""Tests for the psutil capture backend."""

from __future__ import annotations

import os
from collections import namedtuple
from unittest.mock import MagicMock, patch

from trustrun.capture.psutil_ import PsutilCapture
from trustrun.capture.sniffer import PassiveSniffer
from trustrun.resolve import IpInfo

# Mock psutil connection objects
MockAddr = namedtuple("MockAddr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["raddr", "laddr", "type", "status"])


def _make_conn(
    remote_ip: str = "1.2.3.4",
    remote_port: int = 443,
    local_ip: str = "192.168.1.100",
    local_port: int = 54321,
) -> MockConn:
    import socket

    return MockConn(
        raddr=MockAddr(remote_ip, remote_port),
        laddr=MockAddr(local_ip, local_port),
        type=socket.SOCK_STREAM,
        status="ESTABLISHED",
    )


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo())
@patch("trustrun.capture.psutil_.psutil.Process")
def test_poll_returns_new_connections(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []
    proc.net_connections.return_value = [
        _make_conn("1.2.3.4", 443),
        _make_conn("5.6.7.8", 80),
    ]
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())

    events = capture.poll()
    assert len(events) == 2
    assert events[0].remote_ip == "1.2.3.4"
    assert events[0].remote_port == 443
    assert events[1].remote_ip == "5.6.7.8"


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo())
@patch("trustrun.capture.psutil_.psutil.Process")
def test_poll_deduplicates(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []

    conns = [_make_conn("1.2.3.4", 443)]
    proc.net_connections.return_value = conns
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())

    events1 = capture.poll()
    assert len(events1) == 1

    # Same connections, no new events
    events2 = capture.poll()
    assert len(events2) == 0


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo())
@patch("trustrun.capture.psutil_.psutil.Process")
def test_poll_detects_departed_and_reconnected(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())

    # First poll: connection exists
    proc.net_connections.return_value = [_make_conn("1.2.3.4", 443)]
    capture.poll()

    # Second poll: connection departed
    proc.net_connections.return_value = []
    events = capture.poll()
    assert len(events) == 0

    # Third poll: reconnection detected
    proc.net_connections.return_value = [_make_conn("1.2.3.4", 443)]
    events = capture.poll()
    assert len(events) == 1


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo())
@patch("trustrun.capture.psutil_.psutil.Process")
def test_poll_skips_connections_without_raddr(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []

    no_raddr = MockConn(raddr=None, laddr=MockAddr("0.0.0.0", 8080), type=1, status="LISTEN")
    proc.net_connections.return_value = [no_raddr]
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())

    events = capture.poll()
    assert len(events) == 0


def test_not_running_returns_empty():
    capture = PsutilCapture()
    events = capture.poll()
    assert events == []


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
def test_start_stop_lifecycle(mock_sniffer_start: MagicMock):
    capture = PsutilCapture()
    assert not capture.is_running
    capture.start(1)
    assert capture.is_running
    capture.stop()
    assert not capture.is_running


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo(hostname="ptr.example.com", org="ExampleOrg"))
@patch("trustrun.capture.psutil_.psutil.Process")
def test_sniffer_hostname_takes_priority(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    """When the sniffer provides a hostname, it takes priority over the resolver."""
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []
    proc.net_connections.return_value = [_make_conn("1.2.3.4", 443)]
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())

    # Inject a mock sniffer that returns a hostname
    mock_sniffer = MagicMock(spec=PassiveSniffer)
    mock_sniffer.get_hostname.return_value = "sni.openai.com"
    mock_sniffer.is_available = True
    capture._sniffer = mock_sniffer

    events = capture.poll()
    assert len(events) == 1
    assert events[0].hostname == "sni.openai.com"
    assert events[0].org == "ExampleOrg"


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo(hostname="ptr.example.com", org="ExampleOrg"))
@patch("trustrun.capture.psutil_.psutil.Process")
def test_falls_back_to_resolver_when_sniffer_unavailable(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    """When the sniffer is unavailable, resolver hostname is used."""
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []
    proc.net_connections.return_value = [_make_conn("1.2.3.4", 443)]
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())
    # Sniffer is None (start returned False)
    assert capture._sniffer is None

    events = capture.poll()
    assert len(events) == 1
    assert events[0].hostname == "ptr.example.com"
    assert events[0].org == "ExampleOrg"


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
@patch("trustrun.capture.psutil_.IpResolver.resolve", return_value=IpInfo(hostname="ptr.example.com", org="ExampleOrg"))
@patch("trustrun.capture.psutil_.psutil.Process")
def test_sniffer_empty_falls_back_to_resolver(mock_process_cls: MagicMock, mock_resolve: MagicMock, mock_sniffer_start: MagicMock):
    """When the sniffer returns empty string, resolver hostname is used."""
    proc = MagicMock()
    proc.pid = os.getpid()
    proc.name.return_value = "test-proc"
    proc.children.return_value = []
    proc.net_connections.return_value = [_make_conn("1.2.3.4", 443)]
    mock_process_cls.return_value = proc

    capture = PsutilCapture()
    capture.start(os.getpid())

    # Inject a mock sniffer that returns empty (no match)
    mock_sniffer = MagicMock(spec=PassiveSniffer)
    mock_sniffer.get_hostname.return_value = ""
    capture._sniffer = mock_sniffer

    events = capture.poll()
    assert len(events) == 1
    assert events[0].hostname == "ptr.example.com"


@patch("trustrun.capture.psutil_.PassiveSniffer.start", return_value=False)
def test_sniffer_active_property(mock_sniffer_start: MagicMock):
    capture = PsutilCapture()
    capture.start(1)
    assert not capture.sniffer_active

    # Inject an active sniffer
    mock_sniffer = MagicMock(spec=PassiveSniffer)
    mock_sniffer.is_available = True
    capture._sniffer = mock_sniffer
    assert capture.sniffer_active
