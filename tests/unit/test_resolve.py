"""Tests for the IP-to-organization resolver."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from trustrun.resolve import IpInfo, IpResolver, _parse_whois_org


class TestBuiltinCidrMatching:
    def test_azure_ip(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info = resolver.resolve("13.80.0.1")
        assert info.org == "Microsoft Azure"

    def test_aws_ip(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info = resolver.resolve("3.5.1.1")
        assert info.org == "Amazon AWS"

    def test_gcp_ip(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info = resolver.resolve("34.100.0.1")
        assert info.org == "Google Cloud"

    def test_cloudflare_ip(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info = resolver.resolve("104.16.0.1")
        assert info.org == "Cloudflare"

    def test_apple_ip(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info = resolver.resolve("17.253.144.10")
        assert info.org == "Apple Inc."

    def test_github_ip(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info = resolver.resolve("20.33.1.1")
        assert info.org == "GitHub/Microsoft"

    def test_unknown_ip_no_cidr_match(self):
        resolver = IpResolver()
        with (
            patch.object(resolver, "_reverse_dns", return_value=""),
            patch.object(resolver, "_whois_lookup", return_value=""),
        ):
            info = resolver.resolve("198.51.100.1")
        assert info.org == ""


class TestReverseDns:
    def test_hostname_returned(self):
        resolver = IpResolver()
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            return_value=("example.com", [], ["1.2.3.4"]),
        ):
            info = resolver.resolve("198.51.100.1")
        assert info.hostname == "example.com"

    def test_dns_failure_returns_empty(self):
        import socket

        resolver = IpResolver()
        with (
            patch(
                "trustrun.resolve.socket.gethostbyaddr",
                side_effect=socket.herror("not found"),
            ),
            patch.object(resolver, "_whois_lookup", return_value=""),
        ):
            info = resolver.resolve("198.51.100.1")
        assert info.hostname == ""


class TestHostnameSuffixMapping:
    def test_amazonaws_suffix(self):
        resolver = IpResolver()
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            return_value=("ec2-3-5-1-1.us-east-2.compute.amazonaws.com", [], []),
        ):
            info = resolver.resolve("198.51.100.2")
        assert info.org == "Amazon AWS"
        assert "amazonaws.com" in info.hostname

    def test_cloudfront_suffix(self):
        resolver = IpResolver()
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            return_value=(
                "server-13-224-64-45.sea19.r.cloudfront.net",
                [],
                [],
            ),
        ):
            info = resolver.resolve("198.51.100.3")
        assert info.org == "Amazon AWS"

    def test_azure_suffix(self):
        resolver = IpResolver()
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            return_value=("myapp.eastus.azure.com", [], []),
        ):
            info = resolver.resolve("198.51.100.4")
        assert info.org == "Microsoft Azure"


class TestWhoisParsing:
    def test_arin_orgname(self):
        whois_output = """\
NetRange:       192.168.0.0 - 192.168.255.255
CIDR:           192.168.0.0/16
OrgName:        Example Corp
OrgId:          EXAMP
"""
        assert _parse_whois_org(whois_output) == "Example Corp"

    def test_ripe_org_name(self):
        whois_output = """\
inetnum:        192.168.0.0 - 192.168.255.255
netname:        EXAMPLE-NET
org-name:       Example RIPE Org
"""
        assert _parse_whois_org(whois_output) == "Example RIPE Org"

    def test_fallback_to_netname(self):
        whois_output = """\
inetnum:        192.168.0.0 - 192.168.255.255
netname:        SOME-ISP-NET
descr:          Some ISP
"""
        assert _parse_whois_org(whois_output) == "SOME-ISP-NET"

    def test_empty_output(self):
        assert _parse_whois_org("") == ""

    def test_orgname_takes_priority_over_netname(self):
        whois_output = """\
netname:        AZURE-NET
OrgName:        Microsoft Corporation
"""
        assert _parse_whois_org(whois_output) == "Microsoft Corporation"


class TestWhoisLookup:
    @patch("trustrun.resolve.subprocess.run")
    def test_successful_whois(self, mock_run: MagicMock):
        mock_run.return_value = MagicMock(
            stdout="OrgName:        Test Org\n", returncode=0
        )
        resolver = IpResolver()
        # Use an IP not in CIDR ranges, mock DNS failure
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            side_effect=OSError("no ptr"),
        ):
            info = resolver.resolve("198.51.100.5")
        assert info.org == "Test Org"
        mock_run.assert_called_once()

    @patch("trustrun.resolve.subprocess.run")
    def test_whois_timeout(self, mock_run: MagicMock):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="whois", timeout=2)
        resolver = IpResolver()
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            side_effect=OSError("no ptr"),
        ):
            info = resolver.resolve("198.51.100.6")
        assert info.org == ""

    @patch("trustrun.resolve.subprocess.run")
    def test_whois_not_found(self, mock_run: MagicMock):
        mock_run.side_effect = FileNotFoundError("whois not installed")
        resolver = IpResolver()
        with patch(
            "trustrun.resolve.socket.gethostbyaddr",
            side_effect=OSError("no ptr"),
        ):
            info = resolver.resolve("198.51.100.7")
        assert info.org == ""


class TestCaching:
    def test_second_call_uses_cache(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value="") as mock_dns:
            resolver.resolve("17.0.0.1")
            resolver.resolve("17.0.0.1")
        # _reverse_dns should only be called once; second call hits cache
        mock_dns.assert_called_once()

    def test_different_ips_cached_independently(self):
        resolver = IpResolver()
        with patch.object(resolver, "_reverse_dns", return_value=""):
            info1 = resolver.resolve("17.0.0.1")
            info2 = resolver.resolve("3.5.0.1")
        assert info1.org == "Apple Inc."
        assert info2.org == "Amazon AWS"
        assert len(resolver._cache) == 2


class TestFallbackChain:
    def test_cidr_hit_skips_whois(self):
        """When CIDR matches, whois should never be called."""
        resolver = IpResolver()
        with (
            patch.object(resolver, "_reverse_dns", return_value="") as mock_dns,
            patch.object(resolver, "_whois_lookup") as mock_whois,
        ):
            info = resolver.resolve("17.0.0.1")
        assert info.org == "Apple Inc."
        mock_dns.assert_called_once()
        mock_whois.assert_not_called()

    def test_hostname_suffix_hit_skips_whois(self):
        """When hostname suffix matches, whois should not be called."""
        resolver = IpResolver()
        with (
            patch.object(
                resolver,
                "_reverse_dns",
                return_value="server.cloudfront.net",
            ),
            patch.object(resolver, "_whois_lookup") as mock_whois,
        ):
            info = resolver.resolve("198.51.100.8")
        assert info.org == "Amazon AWS"
        mock_whois.assert_not_called()

    def test_full_fallback_to_whois(self):
        """When CIDR and suffix both miss, whois is called."""
        resolver = IpResolver()
        with (
            patch.object(resolver, "_reverse_dns", return_value="unknown.example.com"),
            patch.object(resolver, "_whois_lookup", return_value="Fallback Org"),
        ):
            info = resolver.resolve("198.51.100.9")
        assert info.org == "Fallback Org"
        assert info.hostname == "unknown.example.com"

    def test_all_miss_returns_empty(self):
        """When nothing resolves, org is empty."""
        resolver = IpResolver()
        with (
            patch.object(resolver, "_reverse_dns", return_value=""),
            patch.object(resolver, "_whois_lookup", return_value=""),
        ):
            info = resolver.resolve("198.51.100.10")
        assert info.org == ""
        assert info.hostname == ""
