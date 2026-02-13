"""IP-to-organization resolution for enriching connection events.

Resolves IP addresses to human-readable organization names using:
1. Built-in CIDR→org map for major cloud providers (instant, no network)
2. Reverse DNS via socket.gethostbyaddr() with known suffix→org map
3. Fallback to ``whois`` CLI with aggressive caching
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Timeout in seconds for the whois subprocess.
_WHOIS_TIMEOUT = 2

# ---------------------------------------------------------------------------
# Built-in CIDR → organization mappings
# Covers the cloud providers HIPAA users care about most.
# ---------------------------------------------------------------------------

_BUILTIN_CIDRS: list[tuple[ipaddress.IPv4Network, str]] = [
    # Microsoft Azure
    (ipaddress.IPv4Network("13.64.0.0/11"), "Microsoft Azure"),
    (ipaddress.IPv4Network("20.0.0.0/11"), "Microsoft Azure"),
    (ipaddress.IPv4Network("40.64.0.0/10"), "Microsoft Azure"),
    (ipaddress.IPv4Network("52.96.0.0/12"), "Microsoft Azure"),
    (ipaddress.IPv4Network("104.40.0.0/13"), "Microsoft Azure"),
    # Amazon AWS
    (ipaddress.IPv4Network("3.0.0.0/9"), "Amazon AWS"),
    (ipaddress.IPv4Network("15.176.0.0/12"), "Amazon AWS"),
    (ipaddress.IPv4Network("16.0.0.0/8"), "Amazon AWS"),
    (ipaddress.IPv4Network("18.128.0.0/9"), "Amazon AWS"),
    (ipaddress.IPv4Network("52.0.0.0/11"), "Amazon AWS"),
    # Google Cloud
    (ipaddress.IPv4Network("34.0.0.0/9"), "Google Cloud"),
    (ipaddress.IPv4Network("35.184.0.0/13"), "Google Cloud"),
    (ipaddress.IPv4Network("104.196.0.0/14"), "Google Cloud"),
    (ipaddress.IPv4Network("130.211.0.0/16"), "Google Cloud"),
    # Cloudflare
    (ipaddress.IPv4Network("104.16.0.0/12"), "Cloudflare"),
    (ipaddress.IPv4Network("172.64.0.0/13"), "Cloudflare"),
    (ipaddress.IPv4Network("162.158.0.0/15"), "Cloudflare"),
    # Apple
    (ipaddress.IPv4Network("17.0.0.0/8"), "Apple Inc."),
    # GitHub / Microsoft
    (ipaddress.IPv4Network("20.33.0.0/16"), "GitHub/Microsoft"),
]

# ---------------------------------------------------------------------------
# Known hostname suffix → organization mappings
# Used to derive org from PTR records without a whois call.
# ---------------------------------------------------------------------------

_HOSTNAME_SUFFIX_MAP: list[tuple[str, str]] = [
    (".amazonaws.com", "Amazon AWS"),
    (".cloudfront.net", "Amazon AWS"),
    (".azure.com", "Microsoft Azure"),
    (".microsoft.com", "Microsoft"),
    (".windows.net", "Microsoft Azure"),
    (".google.com", "Google"),
    (".googleapis.com", "Google Cloud"),
    (".googleusercontent.com", "Google Cloud"),
    (".1e100.net", "Google"),
    (".cloudflare.com", "Cloudflare"),
    (".apple.com", "Apple Inc."),
    (".icloud.com", "Apple Inc."),
    (".akamai.net", "Akamai"),
    (".akamaiedge.net", "Akamai"),
    (".akamaitechnologies.com", "Akamai"),
    (".github.com", "GitHub/Microsoft"),
    (".github.io", "GitHub/Microsoft"),
    (".openai.com", "OpenAI"),
    (".fastly.net", "Fastly"),
]


@dataclass(frozen=True)
class IpInfo:
    """Resolved information about an IP address."""

    hostname: str = ""
    org: str = ""


@dataclass
class IpResolver:
    """Resolves IP addresses to hostname + organization.

    Resolution order:
      1. Built-in CIDR→org map (instant, covers major cloud providers)
      2. Reverse DNS via ``socket.gethostbyaddr()`` + known suffix→org map
      3. Fallback to ``whois <ip>`` subprocess (cached, 2s timeout)

    All results are cached for the lifetime of the resolver instance.
    """

    _cache: dict[str, IpInfo] = field(default_factory=dict)

    def resolve(self, ip: str) -> IpInfo:
        """Resolve an IP address to hostname and organization."""
        if ip in self._cache:
            return self._cache[ip]

        info = self._do_resolve(ip)
        self._cache[ip] = info
        return info

    def _do_resolve(self, ip: str) -> IpInfo:
        # Step 1: Check built-in CIDR map
        cidr_org = self._match_cidr(ip)

        # Step 2: Reverse DNS
        hostname = self._reverse_dns(ip)

        # If we got org from CIDR, we're done
        if cidr_org:
            return IpInfo(hostname=hostname, org=cidr_org)

        # Step 3: Try to derive org from hostname suffix
        if hostname:
            suffix_org = self._match_hostname_suffix(hostname)
            if suffix_org:
                return IpInfo(hostname=hostname, org=suffix_org)

        # Step 4: Fall back to whois
        whois_org = self._whois_lookup(ip)
        return IpInfo(hostname=hostname, org=whois_org)

    @staticmethod
    def _match_cidr(ip: str) -> str:
        """Check IP against built-in CIDR→org mappings."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return ""
        for network, org in _BUILTIN_CIDRS:
            if addr in network:
                return org
        return ""

    @staticmethod
    def _reverse_dns(ip: str) -> str:
        """Perform a PTR lookup for the given IP."""
        try:
            hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""

    @staticmethod
    def _match_hostname_suffix(hostname: str) -> str:
        """Derive organization from a hostname using known suffix mappings."""
        lower = hostname.lower()
        for suffix, org in _HOSTNAME_SUFFIX_MAP:
            if lower.endswith(suffix) or lower == suffix.lstrip("."):
                return org
        return ""

    @staticmethod
    def _whois_lookup(ip: str) -> str:
        """Shell out to ``whois`` and parse OrgName / org-name / netname."""
        try:
            result = subprocess.run(
                ["whois", ip],
                capture_output=True,
                text=True,
                timeout=_WHOIS_TIMEOUT,
            )
            return _parse_whois_org(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("whois lookup failed for %s: %s", ip, exc)
            return ""


def _parse_whois_org(text: str) -> str:
    """Extract the organization name from whois output.

    Looks for (in priority order):
      - ``OrgName:``  (ARIN)
      - ``org-name:`` (RIPE)
      - ``netname:``  (fallback)
    """
    org_name = ""
    net_name = ""

    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()

        if lower.startswith("orgname:"):
            org_name = stripped.split(":", 1)[1].strip()
        elif lower.startswith("org-name:"):
            org_name = stripped.split(":", 1)[1].strip()
        elif lower.startswith("netname:") and not net_name:
            net_name = stripped.split(":", 1)[1].strip()

    return org_name or net_name
