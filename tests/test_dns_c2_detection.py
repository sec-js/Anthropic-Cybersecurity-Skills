"""
Tests for skills/detecting-command-and-control-over-dns/scripts/agent.py

Focuses on pure, dependency-free functions:
  shannon_entropy, extract_subdomain, is_whitelisted, parse_timestamp

numpy, tldextract, and sklearn are stubbed so the module loads regardless of
whether those packages are installed in the test environment.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Stub optional heavyweight dependencies before import.
sys.modules.setdefault("numpy", MagicMock())
sys.modules.setdefault("tldextract", MagicMock())
sys.modules.setdefault("sklearn", MagicMock())
sys.modules.setdefault("sklearn.ensemble", MagicMock())
sys.modules.setdefault("sklearn.model_selection", MagicMock())
sys.modules.setdefault("sklearn.metrics", MagicMock())
sys.modules.setdefault("sklearn.preprocessing", MagicMock())

AGENT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "detecting-command-and-control-over-dns"
    / "scripts"
    / "agent.py"
)

spec = importlib.util.spec_from_file_location("dns_c2_agent", AGENT_PATH)
dns_c2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns_c2)

# tldextract is stubbed, so the module will use the fallback split() path.
# Force HAS_TLDEXTRACT = False so tests exercise predictable code paths.
dns_c2.HAS_TLDEXTRACT = False


# ---------------------------------------------------------------------------
# shannon_entropy
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_string_returns_zero(self):
        assert dns_c2.shannon_entropy("") == 0.0

    def test_single_char_repeated_returns_zero(self):
        assert dns_c2.shannon_entropy("aaaa") == 0.0
        assert dns_c2.shannon_entropy("z" * 100) == 0.0

    def test_two_equally_likely_chars_returns_one(self):
        # "ab" -> p(a)=0.5, p(b)=0.5 -> H = 1.0
        result = dns_c2.shannon_entropy("ab")
        assert abs(result - 1.0) < 1e-9

    def test_four_equally_likely_chars_returns_two(self):
        result = dns_c2.shannon_entropy("abcd")
        assert abs(result - 2.0) < 1e-9

    def test_high_entropy_random_looking_string(self):
        # A long, varied string should score well above 3 bits/char
        result = dns_c2.shannon_entropy("a1b2c3d4e5f6g7h8i9j0ABCDEFGH")
        assert result > 3.5

    def test_low_entropy_repetitive_string(self):
        result = dns_c2.shannon_entropy("aaaaaaaaab")  # mostly 'a'
        assert result < 0.6

    def test_base32_like_exfil_subdomain(self):
        # Base32-encoded payloads used by dnscat/iodine are typically 3.5-4.5 bits/char
        result = dns_c2.shannon_entropy("jbswy3dpfqqfo33snrscc")
        assert result > 3.0


# ---------------------------------------------------------------------------
# extract_subdomain (fallback split() path, HAS_TLDEXTRACT=False)
# ---------------------------------------------------------------------------


class TestExtractSubdomain:
    def test_standard_three_part_fqdn(self):
        sub, base = dns_c2.extract_subdomain("api.example.com")
        assert base == "example.com"
        assert sub == "api"

    def test_two_part_fqdn_no_subdomain(self):
        sub, base = dns_c2.extract_subdomain("example.com")
        assert base == "example.com"
        assert sub == ""

    def test_deep_subdomain(self):
        sub, base = dns_c2.extract_subdomain("a.b.c.example.com")
        assert base == "example.com"
        assert "a" in sub

    def test_trailing_dot_stripped(self):
        sub, base = dns_c2.extract_subdomain("api.example.com.")
        assert base == "example.com"
        assert sub == "api"

    def test_lowercases_input(self):
        sub, base = dns_c2.extract_subdomain("API.EXAMPLE.COM")
        assert base == "example.com"
        assert sub == "api"

    def test_exfil_like_subdomain(self):
        # extract_subdomain lowercases the FQDN; use lowercase expected value
        payload_sub = "agvsbg8gd29ybgq"
        sub, base = dns_c2.extract_subdomain(f"{payload_sub}.attacker.com")
        assert sub == payload_sub
        assert base == "attacker.com"


# ---------------------------------------------------------------------------
# is_whitelisted
# ---------------------------------------------------------------------------


class TestIsWhitelisted:
    def test_googleapis_whitelisted(self):
        assert dns_c2.is_whitelisted("storage.googleapis.com") is True

    def test_cloudfront_whitelisted(self):
        assert dns_c2.is_whitelisted("d1234.cloudfront.net") is True

    def test_akadns_whitelisted(self):
        assert dns_c2.is_whitelisted("edge01.akadns.net") is True

    def test_akamaiedge_whitelisted(self):
        assert dns_c2.is_whitelisted("a12345.akamaiedge.net") is True

    def test_windows_net_whitelisted(self):
        assert dns_c2.is_whitelisted("myapp.windows.net") is True

    def test_ptr_record_whitelisted(self):
        assert dns_c2.is_whitelisted("1.0.168.192.in-addr.arpa") is True

    def test_dmarc_whitelisted(self):
        # Pattern r".*\._dmarc\..*" requires a dot before _dmarc (e.g., selector._dmarc.domain)
        assert dns_c2.is_whitelisted("selector._dmarc.example.com") is True

    def test_spf_whitelisted(self):
        # Pattern r".*\._spf\..*" requires a dot before _spf
        assert dns_c2.is_whitelisted("include._spf.google.com") is True

    def test_unknown_domain_not_whitelisted(self):
        assert dns_c2.is_whitelisted("c2server.xyz") is False

    def test_lookalike_not_whitelisted(self):
        # 'googleapis-cdn.com' looks like googleapis but is NOT the real domain
        assert dns_c2.is_whitelisted("evil.googleapis-cdn.com") is False

    def test_known_tunneling_domain_not_whitelisted(self):
        assert dns_c2.is_whitelisted("aGVsbG8.attacker.com") is False


# ---------------------------------------------------------------------------
# parse_timestamp
# ---------------------------------------------------------------------------


class TestParseTimestamp:
    def test_iso_z_suffix_with_microseconds(self):
        # The "%Y-%m-%dT%H:%M:%S.%fZ" format requires microseconds before Z.
        ts = dns_c2.parse_timestamp("2024-01-15T10:30:00.000000Z")
        assert ts is not None
        assert ts.year == 2024
        assert ts.month == 1
        assert ts.day == 15
        assert ts.hour == 10

    def test_iso_z_suffix_no_microseconds_returns_none(self):
        # "2024-01-15T10:30:00Z" matches none of the configured formats — this
        # is a coverage gap worth noting: the production parser silently returns
        # None for plain-Z ISO timestamps.  Test documents the current behaviour.
        ts = dns_c2.parse_timestamp("2024-01-15T10:30:00Z")
        assert ts is None

    def test_iso_with_microseconds(self):
        ts = dns_c2.parse_timestamp("2024-06-20T14:22:33.123456")
        assert ts is not None
        assert ts.microsecond == 123456

    def test_iso_no_microseconds(self):
        ts = dns_c2.parse_timestamp("2024-06-20T14:22:33")
        assert ts is not None
        assert ts.second == 33

    def test_space_separated_with_microseconds(self):
        ts = dns_c2.parse_timestamp("2024-01-01 00:00:01.000000")
        assert ts is not None

    def test_space_separated_no_microseconds(self):
        ts = dns_c2.parse_timestamp("2024-01-01 12:00:00")
        assert ts is not None
        assert ts.hour == 12

    def test_unix_epoch_float(self):
        ts = dns_c2.parse_timestamp("1705315200.0")
        assert ts is not None
        assert ts.year == 2024

    def test_invalid_returns_none(self):
        assert dns_c2.parse_timestamp("not-a-timestamp") is None
        assert dns_c2.parse_timestamp("") is None
        assert dns_c2.parse_timestamp("99999999999999999") is None
