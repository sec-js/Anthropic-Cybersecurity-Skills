"""
Tests for skills/detecting-ntlm-relay-with-event-correlation/scripts/detect_ntlm_relay.py

The script has a hard sys.exit(1) if python-evtx / lxml are absent, so we stub
both packages in sys.modules before the module is loaded.  All functions under
test operate on plain Python dicts — they never touch lxml after module import.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Stub heavy native packages before the module is imported.
_lxml_etree_stub = MagicMock()
_lxml_etree_stub.XMLSyntaxError = Exception  # must be a real exception class
sys.modules.setdefault("Evtx", MagicMock())
sys.modules.setdefault("Evtx.Evtx", MagicMock())
sys.modules.setdefault("lxml", MagicMock())
sys.modules.setdefault("lxml.etree", _lxml_etree_stub)

SCRIPT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "detecting-ntlm-relay-with-event-correlation"
    / "scripts"
    / "detect_ntlm_relay.py"
)

spec = importlib.util.spec_from_file_location("detect_ntlm_relay", SCRIPT_PATH)
ntlm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ntlm)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ntlm_event(
    user="alice",
    source_ip="192.168.1.50",
    workstation="WORKSTATION1",
    computer="SERVER1",
    timestamp="2024-01-15T10:00:00Z",
    lm_package="NTLM V2",
    logon_type="3",
    auth_pkg="NTLM",
    event_id=4624,
):
    return {
        "EventID": event_id,
        "LogonType": logon_type,
        "AuthenticationPackageName": auth_pkg,
        "TargetUserName": user,
        "WorkstationName": workstation,
        "IpAddress": source_ip,
        "Computer": computer,
        "TimeCreated": timestamp,
        "LmPackageName": lm_package,
    }


# ---------------------------------------------------------------------------
# is_internal_ip
# ---------------------------------------------------------------------------


class TestIsInternalIp:
    def test_class_a_private(self):
        assert ntlm.is_internal_ip("10.0.0.1") is True
        assert ntlm.is_internal_ip("10.255.255.255") is True

    def test_class_b_private(self):
        assert ntlm.is_internal_ip("172.16.0.1") is True
        assert ntlm.is_internal_ip("172.31.255.255") is True

    def test_class_b_boundary_below(self):
        assert ntlm.is_internal_ip("172.15.0.1") is False

    def test_class_b_boundary_above(self):
        assert ntlm.is_internal_ip("172.32.0.1") is False

    def test_class_c_private(self):
        assert ntlm.is_internal_ip("192.168.0.1") is True
        assert ntlm.is_internal_ip("192.168.255.255") is True

    def test_public_addresses(self):
        assert ntlm.is_internal_ip("8.8.8.8") is False
        assert ntlm.is_internal_ip("1.1.1.1") is False
        assert ntlm.is_internal_ip("203.0.113.5") is False

    def test_loopback_excluded(self):
        assert ntlm.is_internal_ip("127.0.0.1") is False

    def test_ipv6_loopback_excluded(self):
        assert ntlm.is_internal_ip("::1") is False

    def test_empty_and_placeholder(self):
        assert ntlm.is_internal_ip("") is False
        assert ntlm.is_internal_ip("-") is False

    def test_non_ipv4_format(self):
        assert ntlm.is_internal_ip("not-an-ip") is False


# ---------------------------------------------------------------------------
# detect_ip_hostname_mismatch
# ---------------------------------------------------------------------------


class TestDetectIpHostnameMismatch:
    def test_flags_mismatch(self):
        inventory = {"WORKSTATION1": "192.168.1.10"}
        events = [_ntlm_event(source_ip="192.168.1.99")]  # wrong IP
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["detection_type"] == "IP-Hostname Mismatch (NTLM Relay Indicator)"
        assert findings[0]["actual_source_ip"] == "192.168.1.99"
        assert findings[0]["expected_source_ip"] == "192.168.1.10"

    def test_no_finding_when_ip_matches(self):
        inventory = {"WORKSTATION1": "192.168.1.10"}
        events = [_ntlm_event(source_ip="192.168.1.10")]  # correct IP
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_skips_machine_accounts(self):
        inventory = {"WORKSTATION1": "10.0.0.1"}
        events = [_ntlm_event(user="SERVER2$", source_ip="10.0.0.99")]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_skips_anonymous_logon(self):
        inventory = {"WORKSTATION1": "10.0.0.1"}
        events = [_ntlm_event(user="ANONYMOUS LOGON", source_ip="10.0.0.99")]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_skips_localhost_source(self):
        inventory = {"WORKSTATION1": "10.0.0.1"}
        events = [_ntlm_event(source_ip="127.0.0.1")]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_ignores_unknown_workstation(self):
        inventory = {"OTHER": "192.168.1.5"}
        events = [_ntlm_event(workstation="WORKSTATION1", source_ip="10.9.9.9")]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_skips_non_4624_events(self):
        inventory = {"WORKSTATION1": "192.168.1.10"}
        events = [_ntlm_event(source_ip="192.168.1.99", event_id=4625)]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_skips_non_ntlm_auth(self):
        inventory = {"WORKSTATION1": "192.168.1.10"}
        events = [_ntlm_event(source_ip="192.168.1.99", auth_pkg="Kerberos")]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert findings == []

    def test_multiple_mismatches(self):
        inventory = {"WS1": "10.0.0.1", "WS2": "10.0.0.2"}
        events = [
            _ntlm_event(workstation="WS1", source_ip="10.0.0.99", computer="SRV1"),
            _ntlm_event(workstation="WS2", source_ip="10.0.0.99", computer="SRV2"),
        ]
        findings = ntlm.detect_ip_hostname_mismatch(events, inventory)
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# detect_ntlmv1_downgrade
# ---------------------------------------------------------------------------


class TestDetectNtlmv1Downgrade:
    def test_detects_ntlmv1(self):
        events = [_ntlm_event(lm_package="NTLM V1")]
        findings = ntlm.detect_ntlmv1_downgrade(events)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["target_user"] == "alice"

    def test_no_finding_for_ntlmv2(self):
        events = [_ntlm_event(lm_package="NTLM V2")]
        findings = ntlm.detect_ntlmv1_downgrade(events)
        assert findings == []

    def test_skips_machine_accounts(self):
        events = [_ntlm_event(user="DC01$", lm_package="NTLM V1")]
        findings = ntlm.detect_ntlmv1_downgrade(events)
        assert findings == []

    def test_counts_events_per_user(self):
        events = [
            _ntlm_event(user="alice", lm_package="NTLM V1", computer="SRV1"),
            _ntlm_event(user="alice", lm_package="NTLM V1", computer="SRV2"),
        ]
        findings = ntlm.detect_ntlmv1_downgrade(events)
        assert len(findings) == 1
        assert findings[0]["ntlmv1_event_count"] == 2

    def test_skips_wrong_event_id(self):
        events = [_ntlm_event(event_id=4625, lm_package="NTLM V1")]
        findings = ntlm.detect_ntlmv1_downgrade(events)
        assert findings == []


# ---------------------------------------------------------------------------
# detect_rapid_multi_host_auth
# ---------------------------------------------------------------------------


def _rapid_event(i, user="alice", source_ip="192.168.1.99"):
    """Create event for server SRV{i} at timestamp second i."""
    return _ntlm_event(
        user=user,
        source_ip=source_ip,
        computer=f"SRV{i}",
        timestamp=f"2024-01-15T10:00:{i:02d}Z",
    )


class TestDetectRapidMultiHostAuth:
    def test_triggers_at_threshold(self):
        events = [_rapid_event(i) for i in range(4)]  # 4 unique targets > threshold 3
        findings = ntlm.detect_rapid_multi_host_auth(events, window_seconds=120, threshold=3)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["unique_targets"] >= 3

    def test_no_finding_below_threshold(self):
        events = [_rapid_event(i) for i in range(2)]  # 2 unique targets < threshold 3
        findings = ntlm.detect_rapid_multi_host_auth(events, window_seconds=120, threshold=3)
        assert findings == []

    def test_skips_machine_accounts(self):
        events = [_rapid_event(i, user="SRV1$") for i in range(5)]
        findings = ntlm.detect_rapid_multi_host_auth(events, window_seconds=120, threshold=3)
        assert findings == []

    def test_separate_finding_per_source_user_pair(self):
        alice_events = [_rapid_event(i, user="alice", source_ip="10.0.0.1") for i in range(4)]
        bob_events = [_rapid_event(i, user="bob", source_ip="10.0.0.2") for i in range(4)]
        findings = ntlm.detect_rapid_multi_host_auth(
            alice_events + bob_events, window_seconds=120, threshold=3
        )
        users = {f["target_user"] for f in findings}
        assert "alice" in users
        assert "bob" in users

    def test_skips_events_with_bad_timestamp(self):
        events = [
            {**_rapid_event(0), "TimeCreated": "INVALID"},
            {**_rapid_event(1), "TimeCreated": "INVALID"},
            {**_rapid_event(2), "TimeCreated": "INVALID"},
            {**_rapid_event(3), "TimeCreated": "INVALID"},
        ]
        # Bad timestamps are silently skipped — no crash expected
        findings = ntlm.detect_rapid_multi_host_auth(events, window_seconds=120, threshold=3)
        assert findings == []


# ---------------------------------------------------------------------------
# detect_machine_account_relay
# ---------------------------------------------------------------------------


class TestDetectMachineAccountRelay:
    def _machine_event(self, ip, computer="TARGET"):
        return {
            "EventID": 4624,
            "LogonType": "3",
            "AuthenticationPackageName": "NTLM",
            "TargetUserName": "DC01$",
            "IpAddress": ip,
            "WorkstationName": "ATTACKER",
            "Computer": computer,
            "TimeCreated": "2024-01-15T10:00:00Z",
            "LmPackageName": "NTLM V2",
        }

    def test_flags_machine_account_from_multiple_source_ips(self):
        # Two events for the same machine account from different IPs indicates relay
        events = [
            self._machine_event("192.168.1.5", "SRV1"),
            self._machine_event("10.0.0.99", "SRV2"),
        ]
        findings = ntlm.detect_machine_account_relay(events)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["machine_account"] == "DC01$"
        assert len(findings[0]["source_ips"]) == 2

    def test_single_source_ip_no_finding(self):
        # Same IP twice is normal — no finding
        events = [
            self._machine_event("192.168.1.5", "SRV1"),
            self._machine_event("192.168.1.5", "SRV2"),
        ]
        findings = ntlm.detect_machine_account_relay(events)
        assert findings == []

    def test_ignores_non_machine_accounts(self):
        events = [_ntlm_event(user="alice", source_ip="10.0.0.5")]
        findings = ntlm.detect_machine_account_relay(events)
        assert findings == []

    def test_ignores_localhost_source_ip(self):
        events = [
            self._machine_event("127.0.0.1", "SRV1"),
            self._machine_event("::1", "SRV2"),
        ]
        findings = ntlm.detect_machine_account_relay(events)
        assert findings == []
