"""
Tests for skills/detecting-pass-the-hash-attacks/scripts/agent.py

Covers detect_pth_patterns: multi-target severity thresholds, CRITICAL vs HIGH
boundaries, legitimate source filtering, admin-account detection, and the
error-dict passthrough when the Evtx package is absent.

All functions under test operate on plain Python lists of dicts, so no EVTX
file or Windows event infrastructure is required.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

# Evtx is Windows-only and not available here; it is imported inside a try/except
# in the agent, so no stub is needed — evtx will simply be None.
sys.modules.setdefault("Evtx", MagicMock())
sys.modules.setdefault("Evtx.Evtx", MagicMock())

AGENT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "detecting-pass-the-hash-attacks"
    / "scripts"
    / "agent.py"
)

spec = importlib.util.spec_from_file_location("pth_agent", AGENT_PATH)
pth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pth)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _event(account="alice", source_ip="10.0.0.5", computer="SRV1"):
    return {
        "account": account,
        "source_ip": source_ip,
        "computer": computer,
        "logon_type": 3,
        "auth_package": "NTLM",
    }


def _events_to(computers, account="alice", source_ip="10.0.0.5"):
    """One event per computer from the same source IP / account."""
    return [_event(account=account, source_ip=source_ip, computer=c) for c in computers]


# ---------------------------------------------------------------------------
# Basic threshold tests
# ---------------------------------------------------------------------------


class TestDetectPthPatterns:
    def test_below_threshold_no_finding(self):
        # 2 unique targets — default threshold is 3
        events = _events_to(["SRV1", "SRV2"])
        findings = pth.detect_pth_patterns(events, target_threshold=3)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings == []

    def test_at_threshold_raises_high(self):
        events = _events_to(["SRV1", "SRV2", "SRV3"])
        findings = pth.detect_pth_patterns(events, target_threshold=3)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert len(ntlm_findings) == 1
        assert ntlm_findings[0]["severity"] == "HIGH"
        assert ntlm_findings[0]["target_count"] == 3

    def test_ten_or_more_targets_is_critical(self):
        events = _events_to([f"SRV{i}" for i in range(10)])
        findings = pth.detect_pth_patterns(events, target_threshold=3)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert len(ntlm_findings) == 1
        assert ntlm_findings[0]["severity"] == "CRITICAL"

    def test_nine_targets_is_still_high(self):
        # CRITICAL threshold is >= 10; 9 is HIGH
        events = _events_to([f"SRV{i}" for i in range(9)])
        findings = pth.detect_pth_patterns(events, target_threshold=3)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings[0]["severity"] == "HIGH"

    def test_custom_threshold_respected(self):
        events = _events_to(["SRV1", "SRV2"])  # 2 unique targets
        # With threshold=2 this should fire
        findings = pth.detect_pth_patterns(events, target_threshold=2)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert len(ntlm_findings) == 1

    def test_same_computer_repeated_does_not_inflate_count(self):
        # 5 events all to SRV1 — still only 1 unique target
        events = [_event(computer="SRV1") for _ in range(5)]
        findings = pth.detect_pth_patterns(events, target_threshold=3)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings == []

    def test_mitre_technique_tagged(self):
        events = _events_to(["SRV1", "SRV2", "SRV3"])
        findings = pth.detect_pth_patterns(events, target_threshold=3)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings[0]["mitre"] == "T1550.002"


# ---------------------------------------------------------------------------
# Legitimate source filtering
# ---------------------------------------------------------------------------


class TestLegitimateSourceFiltering:
    def test_localhost_ipv4_skipped(self):
        events = _events_to(["SRV1", "SRV2", "SRV3"], source_ip="127.0.0.1")
        findings = pth.detect_pth_patterns(events)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings == []

    def test_localhost_ipv6_skipped(self):
        events = _events_to(["SRV1", "SRV2", "SRV3"], source_ip="::1")
        findings = pth.detect_pth_patterns(events)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings == []

    def test_placeholder_dash_skipped(self):
        events = _events_to(["SRV1", "SRV2", "SRV3"], source_ip="-")
        findings = pth.detect_pth_patterns(events)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings == []

    def test_empty_source_ip_skipped(self):
        events = _events_to(["SRV1", "SRV2", "SRV3"], source_ip="")
        findings = pth.detect_pth_patterns(events)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert ntlm_findings == []

    def test_private_ip_not_filtered(self):
        # 10.x.x.x is NOT in LEGITIMATE_SOURCES — it should be checked
        events = _events_to(["SRV1", "SRV2", "SRV3"], source_ip="10.5.0.50")
        findings = pth.detect_pth_patterns(events)
        ntlm_findings = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert len(ntlm_findings) == 1


# ---------------------------------------------------------------------------
# Multiple source IP / account combinations
# ---------------------------------------------------------------------------


class TestMultipleSourceIpAccounts:
    def test_two_distinct_sources_each_trigger(self):
        alice_events = _events_to(["A1", "A2", "A3"], account="alice", source_ip="10.0.0.1")
        bob_events = _events_to(["B1", "B2", "B3"], account="bob", source_ip="10.0.0.2")
        findings = pth.detect_pth_patterns(alice_events + bob_events)
        ntlm = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        accounts = {f["account"] for f in ntlm}
        assert "alice" in accounts
        assert "bob" in accounts

    def test_same_ip_different_accounts_tracked_separately(self):
        # Same source IP but different accounts — should produce two findings
        alice_events = _events_to(["A1", "A2", "A3"], account="alice", source_ip="10.0.0.1")
        bob_events = _events_to(["B1", "B2", "B3"], account="bob", source_ip="10.0.0.1")
        findings = pth.detect_pth_patterns(alice_events + bob_events)
        ntlm = [f for f in findings if f.get("type") == "ntlm_type3_multi_target"]
        assert len(ntlm) == 2


# ---------------------------------------------------------------------------
# Admin account detection
# ---------------------------------------------------------------------------


class TestAdminNtlmDetection:
    def test_administrator_two_logons_flags_high(self):
        events = [
            _event(account="administrator", source_ip="10.0.0.5", computer="SRV1"),
            _event(account="administrator", source_ip="10.0.0.5", computer="SRV2"),
        ]
        findings = pth.detect_pth_patterns(events)
        admin_findings = [f for f in findings if f.get("type") == "admin_ntlm"]
        assert len(admin_findings) == 1
        assert admin_findings[0]["severity"] == "HIGH"

    def test_admin_alias_detected(self):
        events = [
            _event(account="admin", source_ip="10.0.0.5", computer="SRV1"),
            _event(account="admin", source_ip="10.0.0.5", computer="SRV2"),
        ]
        findings = pth.detect_pth_patterns(events)
        admin_findings = [f for f in findings if f.get("type") == "admin_ntlm"]
        assert len(admin_findings) == 1

    def test_single_admin_logon_not_flagged(self):
        events = [_event(account="administrator", source_ip="10.0.0.5", computer="SRV1")]
        findings = pth.detect_pth_patterns(events)
        admin_findings = [f for f in findings if f.get("type") == "admin_ntlm"]
        assert admin_findings == []

    def test_admin_from_localhost_not_flagged(self):
        events = [
            _event(account="administrator", source_ip="127.0.0.1", computer="SRV1"),
            _event(account="administrator", source_ip="127.0.0.1", computer="SRV2"),
        ]
        findings = pth.detect_pth_patterns(events)
        admin_findings = [f for f in findings if f.get("type") == "admin_ntlm"]
        assert admin_findings == []


# ---------------------------------------------------------------------------
# Error dict passthrough (evtx not installed)
# ---------------------------------------------------------------------------


class TestErrorDictPassthrough:
    def test_error_dict_returned_as_single_finding(self):
        error = {"error": "python-evtx not installed: pip install python-evtx"}
        findings = pth.detect_pth_patterns(error)
        assert len(findings) == 1
        assert "error" in findings[0]

    def test_empty_event_list_no_findings(self):
        findings = pth.detect_pth_patterns([])
        assert findings == []
