"""
Tests for skills/conducting-social-engineering-penetration-test/scripts/process.py

Covers: analyze_campaign (rate calculations, status cascade, edge cases)
        and analyze_by_department (grouping, click/submit/report counting).

The 'requests' library is required by the module; it is stubbed out since
these functions have zero network I/O.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

_requests_stub = MagicMock()
_requests_stub.packages = MagicMock()
sys.modules.setdefault("requests", _requests_stub)

SCRIPT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "conducting-social-engineering-penetration-test"
    / "scripts"
    / "process.py"
)

spec = importlib.util.spec_from_file_location("se_process", SCRIPT_PATH)
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _campaign(name="Test Campaign", results=None, timeline=None):
    return {
        "name": name,
        "results": results or [],
        "timeline": timeline or [],
    }


def _result(status, dept="Engineering"):
    return {"status": status, "position": dept}


# ---------------------------------------------------------------------------
# analyze_campaign — status counting
# ---------------------------------------------------------------------------


class TestAnalyzeCampaignStatusCounting:
    def test_email_sent_increments_sent(self):
        c = _campaign(results=[_result("Email Sent")])
        stats = se.analyze_campaign(c)
        assert stats["emails_sent"] == 1
        assert stats["emails_opened"] == 0

    def test_email_opened_increments_sent_and_opened(self):
        c = _campaign(results=[_result("Email Opened")])
        stats = se.analyze_campaign(c)
        assert stats["emails_sent"] == 1
        assert stats["emails_opened"] == 1
        assert stats["links_clicked"] == 0

    def test_clicked_link_increments_sent_opened_clicked(self):
        c = _campaign(results=[_result("Clicked Link")])
        stats = se.analyze_campaign(c)
        assert stats["emails_sent"] == 1
        assert stats["emails_opened"] == 1
        assert stats["links_clicked"] == 1
        assert stats["credentials_submitted"] == 0

    def test_submitted_data_increments_all_counters(self):
        c = _campaign(results=[_result("Submitted Data")])
        stats = se.analyze_campaign(c)
        assert stats["emails_sent"] == 1
        assert stats["emails_opened"] == 1
        assert stats["links_clicked"] == 1
        assert stats["credentials_submitted"] == 1

    def test_email_reported_increments_sent_and_reported(self):
        c = _campaign(results=[_result("Email Reported")])
        stats = se.analyze_campaign(c)
        assert stats["emails_sent"] == 1
        assert stats["emails_reported"] == 1
        assert stats["emails_opened"] == 0

    def test_error_status_only_increments_errors(self):
        c = _campaign(results=[_result("Error")])
        stats = se.analyze_campaign(c)
        assert stats["errors"] == 1
        assert stats["emails_sent"] == 0

    def test_mixed_statuses(self):
        c = _campaign(results=[
            _result("Email Sent"),
            _result("Clicked Link"),
            _result("Submitted Data"),
            _result("Email Reported"),
        ])
        stats = se.analyze_campaign(c)
        assert stats["total_targets"] == 4
        assert stats["emails_sent"] == 4
        assert stats["credentials_submitted"] == 1
        assert stats["emails_reported"] == 1


# ---------------------------------------------------------------------------
# analyze_campaign — rate calculations
# ---------------------------------------------------------------------------


class TestAnalyzeCampaignRates:
    def test_zero_targets_returns_zero_rates(self):
        stats = se.analyze_campaign(_campaign(results=[]))
        assert stats["open_rate"] == 0
        assert stats["click_rate"] == 0
        assert stats["submit_rate"] == 0
        assert stats["report_rate"] == 0

    def test_50_percent_open_rate(self):
        results = [_result("Email Opened"), _result("Email Sent")]
        stats = se.analyze_campaign(_campaign(results=results))
        assert stats["open_rate"] == 50.0

    def test_100_percent_submit_rate(self):
        results = [_result("Submitted Data")] * 3
        stats = se.analyze_campaign(_campaign(results=results))
        assert stats["submit_rate"] == 100.0

    def test_rates_rounded_to_one_decimal(self):
        # 1 out of 3 = 33.3...% -> should round to 33.3
        results = [_result("Clicked Link")] + [_result("Email Sent")] * 2
        stats = se.analyze_campaign(_campaign(results=results))
        assert stats["click_rate"] == 33.3

    def test_campaign_name_preserved(self):
        stats = se.analyze_campaign(_campaign(name="Q1 Phish"))
        assert stats["campaign_name"] == "Q1 Phish"


# ---------------------------------------------------------------------------
# analyze_campaign — risk level thresholds (via generate_report indirectly)
# Note: risk level is computed inside generate_report(), not analyze_campaign().
# We test the rate values that drive those thresholds here.
# ---------------------------------------------------------------------------


class TestRiskThresholds:
    """Verify submit_rate values that map to each risk band."""

    def _submit_rate_from(self, submitted, total):
        results = [_result("Submitted Data")] * submitted
        results += [_result("Email Sent")] * (total - submitted)
        return se.analyze_campaign(_campaign(results=results))["submit_rate"]

    def test_critical_threshold_above_20(self):
        # 5/20 = 25% -> CRITICAL
        assert self._submit_rate_from(5, 20) > 20

    def test_high_threshold_between_10_and_20(self):
        # 3/20 = 15% -> HIGH
        rate = self._submit_rate_from(3, 20)
        assert 10 < rate <= 20

    def test_medium_threshold_between_5_and_10(self):
        # 1/14 ≈ 7.1% -> MEDIUM
        rate = self._submit_rate_from(1, 14)
        assert 5 < rate <= 10

    def test_low_threshold_at_or_below_5(self):
        # 1/25 = 4% -> LOW
        rate = self._submit_rate_from(1, 25)
        assert rate <= 5


# ---------------------------------------------------------------------------
# analyze_by_department
# ---------------------------------------------------------------------------


class TestAnalyzeByDepartment:
    def test_groups_by_position(self):
        results = [
            _result("Clicked Link", "Engineering"),
            _result("Email Sent", "HR"),
        ]
        dept = se.analyze_by_department(results)
        assert "Engineering" in dept
        assert "HR" in dept

    def test_totals_correct(self):
        results = [
            _result("Email Sent", "Engineering"),
            _result("Clicked Link", "Engineering"),
            _result("Submitted Data", "Engineering"),
        ]
        dept = se.analyze_by_department(results)
        assert dept["Engineering"]["total"] == 3

    def test_clicked_counts(self):
        results = [
            _result("Clicked Link", "HR"),
            _result("Submitted Data", "HR"),
            _result("Email Sent", "HR"),
        ]
        dept = se.analyze_by_department(results)
        assert dept["HR"]["clicked"] == 2  # Clicked Link + Submitted Data

    def test_submitted_counts(self):
        results = [
            _result("Submitted Data", "Finance"),
            _result("Clicked Link", "Finance"),
        ]
        dept = se.analyze_by_department(results)
        assert dept["Finance"]["submitted"] == 1

    def test_reported_counts(self):
        results = [
            _result("Email Reported", "Security"),
            _result("Email Reported", "Security"),
        ]
        dept = se.analyze_by_department(results)
        assert dept["Security"]["reported"] == 2

    def test_missing_position_uses_unknown(self):
        results = [{"status": "Clicked Link"}]  # no 'position' key
        dept = se.analyze_by_department(results)
        assert "Unknown" in dept

    def test_empty_results_returns_empty_dict(self):
        assert se.analyze_by_department([]) == {}
