"""
Tests for skills/implementing-gdpr-data-subject-access-request/scripts/agent.py

Covers:
  - _redact_connection_string: password masking in various URI formats
  - PIIPatternMatcher.scan_text: email/NINO/credit-card detection, confidence
    boosting, min_confidence filter
  - DSARWorkflowEngine: DSAR registration, status transitions, extension logic
  - ExemptionReviewer: exemption flagging, redaction log on apply_redactions
"""

import importlib.util
from pathlib import Path

import pytest

AGENT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "implementing-gdpr-data-subject-access-request"
    / "scripts"
    / "agent.py"
)

spec = importlib.util.spec_from_file_location("gdpr_agent", AGENT_PATH)
gdpr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gdpr)


# ---------------------------------------------------------------------------
# _redact_connection_string
# ---------------------------------------------------------------------------


class TestRedactConnectionString:
    def test_postgresql_uri(self):
        uri = "postgresql://user:s3cr3t@db.example.com:5432/mydb"
        redacted = gdpr._redact_connection_string(uri)
        assert "s3cr3t" not in redacted
        assert "user" in redacted
        assert "****" in redacted

    def test_mysql_uri(self):
        uri = "mysql://admin:P@ssw0rd!@mysql.host/schema"
        redacted = gdpr._redact_connection_string(uri)
        assert "P@ssw0rd!" not in redacted
        assert "****" in redacted

    def test_uri_without_password_unchanged(self):
        uri = "sqlite:///local.db"
        redacted = gdpr._redact_connection_string(uri)
        assert redacted == uri

    def test_host_and_db_name_preserved(self):
        uri = "postgresql://alice:hunter2@db.corp.com/warehouse"
        redacted = gdpr._redact_connection_string(uri)
        assert "db.corp.com" in redacted
        assert "warehouse" in redacted

    def test_empty_string_unchanged(self):
        assert gdpr._redact_connection_string("") == ""


# ---------------------------------------------------------------------------
# PIIPatternMatcher.scan_text
# ---------------------------------------------------------------------------


class TestPIIPatternMatcherScanText:
    def setup_method(self):
        self.matcher = gdpr.PIIPatternMatcher()

    def test_detects_email(self):
        text = "Please contact alice@example.com for more information."
        matches = self.matcher.scan_text(text)
        types = {m["type"] for m in matches}
        assert "email" in types

    def test_detects_uk_national_insurance_number(self):
        text = "NINO: AB 12 34 56 C"
        matches = self.matcher.scan_text(text, min_confidence=0.5)
        types = {m["type"] for m in matches}
        assert "nino_uk" in types

    def test_detects_credit_card(self):
        text = "card: 4111 1111 1111 1111"
        matches = self.matcher.scan_text(text, min_confidence=0.5)
        types = {m["type"] for m in matches}
        assert "credit_card" in types

    def test_detects_uk_postcode(self):
        text = "Address: 10 Downing Street, London SW1A 2AA"
        matches = self.matcher.scan_text(text, min_confidence=0.5)
        types = {m["type"] for m in matches}
        assert "uk_postcode" in types

    def test_detects_ipv4(self):
        text = "Client connected from 192.168.1.100"
        matches = self.matcher.scan_text(text, min_confidence=0.5)
        types = {m["type"] for m in matches}
        assert "ipv4" in types

    def test_min_confidence_filters_low_confidence_types(self):
        # passport_uk has confidence 0.40 — should be excluded with min=0.5
        text = "Passport: 123456789"
        matches = self.matcher.scan_text(text, min_confidence=0.5)
        types = {m["type"] for m in matches}
        assert "passport_uk" not in types

    def test_min_confidence_includes_low_confidence_when_threshold_lower(self):
        text = "Passport: 123456789"
        matches = self.matcher.scan_text(text, min_confidence=0.3)
        types = {m["type"] for m in matches}
        assert "passport_uk" in types

    def test_context_keyword_boosts_email_confidence(self):
        # The word "email" near an email address should boost confidence
        base = self.matcher.scan_text("test@example.com")
        boosted = self.matcher.scan_text("email: test@example.com")
        base_conf = next((m["confidence"] for m in base if m["type"] == "email"), 0)
        boosted_conf = next((m["confidence"] for m in boosted if m["type"] == "email"), 0)
        assert boosted_conf >= base_conf

    def test_match_includes_gdpr_category(self):
        matches = self.matcher.scan_text("user@domain.com")
        email_match = next(m for m in matches if m["type"] == "email")
        assert email_match["gdpr_category"] == "contact_information"

    def test_match_includes_position(self):
        text = "Contact: user@domain.com end"
        matches = self.matcher.scan_text(text)
        email_match = next(m for m in matches if m["type"] == "email")
        start = email_match["position"]["start"]
        end = email_match["position"]["end"]
        assert text[start:end].strip() == "user@domain.com"

    def test_empty_text_returns_no_matches(self):
        assert self.matcher.scan_text("") == []

    def test_custom_pattern_registered(self):
        custom = {
            "employee_id": {
                "pattern": r"\bEMP-\d{6}\b",
                "description": "Employee ID",
                "confidence": 0.95,
                "gdpr_category": "hr_data",
            }
        }
        matcher = gdpr.PIIPatternMatcher(custom_patterns=custom)
        matches = matcher.scan_text("ID: EMP-123456 approved")
        types = {m["type"] for m in matches}
        assert "employee_id" in types


# ---------------------------------------------------------------------------
# DSARWorkflowEngine — registration
# ---------------------------------------------------------------------------


class TestDSARWorkflowEngineRegistration:
    def setup_method(self):
        self.engine = gdpr.DSARWorkflowEngine()

    def test_register_returns_dsar_id(self):
        dsar = self.engine.register_dsar(
            "Alice Smith", "alice@example.com", "email", "Please send my data"
        )
        assert dsar["dsar_id"].startswith("DSAR-")

    def test_deadline_is_30_days_from_receipt(self):
        from datetime import datetime, timedelta
        dsar = self.engine.register_dsar(
            "Alice Smith", "alice@example.com", "email", "Please send my data"
        )
        received = datetime.fromisoformat(dsar["received_at"])
        deadline = datetime.fromisoformat(dsar["deadline"])
        assert (deadline - received).days == 30

    def test_with_identity_docs_status_is_received(self):
        dsar = self.engine.register_dsar(
            "Alice Smith", "alice@example.com", "portal", "My data please",
            identity_docs=["passport.pdf"]
        )
        assert dsar["status"] == "received"
        assert dsar["identity_verified"] is True

    def test_without_identity_docs_status_is_verification(self):
        dsar = self.engine.register_dsar(
            "Alice Smith", "alice@example.com", "email", "My data please"
        )
        assert dsar["status"] == "identity_verification"
        assert dsar["identity_verified"] is False

    def test_dsar_stored_in_engine(self):
        dsar = self.engine.register_dsar(
            "Bob Jones", "bob@example.com", "post", "Send my data"
        )
        dsar_id = dsar["dsar_id"]
        assert dsar_id in self.engine.dsars

    def test_status_history_initialized(self):
        dsar = self.engine.register_dsar(
            "Carol White", "carol@example.com", "web", "Request"
        )
        assert len(dsar["status_history"]) >= 1
        assert dsar["status_history"][0]["status"] == "received"

    def test_requester_details_preserved(self):
        dsar = self.engine.register_dsar(
            "Dana Green", "dana@example.com", "email", "My DSAR request"
        )
        assert dsar["requester_name"] == "Dana Green"
        assert dsar["requester_email"] == "dana@example.com"


# ---------------------------------------------------------------------------
# DSARWorkflowEngine — status transitions
# ---------------------------------------------------------------------------


class TestDSARStatusTransitions:
    def setup_method(self):
        self.engine = gdpr.DSARWorkflowEngine()
        self.dsar = self.engine.register_dsar(
            "Alice Smith", "alice@example.com", "email", "Please send my data",
            identity_docs=["id.pdf"]
        )
        self.dsar_id = self.dsar["dsar_id"]

    def test_valid_status_update(self):
        updated = self.engine.update_status(self.dsar_id, "in_progress", "Processing")
        assert updated["status"] == "in_progress"

    def test_status_history_appended(self):
        self.engine.update_status(self.dsar_id, "pii_discovery")
        self.engine.update_status(self.dsar_id, "exemption_review")
        history_statuses = [h["status"] for h in self.engine.dsars[self.dsar_id]["status_history"]]
        assert "pii_discovery" in history_statuses
        assert "exemption_review" in history_statuses

    def test_invalid_status_raises_value_error(self):
        with pytest.raises(ValueError, match="Invalid status"):
            self.engine.update_status(self.dsar_id, "made_up_status")

    def test_unknown_dsar_id_raises_value_error(self):
        with pytest.raises(ValueError, match="DSAR not found"):
            self.engine.update_status("DSAR-NONEXISTENT", "in_progress")

    def test_all_valid_statuses_accepted(self):
        for status in gdpr.DSARWorkflowEngine.VALID_STATUSES:
            updated = self.engine.update_status(self.dsar_id, status)
            assert updated["status"] == status


# ---------------------------------------------------------------------------
# DSARWorkflowEngine — deadline extension (Art. 12(3))
# ---------------------------------------------------------------------------


class TestDSARExtension:
    def setup_method(self):
        self.engine = gdpr.DSARWorkflowEngine()
        self.dsar = self.engine.register_dsar(
            "Alice Smith", "alice@example.com", "email", "Data please",
            identity_docs=["id.pdf"]
        )
        self.dsar_id = self.dsar["dsar_id"]

    def test_extension_adds_60_days(self):
        from datetime import datetime
        original_deadline = datetime.fromisoformat(self.dsar["deadline"])
        extended = self.engine.apply_extension(self.dsar_id, "Complex request")
        new_deadline = datetime.fromisoformat(extended["deadline"])
        assert (new_deadline - original_deadline).days == 60

    def test_extension_sets_flag(self):
        extended = self.engine.apply_extension(self.dsar_id, "Complex request")
        assert extended["extension_applied"] is True

    def test_double_extension_raises(self):
        self.engine.apply_extension(self.dsar_id, "First extension")
        with pytest.raises(ValueError, match="Extension already applied"):
            self.engine.apply_extension(self.dsar_id, "Second extension")

    def test_extension_on_unknown_id_raises(self):
        with pytest.raises(ValueError, match="DSAR not found"):
            self.engine.apply_extension("DSAR-FAKE", "reason")


# ---------------------------------------------------------------------------
# ExemptionReviewer
# ---------------------------------------------------------------------------


class TestExemptionReviewer:
    def setup_method(self):
        self.reviewer = gdpr.ExemptionReviewer()
        self.mapped_data = {"categories": [], "supplementary_info": {}}

    def test_returns_all_exemption_types_by_default(self):
        result = self.reviewer.review_exemptions(self.mapped_data)
        expected_count = len(gdpr.EXEMPTION_TYPES)
        assert result["exemption_count"] == expected_count

    def test_specific_exemption_check(self):
        result = self.reviewer.review_exemptions(
            self.mapped_data,
            exemption_checks=["third_party_data"]
        )
        assert result["exemption_count"] == 1
        assert result["exemptions"][0]["exemption_type"] == "third_party_data"

    def test_all_exemptions_pending_review(self):
        result = self.reviewer.review_exemptions(self.mapped_data)
        for exemption in result["exemptions"]:
            assert exemption["status"] == "pending_review"
            assert exemption["dpo_review_required"] is True

    def test_unknown_exemption_type_ignored(self):
        result = self.reviewer.review_exemptions(
            self.mapped_data,
            exemption_checks=["nonexistent_exemption"]
        )
        assert result["exemption_count"] == 0

    def test_apply_redactions_logs_approved_only(self):
        approved = [
            {
                "exemption_type": "third_party_data",
                "action": "redact",
                "legal_basis": "Art. 15(4)",
                "status": "approved",
            },
            {
                "exemption_type": "trade_secrets",
                "action": "redact",
                "legal_basis": "Recital 63",
                "status": "pending_review",  # NOT approved
            },
        ]
        result = self.reviewer.apply_redactions(self.mapped_data, approved)
        assert result["redactions_applied"] == 1
        assert result["redaction_log"][0]["exemption_type"] == "third_party_data"

    def test_apply_redactions_preserves_original_data(self):
        # apply_redactions should deep-copy, not mutate the input
        original = {"categories": ["test"], "supplementary_info": {}}
        self.reviewer.apply_redactions(original, [])
        assert "redaction_log" not in original
