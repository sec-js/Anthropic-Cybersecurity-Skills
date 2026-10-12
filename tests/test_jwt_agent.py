"""
Tests for skills/implementing-jwt-signing-and-verification/scripts/agent.py

Covers: b64url_encode/decode, create_jwt_hs256, verify_jwt_hs256,
        decode_jwt_unsafe, and all severity branches in audit_jwt_security.
These are pure-logic functions with no I/O or external dependencies.
"""

import importlib.util
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# The cryptography package has a broken native extension in this environment.
# Stub it out — only the optional RSA path uses it; all functions under test
# rely solely on stdlib hmac / hashlib / base64.
_crypto_stub = MagicMock()
sys.modules.setdefault("cryptography", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.rsa", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives.asymmetric.padding", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives.serialization", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives._serialization", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.primitives.hashes", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.bindings", _crypto_stub)
sys.modules.setdefault("cryptography.hazmat.bindings._rust", _crypto_stub)

AGENT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "implementing-jwt-signing-and-verification"
    / "scripts"
    / "agent.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("jwt_agent", AGENT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


jwt_agent = _load()


# ---------------------------------------------------------------------------
# b64url_encode / b64url_decode
# ---------------------------------------------------------------------------


class TestB64Url:
    def test_roundtrip_bytes(self):
        data = b"hello world"
        assert jwt_agent.b64url_decode(jwt_agent.b64url_encode(data)) == data

    def test_roundtrip_str(self):
        data = "hello"
        encoded = jwt_agent.b64url_encode(data)
        assert jwt_agent.b64url_decode(encoded) == data.encode()

    def test_no_padding_chars(self):
        # RFC 7515 requires no '=' padding in JWT components
        encoded = jwt_agent.b64url_encode(b"x")
        assert "=" not in encoded

    def test_url_safe_chars_only(self):
        encoded = jwt_agent.b64url_encode(b"\xff\xfe\xfd")
        assert "+" not in encoded
        assert "/" not in encoded

    def test_empty_bytes(self):
        assert jwt_agent.b64url_decode(jwt_agent.b64url_encode(b"")) == b""


# ---------------------------------------------------------------------------
# create_jwt_hs256
# ---------------------------------------------------------------------------


class TestCreateJwtHs256:
    def test_three_part_structure(self):
        token = jwt_agent.create_jwt_hs256({"sub": "u1"}, "secret")
        assert token.count(".") == 2

    def test_header_declares_hs256(self):
        token = jwt_agent.create_jwt_hs256({"sub": "u1"}, "secret")
        header_b64 = token.split(".")[0]
        header = json.loads(jwt_agent.b64url_decode(header_b64))
        assert header["alg"] == "HS256"
        assert header["typ"] == "JWT"

    def test_payload_is_preserved(self):
        payload = {"sub": "alice", "role": "admin"}
        token = jwt_agent.create_jwt_hs256(payload, "secret")
        payload_b64 = token.split(".")[1]
        decoded = json.loads(jwt_agent.b64url_decode(payload_b64))
        assert decoded["sub"] == "alice"
        assert decoded["role"] == "admin"

    def test_different_secrets_produce_different_tokens(self):
        payload = {"sub": "u1"}
        t1 = jwt_agent.create_jwt_hs256(payload, "secret-a")
        t2 = jwt_agent.create_jwt_hs256(payload, "secret-b")
        assert t1.split(".")[2] != t2.split(".")[2]


# ---------------------------------------------------------------------------
# verify_jwt_hs256
# ---------------------------------------------------------------------------


class TestVerifyJwtHs256:
    def test_valid_token(self):
        payload = {"sub": "alice", "exp": int(time.time()) + 3600}
        token = jwt_agent.create_jwt_hs256(payload, "mysecret")
        result = jwt_agent.verify_jwt_hs256(token, "mysecret")
        assert result["valid"] is True
        assert result["claims"]["sub"] == "alice"

    def test_wrong_secret(self):
        token = jwt_agent.create_jwt_hs256({"sub": "alice"}, "correct")
        result = jwt_agent.verify_jwt_hs256(token, "wrong")
        assert result["valid"] is False
        assert "Signature" in result["error"]

    def test_expired_token(self):
        payload = {"sub": "alice", "exp": int(time.time()) - 10}
        token = jwt_agent.create_jwt_hs256(payload, "secret")
        result = jwt_agent.verify_jwt_hs256(token, "secret")
        assert result["valid"] is False
        assert "expired" in result["error"].lower()

    def test_not_yet_valid_token(self):
        payload = {"sub": "alice", "nbf": int(time.time()) + 3600}
        token = jwt_agent.create_jwt_hs256(payload, "secret")
        result = jwt_agent.verify_jwt_hs256(token, "secret")
        assert result["valid"] is False
        assert "not yet valid" in result["error"].lower()

    def test_invalid_format_too_many_parts(self):
        result = jwt_agent.verify_jwt_hs256("a.b.c.d", "secret")
        assert result["valid"] is False

    def test_invalid_format_too_few_parts(self):
        result = jwt_agent.verify_jwt_hs256("a.b", "secret")
        assert result["valid"] is False

    def test_no_exp_claim_is_still_valid(self):
        # Missing exp should not cause verify to reject (audit will flag it)
        payload = {"sub": "alice"}
        token = jwt_agent.create_jwt_hs256(payload, "secret")
        result = jwt_agent.verify_jwt_hs256(token, "secret")
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# decode_jwt_unsafe
# ---------------------------------------------------------------------------


class TestDecodeJwtUnsafe:
    def test_decodes_header_and_payload(self):
        payload = {"sub": "bob", "role": "viewer"}
        token = jwt_agent.create_jwt_hs256(payload, "any-secret")
        decoded = jwt_agent.decode_jwt_unsafe(token)
        assert decoded["payload"]["sub"] == "bob"
        assert decoded["header"]["alg"] == "HS256"
        assert decoded["signature_present"] is True

    def test_invalid_format_returns_error(self):
        result = jwt_agent.decode_jwt_unsafe("not-a-jwt")
        assert "error" in result

    def test_works_without_knowing_secret(self):
        token = jwt_agent.create_jwt_hs256({"sub": "u"}, "super-secret")
        decoded = jwt_agent.decode_jwt_unsafe(token)
        # No secret needed — just inspect the claims
        assert decoded["payload"]["sub"] == "u"


# ---------------------------------------------------------------------------
# audit_jwt_security — severity branches
# ---------------------------------------------------------------------------


def _make_token(payload, alg_override=None, extra_header=None):
    """Helper: craft a token with an optional algorithm override."""
    import base64

    header = {"alg": alg_override or "HS256", "typ": "JWT"}
    if extra_header:
        header.update(extra_header)

    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    header_b64 = b64(header)
    payload_b64 = b64(payload)

    import hashlib
    import hmac as hmac_mod

    if alg_override == "none":
        sig = ""
    else:
        sig = jwt_agent.b64url_encode(
            hmac_mod.new(b"secret", f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
        )
    return f"{header_b64}.{payload_b64}.{sig}"


class TestAuditJwtSecurity:
    def test_alg_none_is_critical(self):
        token = _make_token({"sub": "u"}, alg_override="none")
        findings = jwt_agent.audit_jwt_security(token)
        severities = {f["severity"] for f in findings}
        assert "CRITICAL" in severities

    def test_jwk_injection_in_hs256_header_is_critical(self):
        token = _make_token({"sub": "u"}, extra_header={"jwk": {"kty": "oct"}})
        findings = jwt_agent.audit_jwt_security(token)
        severities = {f["severity"] for f in findings}
        assert "CRITICAL" in severities

    def test_symmetric_algorithm_flagged_medium(self):
        payload = {"sub": "u", "exp": int(time.time()) + 3600,
                   "iss": "svc", "aud": "app", "iat": int(time.time()), "jti": "x"}
        token = _make_token(payload)
        findings = jwt_agent.audit_jwt_security(token)
        medium_issues = [f for f in findings if f["severity"] == "MEDIUM"]
        assert any("HS256" in f["issue"] for f in medium_issues)

    def test_missing_exp_flagged_high(self):
        token = _make_token({"sub": "u"})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("exp" in f["issue"] and f["severity"] == "HIGH" for f in findings)

    def test_long_expiration_flagged_medium(self):
        payload = {"sub": "u", "exp": int(time.time()) + 90000}  # > 24 hours
        token = _make_token(payload)
        findings = jwt_agent.audit_jwt_security(token)
        assert any("expiration" in f["issue"].lower() and f["severity"] == "MEDIUM"
                   for f in findings)

    def test_missing_iss_flagged_medium(self):
        token = _make_token({"sub": "u", "exp": int(time.time()) + 3600})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("iss" in f["issue"] for f in findings)

    def test_missing_aud_flagged_medium(self):
        token = _make_token({"sub": "u", "exp": int(time.time()) + 3600})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("aud" in f["issue"] for f in findings)

    def test_missing_iat_flagged_low(self):
        token = _make_token({"sub": "u"})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("iat" in f["issue"] and f["severity"] == "LOW" for f in findings)

    def test_missing_jti_flagged_medium(self):
        token = _make_token({"sub": "u"})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("jti" in f["issue"] for f in findings)

    def test_sensitive_password_claim_flagged_high(self):
        token = _make_token({"sub": "u", "password": "s3cret"})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("password" in f["issue"] and f["severity"] == "HIGH" for f in findings)

    def test_sensitive_api_key_claim_flagged_high(self):
        token = _make_token({"sub": "u", "api_key": "sk-abc"})
        findings = jwt_agent.audit_jwt_security(token)
        assert any("api_key" in f["issue"] and f["severity"] == "HIGH" for f in findings)

    def test_clean_token_has_no_critical_findings(self):
        now = int(time.time())
        payload = {
            "sub": "u", "iss": "auth-svc", "aud": "myapp",
            "exp": now + 3600, "iat": now, "jti": "unique-id-123",
        }
        token = _make_token(payload)
        findings = jwt_agent.audit_jwt_security(token)
        assert not any(f["severity"] == "CRITICAL" for f in findings)

    def test_invalid_token_format_returns_high_finding(self):
        findings = jwt_agent.audit_jwt_security("garbage")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"
