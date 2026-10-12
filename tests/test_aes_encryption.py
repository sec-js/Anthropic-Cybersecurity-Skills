"""
Tests for skills/implementing-aes-encryption-for-data-at-rest/scripts/agent.py

Covers: derive_key (determinism, salt generation), encrypt_file / decrypt_file
(round-trip correctness, metadata), verify_encryption (PASS / FAIL paths),
and generate_random_key.

All file I/O uses tempfile so no filesystem state is left after the suite.

Requires: pip install cffi  (fixes cryptography's native extension on this host)
"""

import importlib.util
import os
import tempfile
from pathlib import Path

import pytest

AGENT_PATH = (
    Path(__file__).parent.parent
    / "skills"
    / "implementing-aes-encryption-for-data-at-rest"
    / "scripts"
    / "agent.py"
)

spec = importlib.util.spec_from_file_location("aes_agent", AGENT_PATH)
aes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aes)


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_returns_32_byte_key(self):
        key, salt = aes.derive_key("password")
        assert len(key) == 32  # AES-256

    def test_returns_16_byte_salt_when_none_given(self):
        _, salt = aes.derive_key("password")
        assert len(salt) == 16

    def test_deterministic_with_same_salt(self):
        salt = os.urandom(16)
        key1, _ = aes.derive_key("password", salt)
        key2, _ = aes.derive_key("password", salt)
        assert key1 == key2

    def test_different_salts_produce_different_keys(self):
        salt1, salt2 = os.urandom(16), os.urandom(16)
        key1, _ = aes.derive_key("password", salt1)
        key2, _ = aes.derive_key("password", salt2)
        assert key1 != key2

    def test_different_passwords_produce_different_keys(self):
        salt = os.urandom(16)
        key1, _ = aes.derive_key("password-a", salt)
        key2, _ = aes.derive_key("password-b", salt)
        assert key1 != key2

    def test_returned_salt_matches_provided_salt(self):
        salt = os.urandom(16)
        _, returned_salt = aes.derive_key("password", salt)
        assert returned_salt == salt


# ---------------------------------------------------------------------------
# encrypt_file / decrypt_file — round-trip
# ---------------------------------------------------------------------------


class TestEncryptDecryptRoundTrip:
    def _write_temp(self, content: bytes) -> str:
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_roundtrip_small_file(self):
        plaintext = b"Hello, AES-256-GCM!"
        src = self._write_temp(plaintext)
        enc = src + ".enc"
        dec = src + ".dec"
        try:
            aes.encrypt_file(src, enc, "my-password")
            aes.decrypt_file(enc, dec, "my-password")
            assert Path(dec).read_bytes() == plaintext
        finally:
            for p in (src, enc, dec):
                Path(p).unlink(missing_ok=True)

    def test_roundtrip_binary_content(self):
        plaintext = os.urandom(4096)
        src = self._write_temp(plaintext)
        enc, dec = src + ".enc", src + ".dec"
        try:
            aes.encrypt_file(src, enc, "secret")
            aes.decrypt_file(enc, dec, "secret")
            assert Path(dec).read_bytes() == plaintext
        finally:
            for p in (src, enc, dec):
                Path(p).unlink(missing_ok=True)

    def test_roundtrip_empty_file(self):
        src = self._write_temp(b"")
        enc, dec = src + ".enc", src + ".dec"
        try:
            aes.encrypt_file(src, enc, "secret")
            aes.decrypt_file(enc, dec, "secret")
            assert Path(dec).read_bytes() == b""
        finally:
            for p in (src, enc, dec):
                Path(p).unlink(missing_ok=True)

    def test_encrypt_result_metadata(self):
        src = self._write_temp(b"test data")
        enc = src + ".enc"
        try:
            result = aes.encrypt_file(src, enc, "pw")
            assert result["algorithm"] == "AES-256-GCM"
            assert result["original_size"] == 9
            assert "PBKDF2" in result["kdf"]
            # Ciphertext is salt(16) + nonce(12) + ciphertext + GCM tag(16)
            assert result["encrypted_size"] > result["original_size"]
        finally:
            for p in (src, enc):
                Path(p).unlink(missing_ok=True)

    def test_wrong_password_raises(self):
        src = self._write_temp(b"secret data")
        enc, dec = src + ".enc", src + ".dec"
        try:
            aes.encrypt_file(src, enc, "correct-password")
            with pytest.raises(Exception):
                aes.decrypt_file(enc, dec, "wrong-password")
        finally:
            for p in (src, enc, dec):
                Path(p).unlink(missing_ok=True)

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = b"sensitive data"
        src = self._write_temp(plaintext)
        enc = src + ".enc"
        try:
            aes.encrypt_file(src, enc, "pw")
            cipher_bytes = Path(enc).read_bytes()
            assert plaintext not in cipher_bytes
        finally:
            for p in (src, enc):
                Path(p).unlink(missing_ok=True)

    def test_two_encryptions_of_same_file_differ(self):
        # Each encryption uses a fresh random salt + nonce
        src = self._write_temp(b"same plaintext")
        enc1, enc2 = src + ".enc1", src + ".enc2"
        try:
            aes.encrypt_file(src, enc1, "pw")
            aes.encrypt_file(src, enc2, "pw")
            assert Path(enc1).read_bytes() != Path(enc2).read_bytes()
        finally:
            for p in (src, enc1, enc2):
                Path(p).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# verify_encryption
# ---------------------------------------------------------------------------


class TestVerifyEncryption:
    def _setup(self, plaintext: bytes):
        src = tempfile.NamedTemporaryFile(delete=False, suffix=".orig")
        src.write(plaintext)
        src.close()
        enc = src.name + ".enc"
        return src.name, enc

    def test_pass_when_correct(self):
        src, enc = self._setup(b"verify me")
        try:
            aes.encrypt_file(src, enc, "pw")
            result = aes.verify_encryption(src, enc, "pw")
            assert result["status"] == "PASS"
            assert result["content_match"] is True
        finally:
            for p in (src, enc):
                Path(p).unlink(missing_ok=True)

    def test_fail_when_wrong_password(self):
        src, enc = self._setup(b"verify me")
        try:
            aes.encrypt_file(src, enc, "correct")
            result = aes.verify_encryption(src, enc, "wrong")
            assert result["status"] == "FAIL"
        finally:
            for p in (src, enc):
                Path(p).unlink(missing_ok=True)

    def test_fail_when_ciphertext_tampered(self):
        src, enc = self._setup(b"verify me")
        try:
            aes.encrypt_file(src, enc, "pw")
            raw = Path(enc).read_bytes()
            # Flip one byte in the ciphertext body (after salt+nonce)
            tampered = bytearray(raw)
            tampered[28] ^= 0xFF
            Path(enc).write_bytes(bytes(tampered))
            result = aes.verify_encryption(src, enc, "pw")
            assert result["status"] == "FAIL"
        finally:
            for p in (src, enc):
                Path(p).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# generate_random_key
# ---------------------------------------------------------------------------


class TestGenerateRandomKey:
    def test_returns_256_bit_key(self):
        result = aes.generate_random_key()
        assert result["key_size_bits"] == 256
        assert result["algorithm"] == "AES-256"

    def test_key_hex_is_64_chars(self):
        result = aes.generate_random_key()
        assert len(result["key_hex"]) == 64  # 32 bytes = 64 hex chars

    def test_key_hex_is_valid_hex(self):
        result = aes.generate_random_key()
        int(result["key_hex"], 16)  # raises ValueError if not valid hex

    def test_two_calls_produce_different_keys(self):
        k1 = aes.generate_random_key()["key_hex"]
        k2 = aes.generate_random_key()["key_hex"]
        assert k1 != k2
