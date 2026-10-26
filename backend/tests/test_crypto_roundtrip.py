"""
Comprehensive crypto round-trip tests for AES, RSA, and HMAC.
Tests that encrypt → decrypt = original for all cryptographic primitives.
"""

import os

import pytest

from app.security.aes import AESCBC
from app.security.hmac_impl import hmac_sha1, hmac_sha256
from app.security.rsa_impl import RSAImpl


class TestAESRoundTrip:
    """Test AES encryption/decryption round-trip integrity."""

    @pytest.fixture
    def aes_key(self):
        """Generate a valid AES-256 key."""
        return os.urandom(32)

    @pytest.fixture
    def aes(self, aes_key):
        """Create AESCBC instance."""
        return AESCBC(aes_key)

    def test_aes_round_trip_simple_message(self, aes):
        """Test encrypt/decrypt with a simple message."""
        plaintext = b"Hello, World!"
        iv, ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(iv, ciphertext)
        assert decrypted == plaintext

    def test_aes_round_trip_empty_message(self, aes):
        """Test encrypt/decrypt with empty message."""
        plaintext = b""
        iv, ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(iv, ciphertext)
        assert decrypted == plaintext

    def test_aes_round_trip_large_message(self, aes):
        """Test encrypt/decrypt with a large message."""
        plaintext = os.urandom(10000)  # 10KB of random data
        iv, ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(iv, ciphertext)
        assert decrypted == plaintext

    def test_aes_round_trip_different_ivs(self, aes):
        """Test that different IVs produce different ciphertexts."""
        plaintext = b"Same message"
        iv1, ct1 = aes.encrypt(plaintext)
        iv2, ct2 = aes.encrypt(plaintext)

        # IVs should be different (random)
        assert iv1 != iv2
        # Ciphertexts should be different
        assert ct1 != ct2
        # But both should decrypt to the same plaintext
        assert aes.decrypt(iv1, ct1) == plaintext
        assert aes.decrypt(iv2, ct2) == plaintext

    def test_aes_round_trip_multiple_blocks(self, aes):
        """Test encrypt/decrypt with message spanning multiple blocks."""
        # Create message that's exactly 3 blocks (48 bytes)
        plaintext = b"A" * 48
        iv, ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(iv, ciphertext)
        assert decrypted == plaintext

    def test_aes_round_trip_partial_block(self, aes):
        """Test encrypt/decrypt with message that's not a full block."""
        plaintext = b"Partial block"  # 13 bytes
        iv, ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(iv, ciphertext)
        assert decrypted == plaintext


class TestRSARoundTrip:
    """Test RSA encryption/decryption round-trip integrity."""

    @pytest.fixture
    def rsa_keypair(self):
        """Generate RSA keypair (2048-bit for faster tests) with encryption."""
        vault_key = os.urandom(32)
        public, private = RSAImpl.generate_keypair(2048, vault_key)
        return public, private, vault_key

    def test_rsa_round_trip_symmetric_key(self, rsa_keypair):
        """Test encrypt/decrypt of a symmetric key."""
        public, private, vault_key = rsa_keypair
        aes_key = os.urandom(32)

        encrypted = RSAImpl.encrypt_symmetric_key(aes_key, public)
        decrypted = RSAImpl.decrypt_symmetric_key(encrypted, private, vault_key)

        assert decrypted == aes_key

    def test_rsa_round_trip_multiple_keys(self, rsa_keypair):
        """Test encrypt/decrypt of multiple different keys."""
        public, private, vault_key = rsa_keypair

        for _ in range(10):
            aes_key = os.urandom(32)
            encrypted = RSAImpl.encrypt_symmetric_key(aes_key, public)
            decrypted = RSAImpl.decrypt_symmetric_key(encrypted, private, vault_key)
            assert decrypted == aes_key

    def test_rsa_signature_round_trip(self, rsa_keypair):
        """Test sign/verify round-trip."""
        public, private, vault_key = rsa_keypair
        message = b"Important message to sign"

        signature = RSAImpl.sign_message(private, message, vault_key)
        is_valid = RSAImpl.verify_signature(public, message, signature)

        assert is_valid is True

    def test_rsa_signature_tampered(self, rsa_keypair):
        """Test that signature verification fails for tampered messages."""
        public, private, vault_key = rsa_keypair
        message = b"Original message"

        signature = RSAImpl.sign_message(private, message, vault_key)
        is_valid_original = RSAImpl.verify_signature(public, message, signature)
        is_valid_tampered = RSAImpl.verify_signature(
            public, b"Tampered message", signature
        )

        assert is_valid_original is True
        assert is_valid_tampered is False

    def test_rsa_signature_multiple_messages(self, rsa_keypair):
        """Test sign/verify for multiple different messages."""
        public, private, vault_key = rsa_keypair

        messages = [
            b"Message 1",
            b"Message 2 with different content",
            b"A" * 100,  # Long message
            b"",  # Empty message
        ]

        for message in messages:
            signature = RSAImpl.sign_message(private, message, vault_key)
            assert RSAImpl.verify_signature(public, message, signature) is True


class TestHMACRoundTrip:
    """Test HMAC integrity verification."""

    @pytest.fixture
    def hmac_key(self):
        """Generate HMAC key."""
        return os.urandom(32)

    def test_hmac_sha256_round_trip(self, hmac_key):
        """Test HMAC-SHA256 verification."""
        message = b"Message to authenticate"

        hmac_value = hmac_sha256(hmac_key, message).digest()

        # Verify with same key and message
        verify_hmac = hmac_sha256(hmac_key, message).digest()
        assert hmac_value == verify_hmac

    def test_hmac_sha256_different_messages(self, hmac_key):
        """Test that different messages produce different HMACs."""
        message1 = b"Message 1"
        message2 = b"Message 2"

        hmac1 = hmac_sha256(hmac_key, message1).digest()
        hmac2 = hmac_sha256(hmac_key, message2).digest()

        assert hmac1 != hmac2

    def test_hmac_sha256_different_keys(self):
        """Test that different keys produce different HMACs."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        message = b"Same message"

        hmac1 = hmac_sha256(key1, message).digest()
        hmac2 = hmac_sha256(key2, message).digest()

        assert hmac1 != hmac2

    def test_hmac_sha256_update(self, hmac_key):
        """Test HMAC with incremental updates."""
        message = b"Long message that we update incrementally"

        # Single call
        hmac_single = hmac_sha256(hmac_key, message).digest()

        # Incremental updates
        hmac_incremental = hmac_sha256(hmac_key, b"")
        hmac_incremental.update(b"Long ")
        hmac_incremental.update(b"message ")
        hmac_incremental.update(b"that we ")
        hmac_incremental.update(b"update ")
        hmac_incremental.update(b"incrementally")

        assert hmac_single == hmac_incremental.digest()

    def test_hmac_sha1_round_trip(self, hmac_key):
        """Test HMAC-SHA1 verification (legacy support)."""
        message = b"Message to authenticate"

        hmac_value = hmac_sha1(hmac_key, message).digest()
        verify_hmac = hmac_sha1(hmac_key, message).digest()

        assert hmac_value == verify_hmac


class TestIntegratedCryptoRoundTrip:
    """Test integrated crypto operations (RSA + AES + HMAC)."""

    def test_full_crypto_pipeline(self):
        """Test complete pipeline: AES encrypt → RSA wrap key → HMAC sign."""
        # Generate keys
        aes_key = os.urandom(32)
        hmac_key = os.urandom(32)
        vault_key = os.urandom(32)
        public, private = RSAImpl.generate_keypair(2048, vault_key)

        # Original message
        plaintext = b"Secret message"

        # Step 1: Encrypt with AES
        aes = AESCBC(aes_key)
        iv, ciphertext = aes.encrypt(plaintext)

        # Step 2: Wrap AES key with RSA
        wrapped_key = RSAImpl.encrypt_symmetric_key(aes_key, public)

        # Step 3: Sign the ciphertext with HMAC
        hmac_value = hmac_sha256(hmac_key, iv + ciphertext).hexdigest()

        # Reverse the process
        # Step 1: Verify HMAC
        verify_hmac = hmac_sha256(hmac_key, iv + ciphertext).hexdigest()
        assert verify_hmac == hmac_value

        # Step 2: Unwrap AES key with RSA
        unwrapped_key = RSAImpl.decrypt_symmetric_key(wrapped_key, private, vault_key)
        assert unwrapped_key == aes_key

        # Step 3: Decrypt with AES
        aes_decrypt = AESCBC(unwrapped_key)
        decrypted = aes_decrypt.decrypt(iv, ciphertext)
        assert decrypted == plaintext
