import hashlib
import os

from app.security.aes import AESCBC
from app.security.hmac_impl import hmac_sha1, hmac_sha256
from app.security.pbkdf2 import PBKDF2
from app.security.rsa_impl import RSAImpl
from app.security.totp import TOTP, generate_backup_codes


def test_hmac_matches_stdlib():
    key = b"key"
    msg = b"The quick brown fox"
    assert (
        hmac_sha256(key, msg).hexdigest()
        == __import__("hmac").new(key, msg, hashlib.sha256).hexdigest()
    )
    assert (
        hmac_sha1(key, msg).hexdigest()
        == __import__("hmac").new(key, msg, hashlib.sha1).hexdigest()
    )


def test_pbkdf2_matches_stdlib():
    password = b"password"
    salt = b"salt"
    # Test with low iterations for speed
    assert PBKDF2(password, salt, 2, 32).derive() == hashlib.pbkdf2_hmac(
        "sha256", password, salt, 2, 32
    )


def test_aes_256_basic_encryption():
    key = os.urandom(32)
    plaintext = b"test message for encryption"
    iv, ct = AESCBC(key).encrypt(plaintext)
    assert AESCBC(key).decrypt(iv, ct) == plaintext


def test_aes_cbc_round_trip():
    key = os.urandom(32)
    plaintext = b"request payload with padding"
    iv, ct = AESCBC(key).encrypt(plaintext)
    assert AESCBC(key).decrypt(iv, ct) == plaintext


def test_aes_key_length_validation():
    key = os.urandom(16)  # Wrong size
    try:
        AESCBC(key)
        assert False, "Should raise ValueError for wrong key size"
    except ValueError:
        pass


def test_rsa_wraps_symmetric_key():
    # Use 2048-bit for faster tests (minimum acceptable)
    vault_key = os.urandom(32)
    public, private = RSAImpl.generate_keypair(2048, vault_key)
    key = os.urandom(32)
    wrapped = RSAImpl.encrypt_symmetric_key(key, public)
    assert RSAImpl.decrypt_symmetric_key(wrapped, private, vault_key) == key


def test_rsa_key_size_validation():
    try:
        RSAImpl.generate_keypair(1024)  # Too small
        assert False, "Should raise ValueError for key size < 2048"
    except ValueError:
        pass


def test_rsa_signatures():
    vault_key = os.urandom(32)
    public, private = RSAImpl.generate_keypair(2048, vault_key)
    message = b"test message"
    signature = RSAImpl.sign_message(private, message, vault_key)
    assert RSAImpl.verify_signature(public, message, signature)
    assert not RSAImpl.verify_signature(public, b"tampered", signature)


def test_totp_verification():
    totp = TOTP()
    code = totp.totp.now()
    assert totp.verify(code)


def test_totp_invalid_code():
    totp = TOTP()
    assert not totp.verify("000000")


def test_backup_codes_generation():
    codes = generate_backup_codes(5)
    assert len(codes) == 5
    assert all(len(code) == 8 for code in codes)
    assert all(code.isalnum() for code in codes)


def test_rsa_encrypted_private_key():
    """Test that RSA private keys can be encrypted with vault key."""
    vault_key = os.urandom(32)
    public, private = RSAImpl.generate_keypair(2048, vault_key)

    # Verify private key is marked as encrypted
    assert private.get("encrypted") is True
    assert "salt" in private

    # Verify we can still use the encrypted key
    message = b"test message"
    signature = RSAImpl.sign_message(private, message, vault_key)
    assert RSAImpl.verify_signature(public, message, signature)


def test_rsa_unencrypted_private_key_legacy():
    """Test legacy unencrypted private key generation."""
    public, private = RSAImpl.generate_keypair(2048)

    # Verify private key is not encrypted (legacy mode)
    assert private.get("encrypted") is False

    # Verify we can still use the unencrypted key
    message = b"test message"
    signature = RSAImpl.sign_message(private, message)
    assert RSAImpl.verify_signature(public, message, signature)


def test_rsa_encrypted_key_requires_vault_key():
    """Test that encrypted private keys require vault key for operations."""
    vault_key = os.urandom(32)
    _public, private = RSAImpl.generate_keypair(2048, vault_key)

    # Try to use encrypted key without vault key - should fail
    try:
        RSAImpl.sign_message(private, b"test")
        assert False, "Should have raised ValueError for missing vault key"
    except ValueError as e:
        assert "Vault key required" in str(e)
