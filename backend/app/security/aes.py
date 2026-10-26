import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES:
    """AES-256 encryption using the cryptography library.

    This replaces the custom educational implementation with a
    production-ready cryptographic library.
    """

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self.key = key


class AESCBC:
    """AES in Cipher Block Chaining mode using cryptography library.

    Industry-standard implementation with proper padding and IV handling.
    """

    def __init__(self, key: bytes):
        self.aes = AES(key)

    def _pad(self, data: bytes) -> bytes:
        """Add PKCS#7 padding to make data a multiple of 16 bytes."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        if not data:
            raise ValueError("Invalid padding: empty data")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")
        for p in data[-pad_len:]:
            if p != pad_len:
                raise ValueError("Invalid padding")
        return data[:-pad_len]

    def encrypt(self, plaintext: bytes) -> tuple[bytes, bytes]:
        """Encrypt data using AES-256-CBC mode.

        Returns a tuple of (IV, ciphertext). Both are needed for decryption.
        Uses a cryptographically secure random IV.
        """
        iv = os.urandom(16)  # Cryptographically secure random IV
        padded = self._pad(plaintext)

        cipher = Cipher(
            algorithms.AES(self.aes.key), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        return iv, ciphertext

    def decrypt(self, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt data that was encrypted with AES-256-CBC.

        Requires the same IV that was used during encryption.
        """
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
        if len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16")

        cipher = Cipher(
            algorithms.AES(self.aes.key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return self._unpad(padded_plaintext)
