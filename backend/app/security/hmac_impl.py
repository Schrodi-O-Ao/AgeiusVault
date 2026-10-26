import hmac
import hashlib
from typing import Union

class HMACImpl:
    """
    HMAC implementation using the standard library's hmac module.
    
    This replaces the custom educational implementation with Python's
    built-in HMAC, which is cryptographically secure and well-tested.
    """
    def __init__(self, key: bytes, hash_fn, msg: bytes = b""):
        """
        Initialize HMAC with key and hash function.
        
        Args:
            key: Secret key for HMAC
            hash_fn: Hash function (e.g., hashlib.sha256, hashlib.sha1)
            msg: Optional initial message
        """
        self._hmac = hmac.new(key, msg, hash_fn)

    def update(self, data: bytes) -> 'HMACImpl':
        """Add more data to be authenticated - useful for streaming large data."""
        self._hmac.update(data)
        return self

    def digest(self) -> bytes:
        """Finalize and return the HMAC value as bytes."""
        return self._hmac.digest()

    def hexdigest(self) -> str:
        """Return the HMAC value as a hexadecimal string."""
        return self._hmac.hexdigest()

def hmac_sha256(key: bytes, msg: bytes = b"") -> HMACImpl:
    """Convenience function to create an HMAC using SHA-256."""
    return HMACImpl(key, hashlib.sha256, msg)

def hmac_sha1(key: bytes, msg: bytes = b"") -> HMACImpl:
    """Convenience function to create an HMAC using SHA-1.
    
    Note: SHA-1 is considered deprecated for new applications.
    Consider using SHA-256 instead.
    """
    return HMACImpl(key, hashlib.sha1, msg)