import os


def constant_time_compare(val1: bytes, val2: bytes) -> bool:
    """Compare two byte arrays in constant time.

    This is important for security to prevent timing attacks. If we used
    regular comparison, attackers could figure out if they're getting closer
    to the right password by measuring how long the comparison takes.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0


def encode_iv_ct(iv: bytes, ciphertext: bytes) -> str:
    """Encode IV and ciphertext together for storage.

    We combine them with a colon separator so we can store them as one string
    but still separate them later when we need to decrypt.
    """
    return f"{iv.hex()}:{ciphertext.hex()}"


def decode_iv_ct(stored: str) -> tuple[bytes, bytes]:
    """Decode the combined IV and ciphertext back into separate values."""
    try:
        iv_hex, ct_hex = stored.split(":")
        return bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)
    except ValueError:
        raise ValueError("Invalid format for iv:ciphertext")


def secure_random_hex(nbytes: int = 32) -> str:
    """Generate cryptographically secure random bytes as a hex string.

    Use this instead of regular random functions when you need security.
    The random module in Python isn't cryptographically secure.
    """
    return os.urandom(nbytes).hex()
