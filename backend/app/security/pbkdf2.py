from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class PBKDF2:
    """Password-Based Key Derivation Function 2 using cryptography library."""

    def __init__(
        self, password: bytes, salt: bytes, iterations: int = 200_000, dklen: int = 32
    ):
        self.password = password
        self.salt = salt
        self.iterations = iterations
        self.dklen = dklen

    def derive(self) -> bytes:
        """Derive cryptographic key using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.dklen,
            salt=self.salt,
            iterations=self.iterations,
            backend=default_backend(),
        )
        return kdf.derive(self.password)
