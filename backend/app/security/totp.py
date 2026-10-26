import pyotp
import secrets
import string

class TOTP:
    """Time-based One-Time Password implementation using pyotp."""

    def __init__(self, secret_base32: str = None):
        if secret_base32 is None:
            self.totp = pyotp.TOTP(pyotp.random_base32())
            self.secret_base32 = self.totp.secret
        else:
            self.secret_base32 = secret_base32
            self.totp = pyotp.TOTP(secret_base32)

    def generate_uri(self, account_name: str, issuer: str = "AegisVault") -> str:
        """Generate provisioning URI for authenticator applications."""
        return self.totp.provisioning_uri(
            name=account_name,
            issuer_name=issuer
        )

    def verify(self, code: str, valid_window: int = 1) -> bool:
        """Verify 6-digit TOTP code within allowed time window."""
        if not code or len(code) != 6:
            return False

        return self.totp.verify(code, valid_window=valid_window)

def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate cryptographically random 8-character backup codes."""
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(8)) for _ in range(count)]