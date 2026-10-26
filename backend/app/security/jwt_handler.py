import base64
import json
import time

from app.security.crypto_utils import constant_time_compare
from app.security.hmac_impl import hmac_sha256


class JWTHandler:
    def __init__(self, secret: str | bytes):
        if isinstance(secret, bytes):
            self.secret_bytes = secret
        else:
            self.secret_bytes = bytes.fromhex(secret)

    def _b64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _b64url_decode(self, data: str) -> bytes:
        padding = "=" * ((4 - len(data) % 4) % 4)
        return base64.urlsafe_b64decode(data + padding)

    def encode(self, payload: dict, expires_in_seconds: int) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload_copy = payload.copy()
        payload_copy["exp"] = int(time.time()) + expires_in_seconds

        header_b64 = self._b64url_encode(json.dumps(header).encode())
        payload_b64 = self._b64url_encode(json.dumps(payload_copy).encode())

        signing_input = f"{header_b64}.{payload_b64}".encode()
        signature = hmac_sha256(self.secret_bytes, signing_input).digest()
        signature_b64 = self._b64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def decode(self, token: str) -> dict:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode()

        expected_signature = hmac_sha256(self.secret_bytes, signing_input).digest()
        provided_signature = self._b64url_decode(signature_b64)

        if not constant_time_compare(expected_signature, provided_signature):
            raise ValueError("Invalid JWT signature")

        payload = json.loads(self._b64url_decode(payload_b64))
        if "exp" in payload and int(time.time()) > payload["exp"]:
            raise ValueError("JWT expired")

        return payload
