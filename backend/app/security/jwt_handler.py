import time

import jwt


class JWTHandler:
    def __init__(self, secret: str | bytes):
        if isinstance(secret, bytes):
            self.secret_bytes = secret
        else:
            try:
                self.secret_bytes = bytes.fromhex(secret)
            except ValueError:
                self.secret_bytes = secret.encode()

    def encode(self, payload: dict, expires_in_seconds: int) -> str:
        payload_copy = payload.copy()
        payload_copy["exp"] = int(time.time()) + expires_in_seconds
        return jwt.encode(payload_copy, self.secret_bytes, algorithm="HS256")

    def decode(self, token: str) -> dict:
        try:
            return jwt.decode(token, self.secret_bytes, algorithms=["HS256"])
        except jwt.PyJWTError as exc:
            raise ValueError(f"Invalid JWT: {exc}") from exc
