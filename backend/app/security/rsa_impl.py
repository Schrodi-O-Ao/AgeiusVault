import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.security.aes import AESCBC
from app.security.pbkdf2 import PBKDF2


class RSAImpl:
    """RSA cryptographic operations using cryptography library."""

    @staticmethod
    def generate_keypair(
        bits: int = 3072, vault_key: bytes | None = None
    ) -> tuple[dict, dict]:
        """Generate an RSA keypair with optional vault key passphrase encryption."""
        if bits < 2048:
            raise ValueError("RSA key size must be at least 2048 bits")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=bits, backend=default_backend()
        )

        # Get public key
        public_key = private_key.public_key()

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Serialize private key with encryption if vault key is provided
        if vault_key:
            # Derive encryption passphrase from vault key using PBKDF2
            salt = os.urandom(16)  # Random salt for key derivation
            kdf = PBKDF2(vault_key, salt, iterations=100_000, dklen=32)
            passphrase = kdf.derive()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )

            # Store salt for later decryption
            private = {
                "pem": private_pem.decode("utf-8"),
                "format": "PEM",
                "encrypted": True,
                "salt": salt.hex(),
            }
        else:
            # Legacy behavior: no encryption (not recommended for production)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            private = {
                "pem": private_pem.decode("utf-8"),
                "format": "PEM",
                "encrypted": False,
            }

        # Return as dictionaries for JSON compatibility
        public = {"pem": public_pem.decode("utf-8"), "format": "PEM"}

        return public, private

    @staticmethod
    def _load_public_key(public_key_dict: dict):
        pem = public_key_dict.get("pem")
        if not pem:
            raise ValueError("Unsupported public key format; expected PEM")
        return serialization.load_pem_public_key(
            pem.encode("utf-8"), backend=default_backend()
        )

    @staticmethod
    def _load_private_key(private_key_dict: dict, vault_key: bytes | None = None):
        pem = private_key_dict.get("pem")
        if not pem:
            raise ValueError("Unsupported private key format; expected PEM")
        if private_key_dict.get("encrypted", False):
            if vault_key is None:
                raise ValueError("Vault key required to decrypt encrypted private key")
            salt = bytes.fromhex(private_key_dict["salt"])
            kdf = PBKDF2(vault_key, salt, iterations=100_000, dklen=32)
            passphrase = kdf.derive()
            return serialization.load_pem_private_key(
                pem.encode("utf-8"), password=passphrase, backend=default_backend()
            )
        return serialization.load_pem_private_key(
            pem.encode("utf-8"), password=None, backend=default_backend()
        )

    @staticmethod
    def encrypt_symmetric_key(aes_key: bytes, public_key: dict) -> str:
        """Encrypt a symmetric key using RSA-OAEP with SHA-256."""
        pub_key = RSAImpl._load_public_key(public_key)

        ciphertext = pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return ciphertext.hex()

    @staticmethod
    def decrypt_symmetric_key(
        encrypted_hex: str, private_key: dict, vault_key: bytes | None = None
    ) -> bytes:
        """Decrypt a symmetric key using RSA-OAEP with SHA-256."""
        priv_key = RSAImpl._load_private_key(private_key, vault_key)
        ciphertext = bytes.fromhex(encrypted_hex)

        plaintext = priv_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return plaintext

    @staticmethod
    def encrypt_private_key(private_key: dict, vault_key: bytes) -> tuple[bytes, bytes]:
        """Encrypt private key dictionary with vault key using AES-256-CBC."""
        private_json = json.dumps(private_key).encode()
        return AESCBC(vault_key).encrypt(private_json)

    @staticmethod
    def decrypt_private_key(iv: bytes, ciphertext: bytes, vault_key: bytes) -> dict:
        """Decrypt private key dictionary using vault key and AES-256-CBC."""
        decrypted = AESCBC(vault_key).decrypt(iv, ciphertext)
        return json.loads(decrypted.decode())

    @staticmethod
    def sign_message(
        private_key: dict, message: bytes, vault_key: bytes | None = None
    ) -> str:
        """Sign a message using RSA-PSS with SHA-256."""
        priv_key = RSAImpl._load_private_key(private_key, vault_key)

        signature = priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        return signature.hex()

    @staticmethod
    def verify_signature(public_key: dict, message: bytes, signature_hex: str) -> bool:
        """Verify an RSA-PSS message signature."""
        try:
            pub_key = RSAImpl._load_public_key(public_key)
            signature = bytes.fromhex(signature_hex)

            pub_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
