"""
AegisVault Database Seeder

Creates initial users and sample data for testing.
Run with: python seed.py

NOTE: This generates random passwords for development. Never use seed data
in production - always implement proper user management and password policies.
"""

import asyncio
import json
import os
import secrets
import string
import sys
import uuid
from datetime import UTC, datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import settings
from app.database import AsyncSessionLocal, engine
from app.models import (
    User,
)
from app.security.crypto_utils import encode_iv_ct
from app.security.pbkdf2 import PBKDF2
from app.security.rsa_impl import RSAImpl


async def seed():
    """Seed the database with initial data.

    NOTE: This is for development only. In production, use proper user management.
    Default passwords are generated randomly - check the console output for credentials.
    """
    async with engine.begin() as conn:
        # Create all tables
        from app.database import Base

        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        print("Seeding AegisVault database...")
        print("[WARNING] DEVELOPMENT MODE: Generating random passwords for seed users")
        print(
            "[WARNING] These passwords will be displayed below: save them for testing!"
        )

        # Generate random passwords for seed users
        def generate_password(length=16):
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            return "".join(secrets.choice(alphabet) for _ in range(length))

        # Create admin user
        admin_password = generate_password()
        admin_salt = os.urandom(32)
        admin_key_salt = os.urandom(32)
        admin_hash = (
            PBKDF2(admin_password.encode(), admin_salt, settings.PBKDF2_ITERATIONS, 32)
            .derive()
            .hex()
        )

        admin_public, admin_private = RSAImpl.generate_keypair(2048)
        admin_iv, admin_enc_priv = RSAImpl.encrypt_private_key(
            admin_private, admin_password.encode()[:32].ljust(32, b"\x00")
        )

        admin = User(
            id=uuid.uuid4(),
            full_name="System Administrator",
            email="admin@aegisvault.gov",
            password_hash=admin_hash,
            password_salt=admin_salt.hex(),
            key_salt=admin_key_salt.hex(),
            totp_secret_enc="",  # No TOTP initially
            totp_enabled=False,
            role="SYS_ADMIN",
            department="IT",
            manager_id=None,
            rsa_public_key=json.dumps(admin_public),
            rsa_private_enc=encode_iv_ct(admin_iv, admin_enc_priv),
            is_active=True,
            email_verified=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            last_login_at=None,
            failed_attempts=0,
            locked_until=None,
        )
        db.add(admin)
        await db.flush()

        # Create HR admin user
        hr_password = generate_password()
        hr_salt = os.urandom(32)
        hr_key_salt = os.urandom(32)
        hr_hash = (
            PBKDF2(hr_password.encode(), hr_salt, settings.PBKDF2_ITERATIONS, 32)
            .derive()
            .hex()
        )

        hr_public, hr_private = RSAImpl.generate_keypair(2048)
        hr_iv, hr_enc_priv = RSAImpl.encrypt_private_key(
            hr_private, hr_password.encode()[:32].ljust(32, b"\x00")
        )

        hr_admin = User(
            id=uuid.uuid4(),
            full_name="HR Manager",
            email="hr@aegisvault.gov",
            password_hash=hr_hash,
            password_salt=hr_salt.hex(),
            key_salt=hr_key_salt.hex(),
            totp_secret_enc="",
            totp_enabled=False,
            role="HR_ADMIN",
            department="Human Resources",
            manager_id=None,
            rsa_public_key=json.dumps(hr_public),
            rsa_private_enc=encode_iv_ct(hr_iv, hr_enc_priv),
            is_active=True,
            email_verified=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            last_login_at=None,
            failed_attempts=0,
            locked_until=None,
        )
        db.add(hr_admin)
        await db.flush()

        # Create manager user
        mgr_password = generate_password()
        mgr_salt = os.urandom(32)
        mgr_key_salt = os.urandom(32)
        mgr_hash = (
            PBKDF2(mgr_password.encode(), mgr_salt, settings.PBKDF2_ITERATIONS, 32)
            .derive()
            .hex()
        )

        mgr_public, mgr_private = RSAImpl.generate_keypair(2048)
        mgr_iv, mgr_enc_priv = RSAImpl.encrypt_private_key(
            mgr_private, mgr_password.encode()[:32].ljust(32, b"\x00")
        )

        manager = User(
            id=uuid.uuid4(),
            full_name="Department Manager",
            email="manager@aegisvault.gov",
            password_hash=mgr_hash,
            password_salt=mgr_salt.hex(),
            key_salt=mgr_key_salt.hex(),
            totp_secret_enc="",
            totp_enabled=False,
            role="MANAGER",
            department="Operations",
            manager_id=hr_admin.id,
            rsa_public_key=json.dumps(mgr_public),
            rsa_private_enc=encode_iv_ct(mgr_iv, mgr_enc_priv),
            is_active=True,
            email_verified=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            last_login_at=None,
            failed_attempts=0,
            locked_until=None,
        )
        db.add(manager)
        await db.flush()

        # Create staff user
        staff_password = generate_password()
        staff_salt = os.urandom(32)
        staff_key_salt = os.urandom(32)
        staff_hash = (
            PBKDF2(staff_password.encode(), staff_salt, settings.PBKDF2_ITERATIONS, 32)
            .derive()
            .hex()
        )

        staff_public, staff_private = RSAImpl.generate_keypair(2048)
        staff_iv, staff_enc_priv = RSAImpl.encrypt_private_key(
            staff_private, staff_password.encode()[:32].ljust(32, b"\x00")
        )

        staff = User(
            id=uuid.uuid4(),
            full_name="John Staff",
            email="staff@aegisvault.gov",
            password_hash=staff_hash,
            password_salt=staff_salt.hex(),
            key_salt=staff_key_salt.hex(),
            totp_secret_enc="",
            totp_enabled=False,
            role="STAFF",
            department="Operations",
            manager_id=manager.id,
            rsa_public_key=json.dumps(staff_public),
            rsa_private_enc=encode_iv_ct(staff_iv, staff_enc_priv),
            is_active=True,
            email_verified=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            last_login_at=None,
            failed_attempts=0,
            locked_until=None,
        )
        db.add(staff)
        await db.commit()

        print(f"\n{'='*60}")
        print("Seeding complete! Here are your test credentials:")
        print(f"{'='*60}")
        print(f"  * admin@aegisvault.gov (SYS_ADMIN) / {admin_password}")
        print(f"  * hr@aegisvault.gov (HR_ADMIN) / {hr_password}")
        print(f"  * manager@aegisvault.gov (MANAGER) / {mgr_password}")
        print(f"  * staff@aegisvault.gov (STAFF) / {staff_password}")
        print(f"{'='*60}")
        print("[WARNING] SECURITY WARNING: These are random development passwords.")
        print("[WARNING] Never use these in production! Always use strong, unique")
        print("[WARNING] passwords and proper user management in production systems.")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(seed())
