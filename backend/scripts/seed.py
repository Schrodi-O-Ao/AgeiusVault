"""
AegisVault Database Seeder
Creates demo users across all roles with sample requests and delegations.
Run with: python scripts/seed.py
"""
import asyncio, json, os, sys, uuid
from datetime import datetime, timedelta, timezone, date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from app.database import AsyncSessionLocal
from app.models.user import User
from app.models.request import Request
from app.models.approval import Approval
from app.models.delegation import Delegation
from app.models.audit_chain import AuditChain
from app.security.pbkdf2 import PBKDF2
from app.config import settings
from app.security.aes import AESCBC
from app.security.rsa_impl import RSAImpl
from app.security.crypto_utils import encode_iv_ct, secure_random_hex
from app.services.audit_service import GENESIS_HASH, _compute_chain_hash

PASSWORD = "AegisVault@Demo2026!"

USERS = [
    {"full_name": "System Admin",   "email": "admin@aegisvault.gov",    "role": "SYS_ADMIN",  "department": "IT"},
    {"full_name": "HR Director",    "email": "hr@aegisvault.gov",       "role": "HR_ADMIN",   "department": "Human Resources"},
    {"full_name": "Jane Manager",   "email": "jane@aegisvault.gov",     "role": "MANAGER",    "department": "Operations"},
    {"full_name": "Tom Lead",       "email": "tom@aegisvault.gov",      "role": "MANAGER",    "department": "Finance"},
    {"full_name": "Alice Staff",    "email": "alice@aegisvault.gov",    "role": "STAFF",      "department": "Operations"},
    {"full_name": "Bob Staff",      "email": "bob@aegisvault.gov",      "role": "STAFF",      "department": "Operations"},
    {"full_name": "Carol Staff",    "email": "carol@aegisvault.gov",    "role": "STAFF",      "department": "Finance"},
    {"full_name": "Dave Staff",     "email": "dave@aegisvault.gov",     "role": "STAFF",      "department": "Finance"},
]


def create_user(info, manager_id=None):
    uid = uuid.uuid4()
    salt = os.urandom(32)
    ks = os.urandom(32)
    pw_hash = PBKDF2(PASSWORD.encode(), salt, settings.PBKDF2_ITERATIONS, 32).derive().hex()
    vk = PBKDF2(PASSWORD.encode(), ks, 10_000, 32).derive()
    pub, priv = RSAImpl.generate_keypair(2048)
    iv, ct = RSAImpl.encrypt_private_key(priv, vk)
    return User(
        id=uid, full_name=info["full_name"], email=info["email"],
        password_hash=pw_hash, password_salt=salt.hex(), key_salt=ks.hex(),
        rsa_public_key=json.dumps(pub), rsa_private_enc=encode_iv_ct(iv, ct),
        role=info["role"], department=info["department"], manager_id=manager_id,
        is_active=True, email_verified=True,
    ), pub


def wrap_dek(dek, pub, uid, role):
    return {"user_id": str(uid), "wrapped_dek": RSAImpl.encrypt_symmetric_key(dek, pub), "role": role}


async def seed():
    print("Seeding AegisVault database...")
    async with AsyncSessionLocal() as db:
        existing = (await db.execute(select(User).limit(1))).scalars().first()
        if existing:
            print("Database already has users. Skipping seed.")
            return

        users, pubs = {}, {}
        manager_map = {"Operations": None, "Finance": None}

        # Create users
        for info in USERS:
            mgr_id = manager_map.get(info["department"]) if info["role"] == "STAFF" else None
            u, pub = create_user(info, mgr_id)
            db.add(u)
            users[info["email"]] = u
            pubs[info["email"]] = pub
            if info["role"] == "MANAGER":
                manager_map[info["department"]] = u.id
            print(f"  + {info['role']:10s} {info['full_name']}")
        await db.flush()

        # Fix manager_id for staff
        for info in USERS:
            if info["role"] == "STAFF":
                u = users[info["email"]]
                u.manager_id = manager_map[info["department"]]

        # Create sample requests
        requests_data = [
            {"requester": "alice@aegisvault.gov", "type": "ANNUAL_LEAVE", "payload": {"start_date": "2026-06-01", "end_date": "2026-06-05", "reason": "Family holiday"}},
            {"requester": "bob@aegisvault.gov",   "type": "SICK_LEAVE",   "payload": {"start_date": "2026-05-20", "days": "2", "fit_note": "Doctor advised rest"}},
            {"requester": "carol@aegisvault.gov", "type": "EXPENSE",      "payload": {"amount": "145.50", "currency": "GBP", "category": "Travel", "description": "Train to London office"}},
            {"requester": "dave@aegisvault.gov",  "type": "IT_ACCESS",    "payload": {"system": "HR Portal", "access_level": "Read", "justification": "Need to view team schedules"}},
        ]

        for rd in requests_data:
            requester = users[rd["requester"]]
            approver_email = "jane@aegisvault.gov" if requester.department == "Operations" else "tom@aegisvault.gov"
            approver = users[approver_email]
            dek = os.urandom(32)
            payload_json = json.dumps(rd["payload"], sort_keys=True)
            iv, ct = AESCBC(dek).encrypt(payload_json.encode())
            wrapped = [wrap_dek(dek, pubs[rd["requester"]], requester.id, "requester"),
                       wrap_dek(dek, pubs[approver_email], approver.id, "approver")]

            req = Request(
                id=uuid.uuid4(), requester_id=requester.id, type=rd["type"],
                payload_enc=encode_iv_ct(iv, ct), dek_enc=wrapped, status="PENDING",
            )
            db.add(req)
            await db.flush()

            # Audit chain genesis
            now = datetime.now(timezone.utc)
            ch = _compute_chain_hash(GENESIS_HASH, str(req.id), str(requester.id), "SUBMITTED", now.isoformat())
            db.add(AuditChain(
                id=uuid.uuid4(), request_id=req.id, step_index=0,
                actor_id=requester.id, action="SUBMITTED",
                prev_hash=GENESIS_HASH, chain_hash=ch, recorded_at=now,
            ))
            print(f"  + REQUEST  {rd['type']:15s} by {requester.full_name}")

        await db.commit()
        print(f"\nSeeded {len(USERS)} users, {len(requests_data)} requests.")
        print(f"Login with any email above, password: {PASSWORD}")

asyncio.run(seed())
