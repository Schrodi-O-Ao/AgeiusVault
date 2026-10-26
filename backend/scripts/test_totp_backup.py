import asyncio
import time
import os
import sys
from sqlalchemy import select

# Ensure backend package is importable when running the script directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import AsyncSessionLocal
from app.models.user import User
from app.models.totp_backup_code import TOTPBackupCode
from app.services.auth_service import AuthService
from app.security.totp import TOTP


async def main():
    async with AsyncSessionLocal() as db:
        # Use admin user seeded earlier
        res = await db.execute(select(User).where(User.email == 'admin@aegisvault.gov'))
        user = res.scalars().first()
        if not user:
            print('Admin user not found')
            return

        svc = AuthService(db)

        # Setup TOTP (writes secret_enc)
        info = await svc.setup_totp(user)
        secret = info['secret']
        print('TOTP secret generated')

        # Compute current code and enable TOTP (this will persist backup codes)
        current_t = int(time.time() / 30)
        code = TOTP(secret)._generate_code(current_t)
        enable = await svc.enable_totp(user, code, ip_hmac='test', user_agent='script')
        print('Enable response keys:', list(enable.keys()))

        # Verify backup codes present in DB
        bc_res = await db.execute(select(TOTPBackupCode).where(TOTPBackupCode.user_id == user.id))
        bcs = bc_res.scalars().all()
        print('Backup codes persisted:', len(bcs))


if __name__ == '__main__':
    asyncio.run(main())
