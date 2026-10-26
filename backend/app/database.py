from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from app.config import settings

# Database connection pool configuration
# These values are configurable via environment variables
DB_POOL_SIZE = getattr(settings, 'DB_POOL_SIZE', 20)
DB_MAX_OVERFLOW = getattr(settings, 'DB_MAX_OVERFLOW', 10)
DB_POOL_TIMEOUT = getattr(settings, 'DB_POOL_TIMEOUT', 30)
DB_POOL_RECYCLE = getattr(settings, 'DB_POOL_RECYCLE', 3600)

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_size=DB_POOL_SIZE,
    max_overflow=DB_MAX_OVERFLOW,
    pool_timeout=DB_POOL_TIMEOUT,
    pool_recycle=DB_POOL_RECYCLE,
    pool_pre_ping=True,
)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
