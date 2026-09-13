from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.core.config import settings
from app.models import Base

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args=connect_args,
    pool_pre_ping=True if not settings.DATABASE_URL.startswith("sqlite") else False,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Initialize database tables and seed default users."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed default analyst and admin accounts if empty
    from app.models.user import User, UserRole
    from app.core.auth import get_password_hash
    from sqlalchemy import select

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).limit(1))
        if result.scalar_one_or_none() is None:
            demo_users = [
                User(
                    name="Senior SOC Analyst",
                    email="analyst@soc.corp",
                    password_hash=get_password_hash("analyst123"),
                    role=UserRole.analyst,
                ),
                User(
                    name="SOC Administrator",
                    email="admin@soc.corp",
                    password_hash=get_password_hash("admin123"),
                    role=UserRole.admin,
                ),
            ]
            session.add_all(demo_users)
            await session.commit()



async def get_db() -> AsyncSession:
    """FastAPI dependency: yields a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

