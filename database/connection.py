# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Database Connection
#  Manages the asyncpg connection pool to Supabase PostgreSQL.
#  The pool is created once at startup and shared across all Cogs.
# ══════════════════════════════════════════════════════════════════

import asyncpg
import logging

logger = logging.getLogger("antiraid.database")


class Database:
    """
    Async PostgreSQL connection pool wrapper using asyncpg.

    Usage:
        db = Database()
        await db.connect(dsn, min_size=5, max_size=20)
        # ... use db.pool across the bot ...
        await db.close()
    """

    def __init__(self) -> None:
        self.pool: asyncpg.Pool | None = None

    async def connect(
        self,
        dsn: str,
        min_size: int = 5,
        max_size: int = 20,
    ) -> asyncpg.Pool:
        """
        Create the connection pool to Supabase PostgreSQL.

        Args:
            dsn: PostgreSQL connection string (DATABASE_URL).
            min_size: Minimum number of connections kept open.
            max_size: Maximum number of connections in the pool.

        Returns:
            The active asyncpg.Pool instance.

        Raises:
            ConnectionError: If the database is unreachable.
        """
        try:
            self.pool = await asyncpg.create_pool(
                dsn=dsn,
                min_size=min_size,
                max_size=max_size,
                command_timeout=30,
            )
            logger.info(
                "✅ Database pool established — "
                f"min={min_size}, max={max_size}"
            )
            return self.pool

        except Exception as e:
            logger.critical(f"❌ Failed to connect to database: {e}")
            raise ConnectionError(
                f"Could not connect to PostgreSQL: {e}"
            ) from e

    async def close(self) -> None:
        """Gracefully close all connections in the pool."""
        if self.pool:
            await self.pool.close()
            logger.info("🔌 Database pool closed.")
            self.pool = None

    async def health_check(self) -> bool:
        """
        Quick connectivity test — used by !security-status.

        Returns:
            True if the database responds to a simple query.
        """
        if not self.pool:
            return False
        try:
            async with self.pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            return True
        except Exception as e:
            logger.warning(f"⚠️ Database health check failed: {e}")
            return False
