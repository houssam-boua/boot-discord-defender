import asyncio
import asyncpg
from config import Config

async def main():
    pool = await asyncpg.create_pool(Config.DATABASE_URL)
    row = await pool.fetchrow(
        "SELECT column_name, data_type, column_default FROM information_schema.columns WHERE table_name = 'server_configs' AND column_name = 'allow_invites'"
    )
    print(dict(row) if row else "Not found")
    await pool.close()

asyncio.run(main())
