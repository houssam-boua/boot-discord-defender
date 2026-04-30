# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Redis Rate Limiting
#  Per-user message velocity tracker using redis.asyncio.
#  Directly from blueprint Section 8b: "Redis Rate Limiting"
# ══════════════════════════════════════════════════════════════════

import redis.asyncio as aioredis


async def check_spam(redis: aioredis.Redis, user_id: int, guild_id: int,
                     limit: int, window: int) -> bool:
    """
    Increment a per-user message counter in Redis and check if
    the user has exceeded the spam threshold.

    Args:
        redis:    Active Redis async client.
        user_id:  Discord user ID.
        guild_id: Discord guild ID.
        limit:    Maximum messages allowed in the window.
        window:   Time window in seconds.

    Returns:
        True if the user has exceeded the limit (is spamming).
    """
    key = f"spam:{guild_id}:{user_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window)
    return count > limit
