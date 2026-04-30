# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Redis Rate Limiting (Sliding Window)
#  Per-user message velocity tracker using Redis Sorted Sets.
#
#  Fix C-2: The original INCR+EXPIRE "fixed window" algorithm was
#  exploitable — a user could send (limit-1) messages at the END
#  of one window and (limit) messages at the START of the next,
#  achieving 2x the intended rate.
#
#  This sliding window implementation uses ZSET (sorted sets) with
#  timestamps as scores, providing precise per-second granularity.
# ══════════════════════════════════════════════════════════════════

import time

import redis.asyncio as aioredis


async def check_spam(
    redis: aioredis.Redis,
    user_id: int,
    guild_id: int,
    limit: int,
    window: int,
) -> bool:
    """
    Sliding window rate limiter using Redis Sorted Sets.

    Each message adds a timestamped entry. Old entries beyond the
    window are pruned, and the remaining count is compared to the limit.

    This prevents the "boundary burst" exploit where a user sends
    messages at the boundary of two fixed windows.

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
    now = time.time()
    cutoff = now - window

    # Pipeline: atomic batch of operations
    pipe = redis.pipeline(transaction=True)
    pipe.zremrangebyscore(key, "-inf", cutoff)   # Remove expired entries
    pipe.zadd(key, {str(now): now})              # Add current timestamp
    pipe.zcard(key)                              # Count entries in window
    pipe.expire(key, window + 1)                 # Auto-cleanup TTL
    results = await pipe.execute()

    count = results[2]  # zcard result
    return count > limit
