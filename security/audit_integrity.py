# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Audit Log Integrity
#  SHA-256 hash chaining for tamper-proof audit logs.
#  Directly from blueprint Section 8b: "Hash Chain Implementation"
#
#  Every audit log row stores a hash_signature computed from:
#    SHA256(previous_row_hash + JSON(current_log_data))
#
#  If any historical row is modified, the entire chain from that
#  point forward becomes invalid — detectable by !verify-integrity.
# ══════════════════════════════════════════════════════════════════

import hashlib
import json
import logging

logger = logging.getLogger("antiraid.audit")


def compute_log_hash(previous_hash: str, log_data: dict) -> str:
    """
    Compute a SHA-256 hash for a new audit log entry.

    The hash is derived from the previous row's hash concatenated
    with the JSON-serialized log data. This creates an append-only
    chain where modifying any past entry breaks the entire chain
    from that point forward.

    Args:
        previous_hash: The hash_signature of the preceding log row,
                       or "GENESIS" for the very first entry in a guild.
        log_data:      Dictionary containing the log entry fields
                       (guild_id, actor_id, target_id, action_type, details).

    Returns:
        A 64-character hexadecimal SHA-256 hash string.
    """
    payload = previous_hash + json.dumps(log_data, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


async def insert_audit_log(
    pool,
    guild_id: int,
    actor_id: int | None,
    target_id: int | None,
    action_type: str,
    details: dict,
    severity: str = "INFO",
) -> None:
    """
    Insert a tamper-proof audit log entry into the database.

    Uses an explicit transaction with SELECT ... FOR UPDATE to prevent
    concurrent events from reading the same previous_hash and silently
    breaking the cryptographic chain (race condition fix C-1).

    Steps (inside a single transaction):
      1. Lock + fetch the last hash_signature for this guild.
      2. Compute the new hash from (previous_hash + log_data).
      3. INSERT the row with the computed hash_signature.

    Args:
        pool:        asyncpg connection pool.
        guild_id:    Discord guild ID.
        actor_id:    Who triggered the action (None if system-generated).
        target_id:   Who was affected (None if not applicable).
        action_type: Event type string (e.g., "BAN", "MUTE", "GHOST_PING").
        details:     Flexible JSONB metadata dictionary.
        severity:    Log severity — "INFO", "WARN", or "CRITICAL".
    """
    try:
        async with pool.acquire() as conn:
            async with conn.transaction():
                # Lock the most recent row for this guild to serialize
                # concurrent hash chain appends (prevents race condition)
                last = await conn.fetchrow(
                    """SELECT hash_signature FROM audit_logs
                       WHERE guild_id = $1
                       ORDER BY id DESC LIMIT 1
                       FOR UPDATE""",
                    guild_id,
                )
                previous_hash = last["hash_signature"] if last else "GENESIS"

                log_data = {
                    "guild_id": guild_id,
                    "actor_id": actor_id,
                    "target_id": target_id,
                    "action_type": action_type,
                    "details": details,
                }
                new_hash = compute_log_hash(previous_hash, log_data)

                await conn.execute(
                    """INSERT INTO audit_logs
                       (guild_id, actor_id, target_id, action_type,
                        details, severity, hash_signature)
                       VALUES ($1, $2, $3, $4, $5, $6, $7)""",
                    guild_id,
                    actor_id,
                    target_id,
                    action_type,
                    json.dumps(details),
                    severity,
                    new_hash,
                )

        logger.debug(
            f"📝 Audit log: {action_type} in guild {guild_id} "
            f"(actor={actor_id}, target={target_id})"
        )

    except Exception as e:
        logger.error(f"❌ Failed to insert audit log: {e}")

