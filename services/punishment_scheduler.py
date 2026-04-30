# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Punishment Scheduler
#  Uses APScheduler (AsyncIOScheduler) to auto-lift expired
#  temporary punishments (bans, mutes, quarantines).
#
#  Runs a job every 30 seconds that:
#    1. Queries temporal_punishments for active + expired records
#    2. Lifts the punishment in Discord (unban / remove timeout)
#    3. Marks the record as active = FALSE in the database
#
#  Blueprint reference: Section 3 (APScheduler), Section 12
#  ("Bot Restart — punishments stored in PostgreSQL, reloaded on boot")
# ══════════════════════════════════════════════════════════════════

import logging
from datetime import datetime, timezone

import discord
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger("antiraid.scheduler")

# Module-level scheduler instance
scheduler = AsyncIOScheduler()


async def _lift_expired_punishments(bot) -> None:
    """
    Core scheduled job — runs every 30 seconds.
    Queries the database for all active punishments that have expired,
    lifts them in Discord, and marks them inactive in the DB.
    """
    if not bot.db.pool:
        return

    try:
        # Fetch all expired, still-active punishments
        rows = await bot.db.pool.fetch(
            """
            SELECT id, guild_id, user_id, punishment_type
            FROM temporal_punishments
            WHERE active = TRUE AND expires_at <= NOW()
            """
        )

        if not rows:
            return

        logger.info(f"⏰ Found {len(rows)} expired punishment(s) to lift.")

        for row in rows:
            punishment_id = row["id"]
            guild_id = row["guild_id"]
            user_id = row["user_id"]
            punishment_type = row["punishment_type"]

            guild = bot.get_guild(guild_id)
            if not guild:
                # Bot is no longer in this guild — just deactivate the record
                await _deactivate_punishment(bot.db.pool, punishment_id)
                logger.debug(
                    f"Guild {guild_id} not found — deactivated punishment #{punishment_id}"
                )
                continue

            try:
                if punishment_type == "ban":
                    await _lift_ban(guild, user_id)
                elif punishment_type == "mute":
                    await _lift_mute(guild, user_id)
                elif punishment_type == "quarantine":
                    # Quarantine lift requires role restoration — Phase 2
                    logger.debug(
                        f"Quarantine lift for user {user_id} — not yet implemented"
                    )

                # Mark as inactive in DB
                await _deactivate_punishment(bot.db.pool, punishment_id)

                logger.info(
                    f"✅ Lifted {punishment_type} for user {user_id} "
                    f"in {guild.name} (punishment #{punishment_id})"
                )

            except discord.NotFound:
                # User left the server or ban was already lifted
                await _deactivate_punishment(bot.db.pool, punishment_id)
                logger.debug(
                    f"User {user_id} not found — deactivated punishment #{punishment_id}"
                )
            except discord.Forbidden:
                logger.warning(
                    f"⚠️ Missing permissions to lift {punishment_type} "
                    f"for user {user_id} in {guild.name}"
                )
            except Exception as e:
                logger.error(
                    f"❌ Failed to lift punishment #{punishment_id}: {e}"
                )

    except Exception as e:
        logger.error(f"❌ Punishment scheduler job error: {e}")


async def _lift_ban(guild: discord.Guild, user_id: int) -> None:
    """Unban a user by ID."""
    user = discord.Object(id=user_id)
    await guild.unban(user, reason="[AntiRaid] Temporary ban expired")


async def _lift_mute(guild: discord.Guild, user_id: int) -> None:
    """Remove timeout from a member."""
    member = guild.get_member(user_id)
    if member:
        await member.timeout(None, reason="[AntiRaid] Temporary mute expired")
    else:
        # Member not in cache — try fetching
        try:
            member = await guild.fetch_member(user_id)
            await member.timeout(None, reason="[AntiRaid] Temporary mute expired")
        except discord.NotFound:
            pass  # User left the guild


async def _deactivate_punishment(pool, punishment_id: int) -> None:
    """Mark a punishment record as inactive in the database."""
    await pool.execute(
        "UPDATE temporal_punishments SET active = FALSE WHERE id = $1",
        punishment_id,
    )


def start_scheduler(bot) -> None:
    """
    Initialize and start the punishment scheduler.
    Call this in main.py's setup_hook after DB and Redis are connected.

    Args:
        bot: The AntiRaidBot instance (passed to the job function).
    """
    scheduler.add_job(
        _lift_expired_punishments,
        trigger="interval",
        seconds=30,
        args=[bot],
        id="lift_expired_punishments",
        replace_existing=True,
        max_instances=1,
    )

    if not scheduler.running:
        scheduler.start()
        logger.info("✅ Punishment scheduler started (interval: 30s)")


def stop_scheduler() -> None:
    """Gracefully shut down the scheduler."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("🔌 Punishment scheduler stopped.")
