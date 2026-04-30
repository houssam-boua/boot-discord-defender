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
                    await _lift_quarantine(bot, guild, user_id, punishment_id)

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


async def _lift_quarantine(bot, guild: discord.Guild, user_id: int, punishment_id: int) -> None:
    """
    Lift a quarantine: remove the quarantine role and restore saved roles.

    When a user is quarantined, their existing roles are stripped and saved
    in the temporal_punishments.reason field as a JSON-encoded list of role IDs.
    This function reverses that process.
    """
    # Fetch the member
    member = guild.get_member(user_id)
    if not member:
        try:
            member = await guild.fetch_member(user_id)
        except discord.NotFound:
            return  # User left the guild

    # Fetch the punishment details to get saved role IDs
    saved_role_ids: list[int] = []
    if bot.db.pool:
        row = await bot.db.pool.fetchrow(
            "SELECT reason FROM temporal_punishments WHERE id = $1",
            punishment_id,
        )
        if row and row["reason"]:
            try:
                import json
                data = json.loads(row["reason"])
                if isinstance(data, dict):
                    saved_role_ids = data.get("saved_roles", [])
                elif isinstance(data, list):
                    saved_role_ids = data
            except (json.JSONDecodeError, TypeError):
                pass  # reason is plain text, not JSON — no roles to restore

    # Remove the quarantine role
    config_row = await bot.db.pool.fetchrow(
        "SELECT quarantine_role_id FROM server_configs WHERE guild_id = $1",
        guild.id,
    )
    if config_row and config_row["quarantine_role_id"]:
        quarantine_role = guild.get_role(config_row["quarantine_role_id"])
        if quarantine_role and quarantine_role in member.roles:
            try:
                await member.remove_roles(
                    quarantine_role, reason="[AntiRaid] Quarantine expired"
                )
            except discord.Forbidden:
                logger.warning(f"Cannot remove quarantine role from {member}")

    # Restore saved roles
    if saved_role_ids:
        roles_to_restore = []
        for role_id in saved_role_ids:
            role = guild.get_role(role_id)
            if role and not role.is_default() and role < guild.me.top_role:
                roles_to_restore.append(role)

        if roles_to_restore:
            try:
                await member.add_roles(
                    *roles_to_restore,
                    reason="[AntiRaid] Roles restored after quarantine expired",
                )
                logger.info(
                    f"🔄 Restored {len(roles_to_restore)} role(s) for {member} "
                    f"after quarantine lift"
                )
            except discord.Forbidden:
                logger.warning(f"Cannot restore roles for {member} — missing permissions")


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


async def recover_punishments_on_boot(bot) -> None:
    """
    Fix C-5: On startup, recover any active temporal punishments.

    - If expires_at <= NOW(): lift immediately (punishment expired while bot was offline).
    - If expires_at > NOW(): re-schedule with APScheduler trigger="date" so the
      punishment auto-lifts at the correct time.

    Without this, a bot restart would permanently lose all pending punishment
    timers — temp-banned users stay banned forever.
    """
    if not bot.db.pool:
        return

    try:
        rows = await bot.db.pool.fetch(
            """
            SELECT id, guild_id, user_id, punishment_type, expires_at
            FROM temporal_punishments
            WHERE active = TRUE
            """
        )

        if not rows:
            logger.info("🔄 No active punishments to recover.")
            return

        now = datetime.now(timezone.utc)
        recovered = 0
        lifted = 0

        for row in rows:
            expires_at = row["expires_at"]
            # Ensure timezone-aware comparison
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at <= now:
                # Already expired — lift immediately
                guild = bot.get_guild(row["guild_id"])
                if guild:
                    try:
                        if row["punishment_type"] == "ban":
                            await _lift_ban(guild, row["user_id"])
                        elif row["punishment_type"] == "mute":
                            await _lift_mute(guild, row["user_id"])
                    except Exception as e:
                        logger.debug(f"Could not lift expired punishment #{row['id']}: {e}")

                await _deactivate_punishment(bot.db.pool, row["id"])
                lifted += 1
            else:
                # Still pending — schedule with APScheduler
                scheduler.add_job(
                    _lift_single_punishment,
                    trigger="date",
                    run_date=expires_at,
                    args=[bot, row["id"], row["guild_id"], row["user_id"], row["punishment_type"]],
                    id=f"recover_punishment_{row['id']}",
                    replace_existing=True,
                )
                recovered += 1

        logger.info(
            f"🔄 Punishment recovery complete — "
            f"{lifted} lifted (expired), {recovered} re-scheduled."
        )

    except Exception as e:
        logger.error(f"❌ Punishment recovery failed: {e}")


async def _lift_single_punishment(
    bot, punishment_id: int, guild_id: int, user_id: int, punishment_type: str
) -> None:
    """Lift a single punishment by ID — used by the date-trigger scheduler."""
    guild = bot.get_guild(guild_id)
    if not guild:
        if bot.db.pool:
            await _deactivate_punishment(bot.db.pool, punishment_id)
        return

    try:
        if punishment_type == "ban":
            await _lift_ban(guild, user_id)
        elif punishment_type == "mute":
            await _lift_mute(guild, user_id)

        if bot.db.pool:
            await _deactivate_punishment(bot.db.pool, punishment_id)

        logger.info(
            f"✅ Recovered punishment #{punishment_id} lifted: "
            f"{punishment_type} for user {user_id} in {guild.name}"
        )
    except Exception as e:
        logger.error(f"❌ Failed to lift recovered punishment #{punishment_id}: {e}")

