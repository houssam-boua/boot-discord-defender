# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Auto-Raid Protection
#  Blueprint reference: Module 4 — Automated Panic Systems
#
#  "Auto-Lockdown"
#    Trigger: join spike exceeds raid_limit_count joins
#             in raid_limit_seconds (e.g., 10 joins / 3 seconds).
#    Action: set all channel send_messages to False for @everyone.
#    Snapshot saved to Redis before locking (used by !unlockdown).
#    Alert sent to the configured log channel with details.
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import json
import logging
from datetime import datetime, timezone

from security.audit_integrity import insert_audit_log

logger = logging.getLogger("antiraid.antiraid")

# ── Defaults (overridden by server_configs) ────────────────────
DEFAULT_RAID_LIMIT_COUNT = 10
DEFAULT_RAID_LIMIT_SECONDS = 3


class AntiRaid(commands.Cog, name="🚨 Anti-Raid"):
    """
    Automated raid detection and server lockdown.
    Tracks join velocity in Redis and triggers an auto-lockdown
    when the join spike exceeds the configured threshold.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ══════════════════════════════════════════════════════════════
    #  Helper: Fetch raid config from DB
    # ══════════════════════════════════════════════════════════════

    async def _get_raid_config(self, guild_id: int) -> dict:
        """Fetch raid limit thresholds and log channel from server_configs."""
        config = {
            "raid_limit_count": DEFAULT_RAID_LIMIT_COUNT,
            "raid_limit_seconds": DEFAULT_RAID_LIMIT_SECONDS,
            "log_channel_id": None,
        }

        if not self.bot.db.pool:
            return config

        row = await self.bot.db.pool.fetchrow(
            """
            SELECT raid_limit_count, raid_limit_seconds, log_channel_id
            FROM server_configs
            WHERE guild_id = $1
            """,
            guild_id,
        )
        if row:
            config["raid_limit_count"] = row["raid_limit_count"]
            config["raid_limit_seconds"] = row["raid_limit_seconds"]
            config["log_channel_id"] = row["log_channel_id"]

        return config

    # ══════════════════════════════════════════════════════════════
    #  Core: Auto-Lockdown — snapshot + lock all channels
    # ══════════════════════════════════════════════════════════════

    async def _execute_auto_lockdown(
        self,
        guild: discord.Guild,
        config: dict,
        join_count: int,
    ) -> None:
        """
        Execute an automatic server lockdown in response to a raid.
        Re-uses the same snapshot+lock pattern from the Moderation cog
        so that !unlockdown can restore permissions.

        Blueprint: "A snapshot of original permissions is saved to
        Redis before locking (used by !unlockdown)."
        """
        redis = self.bot.redis
        if not redis:
            logger.warning(
                f"Cannot auto-lockdown {guild.name} — Redis unavailable"
            )
            return

        # ── Check if already locked (prevent duplicate lockdowns) ──
        redis_key = f"lockdown_snapshot:{guild.id}"
        existing = await redis.get(redis_key)
        if existing:
            logger.info(
                f"Auto-lockdown skipped in {guild.name} — already locked"
            )
            return

        everyone_role = guild.default_role
        snapshot = {}
        locked_count = 0

        # ── Save snapshot & lock all text channels ─────────────
        for channel in guild.text_channels:
            overwrites = channel.overwrites_for(everyone_role)

            current_value = overwrites.send_messages
            snapshot[str(channel.id)] = (
                current_value if current_value is not None else "inherit"
            )

            if current_value is False:
                continue

            try:
                overwrites.send_messages = False
                await channel.set_permissions(
                    everyone_role,
                    overwrite=overwrites,
                    reason="[AntiRaid] AUTO-LOCKDOWN — Raid detected",
                )
                locked_count += 1
            except discord.Forbidden:
                logger.warning(
                    f"Cannot lock #{channel.name} — missing permissions"
                )
            except discord.HTTPException as e:
                logger.error(f"HTTP error locking #{channel.name}: {e}")

        # ── Save snapshot to Redis ─────────────────────────────
        await redis.set(
            redis_key,
            json.dumps(snapshot),
            ex=86400 * 7,  # 7-day TTL
        )

        # ── Log to database (ALWAYS) ──────────────────────────
        if self.bot.db.pool:
            await insert_audit_log(
                pool=self.bot.db.pool,
                guild_id=guild.id,
                actor_id=self.bot.user.id,
                target_id=None,
                action_type="AUTO_LOCKDOWN",
                details={
                    "trigger": "join_spike",
                    "join_count": join_count,
                    "threshold": config["raid_limit_count"],
                    "window_seconds": config["raid_limit_seconds"],
                    "channels_locked": locked_count,
                },
                severity="CRITICAL",
            )

        # ── Send critical alert to log channel ─────────────────
        if config["log_channel_id"]:
            log_channel = guild.get_channel(config["log_channel_id"])
            if log_channel:
                embed = discord.Embed(
                    title="🚨 AUTO-LOCKDOWN ACTIVATED — Raid Detected",
                    description=(
                        f"A join spike has exceeded the raid threshold.\n"
                        f"The server has been automatically locked down.\n\n"
                        f"**Joins detected:** {join_count} in "
                        f"{config['raid_limit_seconds']}s\n"
                        f"**Threshold:** {config['raid_limit_count']} joins / "
                        f"{config['raid_limit_seconds']}s\n"
                        f"**Channels locked:** {locked_count}\n\n"
                        f"Use `!unlockdown` to restore permissions when safe."
                    ),
                    color=discord.Color.dark_red(),
                    timestamp=datetime.now(timezone.utc),
                )
                embed.set_footer(text="⚠️ Automated response by AntiRaid")

                try:
                    await log_channel.send(content="@here", embed=embed)
                except Exception as e:
                    logger.error(f"Failed to send auto-lockdown alert: {e}")

        logger.critical(
            f"🚨 AUTO-LOCKDOWN in {guild.name} ({guild.id}) — "
            f"{join_count} joins in {config['raid_limit_seconds']}s "
            f"(threshold: {config['raid_limit_count']}), "
            f"{locked_count} channels locked"
        )

    # ══════════════════════════════════════════════════════════════
    #  LISTENER: on_member_join — Join Velocity Tracker
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        """
        Track join velocity using Redis and trigger auto-lockdown
        if the join rate exceeds the configured threshold.

        Redis key: raid:joins:{guild_id}
        Expiration: raid_limit_seconds
        """
        # Skip bots — they don't count toward raid detection
        if member.bot:
            return

        guild = member.guild
        redis = self.bot.redis
        if not redis:
            return

        config = await self._get_raid_config(guild.id)

        # ── Increment join counter in Redis ────────────────────
        key = f"raid:joins:{guild.id}"
        count = await redis.incr(key)
        if count == 1:
            await redis.expire(key, config["raid_limit_seconds"])

        # ── Check threshold ────────────────────────────────────
        if count >= config["raid_limit_count"]:
            logger.warning(
                f"⚠️ Join spike in {guild.name}: {count} joins in "
                f"{config['raid_limit_seconds']}s (limit: {config['raid_limit_count']})"
            )
            await self._execute_auto_lockdown(guild, config, count)


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AntiRaid(bot))
