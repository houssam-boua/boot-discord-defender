# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Moderation Cog
#  Emergency commands and temporal punishment management.
#
#  Commands (all @is_staff() protected):
#    !temp-ban  [@user] [duration] [reason]
#    !temp-mute [@user] [duration] [reason]
#    !purge     [number]
#    !purge-user [@user]
#    !lockdown
#    !unlockdown
#
#  Blueprint references:
#    Section 6 — Admin Command Reference (Emergency + Moderation)
#    Module 4  — Automated Panic Systems (lockdown snapshots)
#    Section 12 — Engineering Challenges (batch purge, rate limits)
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import json
import re
import logging
from datetime import datetime, timedelta, timezone

from utils.permissions import is_staff, NotStaff

logger = logging.getLogger("antiraid.moderation")


# ══════════════════════════════════════════════════════════════════
#  Duration Parser — converts "1h", "2d", "30m" to timedelta
# ══════════════════════════════════════════════════════════════════

# Regex: captures a number followed by a time unit letter
_DURATION_RE = re.compile(
    r"^(\d+)\s*(m|min|mins|minutes|h|hr|hrs|hours|d|day|days|w|week|weeks|s|sec|secs|seconds)$",
    re.IGNORECASE,
)

# Unit multipliers in seconds
_UNIT_MAP = {
    "s": 1, "sec": 1, "secs": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}

# Limits
MAX_DURATION_SECONDS = 28 * 86400  # 28 days (Discord timeout limit)
MAX_BAN_DURATION_SECONDS = 365 * 86400  # 1 year


def parse_duration(text: str) -> timedelta | None:
    """
    Parse a human-readable duration string into a timedelta.

    Supported formats: "30s", "5m", "1h", "2d", "1w"

    Args:
        text: The duration string (e.g., "2h", "7d").

    Returns:
        A timedelta object, or None if parsing fails.
    """
    match = _DURATION_RE.match(text.strip())
    if not match:
        return None

    amount = int(match.group(1))
    unit = match.group(2).lower()

    if unit not in _UNIT_MAP:
        return None

    total_seconds = amount * _UNIT_MAP[unit]

    if total_seconds <= 0:
        return None

    return timedelta(seconds=total_seconds)


def format_duration(td: timedelta) -> str:
    """Format a timedelta into a human-readable string."""
    total = int(td.total_seconds())
    if total >= 86400:
        days = total // 86400
        return f"{days} day{'s' if days != 1 else ''}"
    elif total >= 3600:
        hours = total // 3600
        return f"{hours} hour{'s' if hours != 1 else ''}"
    elif total >= 60:
        mins = total // 60
        return f"{mins} minute{'s' if mins != 1 else ''}"
    else:
        return f"{total} second{'s' if total != 1 else ''}"


class Moderation(commands.Cog, name="🔨 Moderation"):
    """Emergency commands and temporal punishment management."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ── Helper: Send alert to log channel ──────────────────────
    async def _log_to_channel(
        self,
        guild: discord.Guild,
        embed: discord.Embed,
    ) -> None:
        """Send an embed to the guild's configured log channel."""
        if not self.bot.db.pool:
            return

        row = await self.bot.db.pool.fetchrow(
            "SELECT log_channel_id FROM server_configs WHERE guild_id = $1",
            guild.id,
        )
        if not row or not row["log_channel_id"]:
            return

        log_channel = guild.get_channel(row["log_channel_id"])
        if log_channel:
            try:
                await log_channel.send(embed=embed)
            except Exception as e:
                logger.error(f"Failed to send to log channel: {e}")

    # ── Helper: Insert punishment record ───────────────────────
    async def _insert_punishment(
        self,
        guild_id: int,
        user_id: int,
        punishment_type: str,
        duration: timedelta,
        reason: str,
        issued_by: int,
        details: dict | None = None,
    ) -> None:
        """Insert a temporal punishment record into the database."""
        expires_at = datetime.now(timezone.utc) + duration
        details_json = json.dumps(details) if details else '{}'

        await self.bot.db.pool.execute(
            """
            INSERT INTO temporal_punishments
                (guild_id, user_id, punishment_type, expires_at, reason, issued_by, details)
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
            """,
            guild_id,
            user_id,
            punishment_type,
            expires_at,
            reason,
            issued_by,
            details_json,
        )

    # ══════════════════════════════════════════════════════════════
    #  !temp-ban [@user] [duration] [reason]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="temp-ban",
        aliases=["tempban", "tban"],
        help="Temporarily ban a user. Auto-lifted after duration.",
        usage="<@user> <duration> [reason]",
    )
    @is_staff()
    async def temp_ban(
        self,
        ctx: commands.Context,
        member: discord.Member,
        duration_str: str,
        *,
        reason: str = "No reason provided",
    ) -> None:
        """Temporarily ban a user — auto-unbanned by the scheduler."""

        # ── Parse duration ─────────────────────────────────────
        duration = parse_duration(duration_str)
        if not duration:
            embed = discord.Embed(
                title="❌ Invalid Duration",
                description=(
                    "Use a format like: `30m`, `1h`, `2d`, `1w`\n\n"
                    "**Examples:**\n"
                    "• `!temp-ban @user 1h Spamming`\n"
                    "• `!temp-ban @user 7d Raiding`"
                ),
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        if duration.total_seconds() > MAX_BAN_DURATION_SECONDS:
            embed = discord.Embed(
                title="❌ Duration Too Long",
                description="Maximum temp-ban duration is **365 days**.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Hierarchy check ────────────────────────────────────
        if member.top_role >= ctx.author.top_role and ctx.author.id != ctx.guild.owner_id:
            embed = discord.Embed(
                title="❌ Cannot Ban",
                description="You cannot ban someone with an equal or higher role.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Execute ban ────────────────────────────────────────
        try:
            await member.ban(
                reason=f"[AntiRaid] Temp-ban by {ctx.author} | Duration: {format_duration(duration)} | {reason}",
                delete_message_days=0,
            )
        except discord.Forbidden:
            embed = discord.Embed(
                title="❌ Missing Permissions",
                description="I don't have permission to ban this user.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Insert into DB ─────────────────────────────────────
        await self._insert_punishment(
            guild_id=ctx.guild.id,
            user_id=member.id,
            punishment_type="ban",
            duration=duration,
            reason=reason,
            issued_by=ctx.author.id,
        )

        # ── Confirmation ───────────────────────────────────────
        human_duration = format_duration(duration)
        embed = discord.Embed(
            title="🔨 Temporary Ban",
            description=(
                f"**{member}** has been temporarily banned.\n\n"
                f"**Duration:** {human_duration}\n"
                f"**Reason:** {reason}\n"
                f"**Issued by:** {ctx.author.mention}"
            ),
            color=discord.Color.dark_red(),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        await ctx.send(embed=embed)

        # Log to channel
        await self._log_to_channel(ctx.guild, embed)

        logger.info(
            f"🔨 Temp-ban: {member} ({member.id}) for {human_duration} "
            f"by {ctx.author} ({ctx.author.id}) in {ctx.guild.name} — {reason}"
        )

    # ══════════════════════════════════════════════════════════════
    #  !temp-mute [@user] [duration] [reason]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="temp-mute",
        aliases=["tempmute", "tmute"],
        help="Temporarily mute a user using Discord's native timeout.",
        usage="<@user> <duration> [reason]",
    )
    @is_staff()
    async def temp_mute(
        self,
        ctx: commands.Context,
        member: discord.Member,
        duration_str: str,
        *,
        reason: str = "No reason provided",
    ) -> None:
        """Temporarily mute a user — auto-unmuted by Discord timeout + scheduler."""

        # ── Parse duration ─────────────────────────────────────
        duration = parse_duration(duration_str)
        if not duration:
            embed = discord.Embed(
                title="❌ Invalid Duration",
                description=(
                    "Use a format like: `30m`, `1h`, `2d`, `1w`\n\n"
                    "**Examples:**\n"
                    "• `!temp-mute @user 30m Excessive caps`\n"
                    "• `!temp-mute @user 2h Ignoring warnings`"
                ),
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        if duration.total_seconds() > MAX_DURATION_SECONDS:
            embed = discord.Embed(
                title="❌ Duration Too Long",
                description="Maximum mute duration is **28 days** (Discord timeout limit).",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Hierarchy check ────────────────────────────────────
        if member.top_role >= ctx.author.top_role and ctx.author.id != ctx.guild.owner_id:
            embed = discord.Embed(
                title="❌ Cannot Mute",
                description="You cannot mute someone with an equal or higher role.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Apply timeout ──────────────────────────────────────
        try:
            await member.timeout(
                duration,
                reason=f"[AntiRaid] Temp-mute by {ctx.author} | Duration: {format_duration(duration)} | {reason}",
            )
        except discord.Forbidden:
            embed = discord.Embed(
                title="❌ Missing Permissions",
                description="I don't have permission to mute this user.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Insert into DB ─────────────────────────────────────
        await self._insert_punishment(
            guild_id=ctx.guild.id,
            user_id=member.id,
            punishment_type="mute",
            duration=duration,
            reason=reason,
            issued_by=ctx.author.id,
        )

        # ── Confirmation ───────────────────────────────────────
        human_duration = format_duration(duration)
        embed = discord.Embed(
            title="🔇 Temporary Mute",
            description=(
                f"**{member}** has been temporarily muted.\n\n"
                f"**Duration:** {human_duration}\n"
                f"**Reason:** {reason}\n"
                f"**Issued by:** {ctx.author.mention}"
            ),
            color=discord.Color.orange(),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        await ctx.send(embed=embed)

        await self._log_to_channel(ctx.guild, embed)

        logger.info(
            f"🔇 Temp-mute: {member} ({member.id}) for {human_duration} "
            f"by {ctx.author} ({ctx.author.id}) in {ctx.guild.name} — {reason}"
        )

    # ══════════════════════════════════════════════════════════════
    #  !purge [number]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="purge",
        aliases=["clear", "clean"],
        help="Delete the last N messages in the current channel.",
        usage="<number>",
    )
    @is_staff()
    async def purge(self, ctx: commands.Context, amount: int) -> None:
        """Bulk-delete messages from the current channel."""

        if amount < 1 or amount > 1000:
            embed = discord.Embed(
                title="❌ Invalid Amount",
                description="You can purge between **1** and **1000** messages.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # Delete the command message itself first
        try:
            await ctx.message.delete()
        except discord.Forbidden:
            pass

        # Batch delete in chunks of 100 (Discord API limit)
        # discord.py's purge() handles batching internally
        deleted = await ctx.channel.purge(limit=amount)

        embed = discord.Embed(
            title="🗑️ Purge Complete",
            description=f"Deleted **{len(deleted)}** messages in {ctx.channel.mention}.",
            color=discord.Color.green(),
        )
        embed.set_footer(text=f"Executed by {ctx.author}")
        confirmation = await ctx.send(embed=embed)

        # Auto-delete the confirmation after 5 seconds
        await confirmation.delete(delay=5)

        logger.info(
            f"🗑️ Purged {len(deleted)} messages in #{ctx.channel.name} "
            f"by {ctx.author} ({ctx.author.id})"
        )

    # ══════════════════════════════════════════════════════════════
    #  !purge-user [@user]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="purge-user",
        aliases=["purgeuser", "nuke-user"],
        help="Delete all messages from a user across all channels.",
        usage="<@user>",
    )
    @is_staff()
    async def purge_user(
        self, ctx: commands.Context, target: discord.Member
    ) -> None:
        """
        Scan all text channels and delete messages from the target user.
        Uses batch processing in chunks of 100 to respect Discord rate limits.
        """
        # Delete the command message
        try:
            await ctx.message.delete()
        except discord.Forbidden:
            pass

        status_embed = discord.Embed(
            title="🗑️ Purge User — In Progress",
            description=f"Scanning all channels for messages from {target.mention}...",
            color=discord.Color.yellow(),
        )
        status_msg = await ctx.send(embed=status_embed)

        total_deleted = 0

        for channel in ctx.guild.text_channels:
            # Check if bot has permission in this channel
            perms = channel.permissions_for(ctx.guild.me)
            if not perms.manage_messages or not perms.read_message_history:
                continue

            try:
                deleted = await channel.purge(
                    limit=500,
                    check=lambda m: m.author.id == target.id,
                )
                total_deleted += len(deleted)
            except discord.Forbidden:
                continue
            except discord.HTTPException as e:
                logger.warning(f"Purge error in #{channel.name}: {e}")
                continue

        # Update the status message
        result_embed = discord.Embed(
            title="🗑️ Purge User — Complete",
            description=(
                f"Deleted **{total_deleted}** messages from {target.mention} "
                f"across all channels."
            ),
            color=discord.Color.green(),
        )
        result_embed.set_footer(text=f"Executed by {ctx.author}")

        try:
            await status_msg.edit(embed=result_embed)
            await status_msg.delete(delay=10)
        except Exception:
            pass

        await self._log_to_channel(ctx.guild, result_embed)

        logger.info(
            f"🗑️ Purged {total_deleted} messages from {target} ({target.id}) "
            f"across all channels by {ctx.author}"
        )

    # ══════════════════════════════════════════════════════════════
    #  !lockdown
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="lockdown",
        aliases=["lock"],
        help="Lock all channels — sets send_messages=False for @everyone.",
    )
    @is_staff()
    async def lockdown(self, ctx: commands.Context) -> None:
        """
        Emergency lockdown — saves permission snapshot to Redis,
        then sets send_messages=False for @everyone on all text channels.
        """
        # ── Check Redis availability ───────────────────────────
        if not self.bot.redis:
            embed = discord.Embed(
                title="❌ Redis Unavailable",
                description=(
                    "Lockdown requires Redis to save the permission snapshot.\n"
                    "Cannot lock down without the ability to restore later."
                ),
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        everyone_role = ctx.guild.default_role
        snapshot = {}
        locked_count = 0

        # ── Save current permissions & lock ────────────────────
        status_embed = discord.Embed(
            title="🔒 Lockdown — In Progress",
            description="Locking all channels...",
            color=discord.Color.yellow(),
        )
        status_msg = await ctx.send(embed=status_embed)

        for channel in ctx.guild.text_channels:
            overwrites = channel.overwrites_for(everyone_role)

            # Save current send_messages state (True, False, or None)
            current_value = overwrites.send_messages
            snapshot[str(channel.id)] = (
                current_value if current_value is not None else "inherit"
            )

            # Skip if already locked
            if current_value is False:
                continue

            # Set send_messages = False for @everyone
            try:
                overwrites.send_messages = False
                await channel.set_permissions(
                    everyone_role,
                    overwrite=overwrites,
                    reason=f"[AntiRaid] Lockdown by {ctx.author}",
                )
                locked_count += 1
            except discord.Forbidden:
                logger.warning(f"Cannot lock #{channel.name} — missing permissions")
            except discord.HTTPException as e:
                logger.error(f"HTTP error locking #{channel.name}: {e}")

        # ── Save snapshot to Redis ─────────────────────────────
        redis_key = f"lockdown_snapshot:{ctx.guild.id}"
        await self.bot.redis.set(
            redis_key,
            json.dumps(snapshot),
            ex=86400 * 7,  # Expire after 7 days
        )

        # ── Confirmation ───────────────────────────────────────
        result_embed = discord.Embed(
            title="🔒 Server Lockdown Active",
            description=(
                f"**{locked_count}** channels have been locked.\n"
                f"`send_messages` set to `False` for @everyone.\n\n"
                f"Use `{ctx.prefix}unlockdown` to restore permissions."
            ),
            color=discord.Color.dark_red(),
        )
        result_embed.set_footer(
            text=f"Locked by {ctx.author}", icon_url=ctx.author.display_avatar.url
        )

        try:
            await status_msg.edit(embed=result_embed)
        except Exception:
            await ctx.send(embed=result_embed)

        await self._log_to_channel(ctx.guild, result_embed)

        logger.info(
            f"🔒 Lockdown activated in {ctx.guild.name} ({ctx.guild.id}) "
            f"by {ctx.author} — {locked_count} channels locked"
        )

    # ══════════════════════════════════════════════════════════════
    #  !unlockdown
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="unlockdown",
        aliases=["unlock"],
        help="Restore all channels to pre-lockdown permissions.",
    )
    @is_staff()
    async def unlockdown(self, ctx: commands.Context) -> None:
        """
        Restore permissions from the Redis snapshot saved during lockdown.
        """
        # ── Check Redis availability ───────────────────────────
        if not self.bot.redis:
            embed = discord.Embed(
                title="❌ Redis Unavailable",
                description="Cannot retrieve the lockdown snapshot without Redis.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Retrieve snapshot ──────────────────────────────────
        redis_key = f"lockdown_snapshot:{ctx.guild.id}"
        snapshot_data = await self.bot.redis.get(redis_key)

        if not snapshot_data:
            embed = discord.Embed(
                title="❌ No Snapshot Found",
                description=(
                    "No lockdown snapshot exists for this server.\n"
                    "Either the server was never locked, or the snapshot expired (7 days)."
                ),
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        snapshot = json.loads(snapshot_data)
        everyone_role = ctx.guild.default_role
        restored_count = 0

        # ── Restore permissions ────────────────────────────────
        status_embed = discord.Embed(
            title="🔓 Unlockdown — In Progress",
            description="Restoring channel permissions...",
            color=discord.Color.yellow(),
        )
        status_msg = await ctx.send(embed=status_embed)

        for channel_id_str, saved_value in snapshot.items():
            channel = ctx.guild.get_channel(int(channel_id_str))
            if not channel:
                continue

            overwrites = channel.overwrites_for(everyone_role)

            # Restore the original send_messages permission
            if saved_value == "inherit" or saved_value is None:
                overwrites.send_messages = None  # Reset to inherit
            else:
                overwrites.send_messages = saved_value

            try:
                await channel.set_permissions(
                    everyone_role,
                    overwrite=overwrites,
                    reason=f"[AntiRaid] Unlockdown by {ctx.author}",
                )
                restored_count += 1
            except discord.Forbidden:
                logger.warning(f"Cannot unlock #{channel.name} — missing permissions")
            except discord.HTTPException as e:
                logger.error(f"HTTP error unlocking #{channel.name}: {e}")

        # ── Clean up the snapshot from Redis ───────────────────
        await self.bot.redis.delete(redis_key)

        # ── Confirmation ───────────────────────────────────────
        result_embed = discord.Embed(
            title="🔓 Lockdown Lifted",
            description=(
                f"**{restored_count}** channel permissions have been restored.\n"
                f"The server is now back to normal operation."
            ),
            color=discord.Color.green(),
        )
        result_embed.set_footer(
            text=f"Unlocked by {ctx.author}", icon_url=ctx.author.display_avatar.url
        )

        try:
            await status_msg.edit(embed=result_embed)
        except Exception:
            await ctx.send(embed=result_embed)

        await self._log_to_channel(ctx.guild, result_embed)

        logger.info(
            f"🔓 Unlockdown in {ctx.guild.name} ({ctx.guild.id}) "
            f"by {ctx.author} — {restored_count} channels restored"
        )

    # ══════════════════════════════════════════════════════════════
    #  !panic-mode
    #  "Lockdown + enable maximum verification + alert staff"
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="panic-mode",
        aliases=["panic"],
        help="Lockdown + enable maximum verification + alert all staff.",
    )
    @is_staff()
    async def panic_mode(self, ctx: commands.Context) -> None:
        """Compound emergency command — activates all defenses at once."""
        pool = self.bot.db.pool

        # ── 1. Lockdown all channels ──────────────────────────
        if self.bot.redis:
            redis_key = f"lockdown_snapshot:{ctx.guild.id}"
            existing = await self.bot.redis.get(redis_key)

            if not existing:
                everyone_role = ctx.guild.default_role
                snapshot = {}
                locked_count = 0

                for channel in ctx.guild.text_channels:
                    overwrites = channel.overwrites_for(everyone_role)
                    current_value = overwrites.send_messages
                    snapshot[str(channel.id)] = (
                        current_value if current_value is not None else "inherit"
                    )
                    if current_value is not False:
                        try:
                            overwrites.send_messages = False
                            await channel.set_permissions(
                                everyone_role, overwrite=overwrites,
                                reason=f"[AntiRaid] PANIC MODE by {ctx.author}",
                            )
                            locked_count += 1
                        except (discord.Forbidden, discord.HTTPException):
                            pass

                await self.bot.redis.set(redis_key, json.dumps(snapshot), ex=86400 * 7)

        # ── 2. Enable max verification ────────────────────────
        if pool:
            await pool.execute(
                """UPDATE server_configs
                   SET captcha_enabled = TRUE, antinuke_enabled = TRUE, antispam_enabled = TRUE
                   WHERE guild_id = $1""",
                ctx.guild.id,
            )

        # ── 3. Log to audit ───────────────────────────────────
        if pool:
            from security.audit_integrity import insert_audit_log
            await insert_audit_log(
                pool=pool, guild_id=ctx.guild.id, actor_id=ctx.author.id,
                target_id=None, action_type="PANIC_MODE",
                details={"triggered_by": str(ctx.author)}, severity="CRITICAL",
            )

        # ── 4. Alert ──────────────────────────────────────────
        embed = discord.Embed(
            title="🚨 PANIC MODE ACTIVATED",
            description=(
                "**All emergency defenses are now active:**\n\n"
                "🔒 Server locked down\n"
                "✅ CAPTCHA enabled\n"
                "🛡️ Anti-Nuke enabled\n"
                "🔇 Anti-Spam enabled\n\n"
                f"Use `{ctx.prefix}unlockdown` to restore when safe."
            ),
            color=discord.Color.dark_red(),
        )
        embed.set_footer(text=f"Activated by {ctx.author}")
        await ctx.send(content="@here", embed=embed)
        await self._log_to_channel(ctx.guild, embed)

        logger.critical(f"🚨 PANIC MODE in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !slowmode-all [seconds]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="slowmode-all",
        aliases=["slowmodeall", "globalslowmode"],
        help="Apply slowmode to every text channel at once.",
        usage="<seconds>",
    )
    @is_staff()
    async def slowmode_all(self, ctx: commands.Context, seconds: int) -> None:
        """Set slowmode on all text channels. Use 0 to disable."""
        if seconds < 0 or seconds > 21600:
            embed = discord.Embed(
                title="❌ Invalid Value",
                description="Slowmode must be between **0** and **21600** seconds (6 hours).",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        updated = 0
        for channel in ctx.guild.text_channels:
            try:
                await channel.edit(
                    slowmode_delay=seconds,
                    reason=f"[AntiRaid] Slowmode-all by {ctx.author}",
                )
                updated += 1
            except (discord.Forbidden, discord.HTTPException):
                pass

        action = f"set to **{seconds}s**" if seconds > 0 else "**removed**"
        embed = discord.Embed(
            title="🐌 Slowmode Applied" if seconds > 0 else "🐌 Slowmode Removed",
            description=f"Slowmode {action} on **{updated}** channels.",
            color=discord.Color.green(),
        )
        embed.set_footer(text=f"By {ctx.author}")
        await ctx.send(embed=embed)
        logger.info(f"Slowmode-all {seconds}s in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !quarantine [@user]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="quarantine",
        aliases=["q"],
        help="Strip all roles from a user and assign the quarantine role.",
        usage="<@user>",
    )
    @is_staff()
    async def quarantine(self, ctx: commands.Context, member: discord.Member) -> None:
        """Manually quarantine a user — strip roles, assign quarantine role."""
        pool = self.bot.db.pool

        # Fetch quarantine role from config
        row = await pool.fetchrow(
            "SELECT quarantine_role_id FROM server_configs WHERE guild_id = $1",
            ctx.guild.id,
        )
        if not row or not row["quarantine_role_id"]:
            embed = discord.Embed(
                title="❌ No Quarantine Role",
                description=f"Set one first with `{ctx.prefix}set-quarantine-role @role`.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        q_role = ctx.guild.get_role(row["quarantine_role_id"])
        if not q_role:
            await ctx.send("❌ Quarantine role no longer exists.")
            return

        # Save current roles for restoration
        saved_role_ids = [r.id for r in member.roles if r != ctx.guild.default_role]

        # Save to Redis for instant !unquarantine access
        if self.bot.redis:
            await self.bot.redis.set(
                f"quarantine_roles:{ctx.guild.id}:{member.id}",
                json.dumps(saved_role_ids),
                ex=86400 * 30,  # 30-day TTL
            )

        # Strip roles + assign quarantine
        removable = [r for r in member.roles if r != ctx.guild.default_role and r.is_assignable()]
        try:
            if removable:
                await member.remove_roles(*removable, reason=f"[AntiRaid] Quarantine by {ctx.author}")
            await member.add_roles(q_role, reason=f"[AntiRaid] Quarantine by {ctx.author}")
        except discord.Forbidden:
            await ctx.send("❌ Missing permissions to modify this user's roles.")
            return

        # Persist to temporal_punishments with saved roles in details JSONB
        # This ensures the scheduler can restore roles even after a Redis restart.
        await self._insert_punishment(
            guild_id=ctx.guild.id,
            user_id=member.id,
            punishment_type="quarantine",
            duration=timedelta(days=365 * 10),  # Indefinite — lifted manually or by scheduler
            reason=f"Quarantined by {ctx.author}",
            issued_by=ctx.author.id,
            details={"saved_roles": saved_role_ids},
        )

        embed = discord.Embed(
            title="🔒 User Quarantined",
            description=(
                f"**{member}** has been quarantined.\n\n"
                f"**Roles removed:** {len(removable)}\n"
                f"**Quarantine role:** {q_role.mention}\n\n"
                f"Use `{ctx.prefix}unquarantine {member.mention}` to restore."
            ),
            color=discord.Color.dark_orange(),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        await ctx.send(embed=embed)
        await self._log_to_channel(ctx.guild, embed)
        logger.info(f"Quarantined {member} in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !unquarantine [@user]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="unquarantine",
        aliases=["uq"],
        help="Restore a quarantined user's roles.",
        usage="<@user>",
    )
    @is_staff()
    async def unquarantine(self, ctx: commands.Context, member: discord.Member) -> None:
        """Restore roles from the Redis snapshot saved during quarantine."""
        # Fetch saved roles
        saved_data = None
        if self.bot.redis:
            saved_data = await self.bot.redis.get(
                f"quarantine_roles:{ctx.guild.id}:{member.id}"
            )

        if not saved_data:
            await ctx.send("❌ No saved roles found for this user (snapshot may have expired).")
            return

        role_ids = json.loads(saved_data)

        # Remove quarantine role
        row = await self.bot.db.pool.fetchrow(
            "SELECT quarantine_role_id FROM server_configs WHERE guild_id = $1",
            ctx.guild.id,
        )
        if row and row["quarantine_role_id"]:
            q_role = ctx.guild.get_role(row["quarantine_role_id"])
            if q_role and q_role in member.roles:
                try:
                    await member.remove_roles(q_role, reason="[AntiRaid] Unquarantine")
                except discord.Forbidden:
                    pass

        # Restore saved roles
        restored = 0
        for rid in role_ids:
            role = ctx.guild.get_role(rid)
            if role and role.is_assignable():
                try:
                    await member.add_roles(role, reason=f"[AntiRaid] Unquarantine by {ctx.author}")
                    restored += 1
                except (discord.Forbidden, discord.HTTPException):
                    pass

        # Clean up Redis
        await self.bot.redis.delete(f"quarantine_roles:{ctx.guild.id}:{member.id}")

        embed = discord.Embed(
            title="🔓 User Unquarantined",
            description=f"**{member}** has been restored. **{restored}** roles re-applied.",
            color=discord.Color.green(),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        await ctx.send(embed=embed)
        logger.info(f"Unquarantined {member} in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !warn [@user] [reason]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="warn",
        help="Issue a formal warning to a user (logged to DB).",
        usage="<@user> <reason>",
    )
    @is_staff()
    async def warn(
        self, ctx: commands.Context, member: discord.Member, *, reason: str = "No reason provided"
    ) -> None:
        """Issue a warning — stored in audit_logs with WARN severity."""
        pool = self.bot.db.pool

        from security.audit_integrity import insert_audit_log
        await insert_audit_log(
            pool=pool, guild_id=ctx.guild.id, actor_id=ctx.author.id,
            target_id=member.id, action_type="WARN",
            details={"reason": reason}, severity="WARN",
        )

        # Try to DM the user
        try:
            dm_embed = discord.Embed(
                title=f"⚠️ Warning from {ctx.guild.name}",
                description=f"**Reason:** {reason}",
                color=discord.Color.orange(),
            )
            await member.send(embed=dm_embed)
        except discord.Forbidden:
            pass

        embed = discord.Embed(
            title="⚠️ Warning Issued",
            description=(
                f"**{member}** has been warned.\n\n"
                f"**Reason:** {reason}\n"
                f"**By:** {ctx.author.mention}"
            ),
            color=discord.Color.orange(),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        await ctx.send(embed=embed)
        await self._log_to_channel(ctx.guild, embed)
        logger.info(f"Warning issued to {member} in {ctx.guild.name} by {ctx.author}: {reason}")

    # ══════════════════════════════════════════════════════════════
    #  !warnings [@user]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="warnings",
        aliases=["warns", "warn-list"],
        help="View warning history for a user.",
        usage="<@user>",
    )
    @is_staff()
    async def warnings(self, ctx: commands.Context, member: discord.Member) -> None:
        """Fetch all WARN entries from audit_logs for a user."""
        pool = self.bot.db.pool
        rows = await pool.fetch(
            """SELECT actor_id, details, created_at FROM audit_logs
               WHERE guild_id = $1 AND target_id = $2 AND action_type = 'WARN'
               ORDER BY created_at DESC LIMIT 20""",
            ctx.guild.id, member.id,
        )

        if not rows:
            embed = discord.Embed(
                title=f"📋 Warnings — {member}",
                description="No warnings on record.",
                color=discord.Color.green(),
            )
            await ctx.send(embed=embed)
            return

        lines = []
        for i, row in enumerate(rows, 1):
            details = row["details"] if isinstance(row["details"], dict) else {}
            reason = details.get("reason", "N/A")
            ts = discord.utils.format_dt(row["created_at"], style="R")
            warner = ctx.guild.get_member(row["actor_id"])
            warner_str = str(warner) if warner else f"`{row['actor_id']}`"
            lines.append(f"**{i}.** {reason}\n   — by {warner_str} {ts}")

        embed = discord.Embed(
            title=f"⚠️ Warnings — {member} ({len(rows)} total)",
            description="\n\n".join(lines),
            color=discord.Color.orange(),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  Unified Error Handler
    # ══════════════════════════════════════════════════════════════

    @temp_ban.error
    @temp_mute.error
    @purge.error
    @purge_user.error
    @lockdown.error
    @unlockdown.error
    @panic_mode.error
    @slowmode_all.error
    @quarantine.error
    @unquarantine.error
    @warn.error
    @warnings.error
    async def moderation_error(
        self, ctx: commands.Context, error: commands.CommandError
    ) -> None:
        """Unified error handler for all moderation commands."""

        if isinstance(error, NotStaff):
            embed = discord.Embed(
                title="🔒 Access Denied",
                description=error.message,
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed, delete_after=10)
            return

        if isinstance(error, commands.MissingRequiredArgument):
            embed = discord.Embed(
                title="❌ Missing Argument",
                description=(
                    f"You forgot the **`{error.param.name}`** argument.\n\n"
                    f"**Usage:** `{ctx.prefix}{ctx.command.qualified_name} {ctx.command.usage or ''}`"
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        if isinstance(error, commands.BadArgument):
            embed = discord.Embed(
                title="❌ Invalid Argument",
                description=(
                    f"Could not find the specified user or the argument is invalid.\n\n"
                    f"**Usage:** `{ctx.prefix}{ctx.command.qualified_name} {ctx.command.usage or ''}`"
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        if isinstance(error, commands.MemberNotFound):
            embed = discord.Embed(
                title="❌ Member Not Found",
                description="Could not find that member in this server.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # Unexpected error
        logger.error(
            f"Unhandled error in {ctx.command.qualified_name}: {error}",
            exc_info=error,
        )
        embed = discord.Embed(
            title="⚠️ Unexpected Error",
            description="Something went wrong. The error has been logged.",
            color=discord.Color.dark_red(),
        )
        await ctx.send(embed=embed)


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Moderation(bot))

