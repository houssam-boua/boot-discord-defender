# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Anti-Nuke System (Internal Protection)
#  Blueprint reference: Module 3 + Section 8b "Hybrid Anti-Nuke"
#
#  Monitors Discord Audit Logs + real-time events to detect
#  rogue or compromised admins performing destructive actions.
#
#  Detection vectors:
#    • Anti-Mass Ban     — on_member_ban
#    • Anti-Mass Kick    — on_member_remove (audit log: kick)
#    • Anti-Channel Del  — on_guild_channel_delete
#    • Anti-Role Del     — on_guild_role_delete
#    • Anti-Bot Add      — on_member_join (member.bot)
#
#  Redis key format: nuke:{action}:{guild_id}:{actor_id}
#  Threshold: 3 actions in 10 seconds → strip all roles from actor
#
#  All triggers logged via hash-chained insert_audit_log.
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import asyncio
import logging
from datetime import datetime, timezone

from security.audit_integrity import insert_audit_log

logger = logging.getLogger("antiraid.antinuke")

# ── Detection Thresholds ──────────────────────────────────────
NUKE_THRESHOLD = 3        # Actions before triggering response
NUKE_WINDOW_SECONDS = 10  # Time window for action counting


class AntiNuke(commands.Cog, name="🛡️ Anti-Nuke"):
    """
    Internal protection system — detects and neutralizes rogue admins
    performing mass-destructive actions (bans, kicks, channel/role deletes).
    Uses hybrid detection: real-time events + audit log attribution.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        # H-1 fix: cache antinuke_enabled per guild to avoid DB hit on every event
        self._enabled_cache: dict[int, bool] = {}

    # ══════════════════════════════════════════════════════════════
    #  Helper: Check if antinuke is enabled for this guild
    # ══════════════════════════════════════════════════════════════

    async def _is_enabled(self, guild_id: int) -> bool:
        """Check antinuke_enabled flag from server_configs (cached)."""
        # H-1 fix: check in-memory cache first
        if guild_id in self._enabled_cache:
            return self._enabled_cache[guild_id]

        if not self.bot.db.pool:
            return False

        row = await self.bot.db.pool.fetchrow(
            "SELECT antinuke_enabled FROM server_configs WHERE guild_id = $1",
            guild_id,
        )
        # Default to True if no config row exists
        result = row["antinuke_enabled"] if row else True
        self._enabled_cache[guild_id] = result
        return result

    def invalidate_cache(self, guild_id: int) -> None:
        """Clear the cached enabled flag so the next check re-queries DB."""
        self._enabled_cache.pop(guild_id, None)

    # ══════════════════════════════════════════════════════════════
    #  Helper: Get log channel
    # ══════════════════════════════════════════════════════════════

    async def _get_log_channel(
        self, guild: discord.Guild
    ) -> discord.TextChannel | None:
        """Fetch the configured log channel for alert embeds."""
        if not self.bot.db.pool:
            return None

        row = await self.bot.db.pool.fetchrow(
            "SELECT log_channel_id FROM server_configs WHERE guild_id = $1",
            guild.id,
        )
        if not row or not row["log_channel_id"]:
            return None

        return guild.get_channel(row["log_channel_id"])

    # ══════════════════════════════════════════════════════════════
    #  Helper: Bypass check — skip if actor is bot, owner, or whitelisted
    # ══════════════════════════════════════════════════════════════

    async def _should_bypass(self, guild: discord.Guild, actor: discord.User) -> bool:
        """
        Returns True if the actor should be exempt from antinuke checks.
        Bypass rule: bot itself + guild owner + antinuke_whitelist entries.
        """
        if actor.id == self.bot.user.id:
            return True
        if actor.id == guild.owner_id:
            return True

        # H-2 fix: check antinuke_whitelist table
        if self.bot.db.pool:
            row = await self.bot.db.pool.fetchrow(
                """SELECT 1 FROM antinuke_whitelist
                   WHERE guild_id = $1 AND user_id = $2
                   LIMIT 1""",
                guild.id,
                actor.id,
            )
            if row:
                return True

        return False

    # ══════════════════════════════════════════════════════════════
    #  Core: Redis rate tracking + threshold check
    # ══════════════════════════════════════════════════════════════

    async def _track_and_check(
        self,
        guild: discord.Guild,
        actor: discord.User,
        action_type: str,
    ) -> bool:
        """
        Increment the Redis counter for this actor's action and check
        if the nuke threshold has been reached.

        Redis key format: nuke:{action}:{guild_id}:{actor_id}

        Args:
            guild:       The Discord guild.
            actor:       The user who performed the action.
            action_type: Short action label (ban, kick, channel_delete, role_delete).

        Returns:
            True if the threshold was reached or exceeded (nuke detected).
        """
        if not self.bot.redis:
            return False

        key = f"nuke:{action_type}:{guild.id}:{actor.id}"
        count = await self.bot.redis.incr(key)
        if count == 1:
            await self.bot.redis.expire(key, NUKE_WINDOW_SECONDS)

        if count >= NUKE_THRESHOLD:
            # C-3 fix: Redis NX lock prevents parallel events from ALL
            # triggering _mitigate_nuke simultaneously (rate limit protection)
            lock_key = f"nuke:mitigate:lock:{guild.id}:{actor.id}"
            acquired = await self.bot.redis.set(lock_key, "1", nx=True, ex=30)
            return bool(acquired)

        return False

    # ══════════════════════════════════════════════════════════════
    #  Core: Mitigation Response — strip all roles from rogue actor
    # ══════════════════════════════════════════════════════════════

    async def _mitigate_nuke(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        action_type: str,
        details: dict,
    ) -> None:
        """
        Neutralize a rogue admin by stripping all their roles.
        Logs the incident to the database and sends a critical alert.

        Args:
            guild:       The target guild.
            actor:       The rogue admin to quarantine.
            action_type: The type of nuke detected (e.g., "ban", "channel_delete").
            details:     Additional context for the audit log.
        """
        logger.critical(
            f"🚨 NUKE DETECTED in {guild.name} ({guild.id}) — "
            f"Actor: {actor} ({actor.id}) — Action: {action_type}"
        )

        # ── Strip all roles from the rogue actor ──────────────
        roles_removed = []
        member = guild.get_member(actor.id)
        if not member:
            try:
                member = await guild.fetch_member(actor.id)
            except (discord.NotFound, discord.HTTPException):
                member = None

        if member:
            # Collect removable roles (can't remove @everyone or roles above bot)
            removable_roles = [
                r for r in member.roles
                if r != guild.default_role
                and r < guild.me.top_role
                and r.is_assignable()
            ]

            if removable_roles:
                roles_removed = [r.name for r in removable_roles]
                try:
                    await member.remove_roles(
                        *removable_roles,
                        reason=f"[AntiRaid] NUKE DETECTED — {action_type} threshold exceeded",
                    )
                    logger.info(
                        f"✅ Stripped {len(removable_roles)} roles from {actor} ({actor.id})"
                    )
                except discord.Forbidden:
                    logger.warning(
                        f"⚠️ Cannot strip roles from {actor} — missing permissions"
                    )
                except discord.HTTPException as e:
                    logger.error(f"❌ Role strip failed: {e}")

        # ── Log to audit_logs (ALWAYS) ─────────────────────────
        if self.bot.db.pool:
            await insert_audit_log(
                pool=self.bot.db.pool,
                guild_id=guild.id,
                actor_id=actor.id,
                target_id=actor.id,
                action_type="ANTI_NUKE_TRIGGER",
                details={
                    "nuke_type": action_type,
                    "roles_removed": roles_removed,
                    "threshold": NUKE_THRESHOLD,
                    "window_seconds": NUKE_WINDOW_SECONDS,
                    **details,
                },
                severity="CRITICAL",
            )

        # ── Send critical alert to log channel ─────────────────
        log_channel = await self._get_log_channel(guild)
        if log_channel:
            embed = discord.Embed(
                title="🚨 NUKE DETECTED — Anti-Nuke Triggered",
                description=(
                    f"A rogue or compromised admin has been **quarantined**.\n\n"
                    f"**Actor:** {actor.mention} (`{actor.id}`)\n"
                    f"**Action:** `{action_type}` — **{NUKE_THRESHOLD}+** actions "
                    f"in **{NUKE_WINDOW_SECONDS}s**\n"
                    f"**Response:** All roles stripped immediately."
                ),
                color=discord.Color.dark_red(),
                timestamp=datetime.now(timezone.utc),
            )
            if roles_removed:
                roles_str = ", ".join(f"`{r}`" for r in roles_removed[:20])
                embed.add_field(
                    name="Roles Removed",
                    value=roles_str,
                    inline=False,
                )
            embed.set_thumbnail(url=actor.display_avatar.url)
            embed.set_footer(
                text="⚠️ Investigate immediately — this admin's permissions have been revoked."
            )

            try:
                await log_channel.send(
                    content="@here",  # Ping staff
                    embed=embed,
                )
            except Exception as e:
                logger.error(f"Failed to send nuke alert: {e}")

    # ══════════════════════════════════════════════════════════════
    #  LISTENER: on_member_ban — Anti-Mass Ban
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_ban(
        self, guild: discord.Guild, user: discord.User
    ) -> None:
        """Detect mass banning by a single admin."""
        if not await self._is_enabled(guild.id):
            return

        # Attribute the action via audit log
        actor = None
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.ban, limit=1
            ):
                actor = entry.user
                break
        except discord.Forbidden:
            logger.warning(f"Missing audit log permissions in {guild.name}")
            return

        if not actor:
            return
        if await self._should_bypass(guild, actor):
            return

        # Track in Redis and check threshold
        triggered = await self._track_and_check(guild, actor, "ban")
        if triggered:
            await self._mitigate_nuke(
                guild=guild,
                actor=actor,
                action_type="ban",
                details={"latest_target": str(user), "target_id": user.id},
            )

    # ══════════════════════════════════════════════════════════════
    #  LISTENER: on_member_remove — Anti-Mass Kick
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        """
        Detect mass kicking by a single admin.
        on_member_remove fires for both leaves and kicks.
        We check the audit log to distinguish kicks from voluntary leaves.
        """
        guild = member.guild

        if not await self._is_enabled(guild.id):
            return

        # Small delay to allow the audit log entry to appear
        # L-1 fix: increased from 0.5s to 1.5s — Discord API often
        # takes ~1s to populate kick audit entries
        await asyncio.sleep(1.5)

        # Check audit log for a recent kick action targeting this member
        actor = None
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.kick, limit=5
            ):
                # Match the target and ensure it was recent (within 5 seconds)
                if entry.target and entry.target.id == member.id:
                    time_diff = (
                        datetime.now(timezone.utc) - entry.created_at
                    ).total_seconds()
                    if time_diff < 5:
                        actor = entry.user
                    break
        except discord.Forbidden:
            return

        # No kick found — member left voluntarily
        if not actor:
            return
        if await self._should_bypass(guild, actor):
            return

        # Track in Redis and check threshold
        triggered = await self._track_and_check(guild, actor, "kick")
        if triggered:
            await self._mitigate_nuke(
                guild=guild,
                actor=actor,
                action_type="kick",
                details={"latest_target": str(member), "target_id": member.id},
            )

    # ══════════════════════════════════════════════════════════════
    #  LISTENER: on_guild_channel_delete — Anti-Channel Nuke
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_guild_channel_delete(
        self, channel: discord.abc.GuildChannel
    ) -> None:
        """
        Detect mass channel deletion by a single admin.
        Blueprint Section 8b: exact pattern from "Hybrid Anti-Nuke Detection".
        """
        guild = channel.guild

        if not await self._is_enabled(guild.id):
            return

        # Attribute via audit log (blueprint-exact pattern)
        actor = None
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.channel_delete, limit=1
            ):
                actor = entry.user
                break
        except discord.Forbidden:
            return

        if not actor:
            return
        if await self._should_bypass(guild, actor):
            return

        # Track in Redis and check threshold
        triggered = await self._track_and_check(guild, actor, "channel_delete")
        if triggered:
            await self._mitigate_nuke(
                guild=guild,
                actor=actor,
                action_type="channel_delete",
                details={
                    "latest_channel": channel.name,
                    "channel_type": str(channel.type),
                },
            )

    # ══════════════════════════════════════════════════════════════
    #  LISTENER: on_guild_role_delete — Anti-Role Nuke
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_guild_role_delete(self, role: discord.Role) -> None:
        """Detect mass role deletion by a single admin."""
        guild = role.guild

        if not await self._is_enabled(guild.id):
            return

        # Attribute via audit log
        actor = None
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.role_delete, limit=1
            ):
                actor = entry.user
                break
        except discord.Forbidden:
            return

        if not actor:
            return
        if await self._should_bypass(guild, actor):
            return

        # Track in Redis and check threshold
        triggered = await self._track_and_check(guild, actor, "role_delete")
        if triggered:
            await self._mitigate_nuke(
                guild=guild,
                actor=actor,
                action_type="role_delete",
                details={
                    "latest_role": role.name,
                    "role_color": str(role.color),
                    "role_position": role.position,
                },
            )

    # ══════════════════════════════════════════════════════════════
    #  LISTENER: on_member_join — Anti-Bot Add
    #  "Any non-Owner admin inviting a new bot → bot kicked,
    #   inviter quarantined, log ANTI_BOT_INVITE."
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        """
        Detect unauthorized bot additions.
        If a bot is added by someone who is NOT the guild owner,
        immediately kick the bot and quarantine the inviter.
        """
        # Only care about bots joining
        if not member.bot:
            return

        guild = member.guild

        if not await self._is_enabled(guild.id):
            return

        # Don't block the AntiRaid bot itself
        if member.id == self.bot.user.id:
            return

        # Small delay for audit log to populate
        await asyncio.sleep(1)

        # Find who invited the bot via audit log
        inviter = None
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.bot_add, limit=5
            ):
                if entry.target and entry.target.id == member.id:
                    inviter = entry.user
                    break
        except discord.Forbidden:
            logger.warning(
                f"Missing audit log perms in {guild.name} — "
                f"cannot verify bot add for {member}"
            )
            return

        if not inviter:
            return

        # Guild owner is allowed to add bots
        if inviter.id == guild.owner_id:
            return

        logger.warning(
            f"🤖 Unauthorized bot add in {guild.name}: "
            f"{member} added by {inviter} ({inviter.id}) — NOT the owner"
        )

        # ── Kick the unauthorized bot ──────────────────────────
        try:
            await member.kick(
                reason=f"[AntiRaid] Unauthorized bot add by {inviter} (not owner)"
            )
            logger.info(f"✅ Kicked unauthorized bot: {member} ({member.id})")
        except discord.Forbidden:
            logger.warning(f"Cannot kick bot {member} — missing permissions")
        except discord.HTTPException as e:
            logger.error(f"Failed to kick bot: {e}")

        # ── Quarantine the inviter — strip all roles ───────────
        inviter_member = guild.get_member(inviter.id)
        if not inviter_member:
            try:
                inviter_member = await guild.fetch_member(inviter.id)
            except (discord.NotFound, discord.HTTPException):
                inviter_member = None

        roles_removed = []
        if inviter_member:
            removable_roles = [
                r for r in inviter_member.roles
                if r != guild.default_role
                and r < guild.me.top_role
                and r.is_assignable()
            ]
            if removable_roles:
                roles_removed = [r.name for r in removable_roles]
                try:
                    await inviter_member.remove_roles(
                        *removable_roles,
                        reason="[AntiRaid] Unauthorized bot invite — permissions revoked",
                    )
                except discord.Forbidden:
                    logger.warning(f"Cannot strip roles from {inviter}")
                except discord.HTTPException as e:
                    logger.error(f"Role strip failed: {e}")

        # ── Log to audit_logs (ALWAYS) ─────────────────────────
        if self.bot.db.pool:
            await insert_audit_log(
                pool=self.bot.db.pool,
                guild_id=guild.id,
                actor_id=inviter.id,
                target_id=member.id,
                action_type="ANTI_BOT_INVITE",
                details={
                    "bot_name": str(member),
                    "bot_id": member.id,
                    "inviter": str(inviter),
                    "inviter_id": inviter.id,
                    "roles_removed": roles_removed,
                },
                severity="CRITICAL",
            )

        # ── Send critical alert ────────────────────────────────
        log_channel = await self._get_log_channel(guild)
        if log_channel:
            embed = discord.Embed(
                title="🤖 Unauthorized Bot Blocked",
                description=(
                    f"A bot was added by a **non-owner** admin and has been kicked.\n\n"
                    f"**Bot:** {member} (`{member.id}`)\n"
                    f"**Added By:** {inviter.mention} (`{inviter.id}`)\n"
                    f"**Response:** Bot kicked + inviter's roles stripped."
                ),
                color=discord.Color.dark_red(),
                timestamp=datetime.now(timezone.utc),
            )
            if roles_removed:
                embed.add_field(
                    name="Inviter Roles Removed",
                    value=", ".join(f"`{r}`" for r in roles_removed[:20]),
                    inline=False,
                )
            embed.set_thumbnail(url=member.display_avatar.url)
            embed.set_footer(
                text="⚠️ This admin's permissions have been revoked pending review."
            )

            try:
                await log_channel.send(content="@here", embed=embed)
            except Exception as e:
                logger.error(f"Failed to send bot-add alert: {e}")


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AntiNuke(bot))
