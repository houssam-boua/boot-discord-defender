# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Audit Logging Cog
#  Listens to Discord events and records them in the audit_logs
#  table using the tamper-proof hash chain from audit_integrity.py.
#
#  Blueprint reference: Module 5 — Tamper-Proof Auditing
#
#  Events logged:
#    • Message deleted (+ Ghost Ping detection)
#    • Message edited
#    • Member join
#    • Member leave (remove)
#    • Member banned
#    • Member unbanned
#
#  All events are ALWAYS written to the database.
#  Embed notifications are sent to the log channel only if configured.
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import logging
from datetime import datetime, timezone

from security.audit_integrity import insert_audit_log

logger = logging.getLogger("antiraid.logging")


class AuditLogging(commands.Cog, name="📋 Audit Logging"):
    """
    Passive event listener — records all guild events to the
    tamper-proof audit_logs database table and sends formatted
    embeds to the server's configured log channel.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ══════════════════════════════════════════════════════════════
    #  Helper: Get log channel for a guild
    # ══════════════════════════════════════════════════════════════

    async def _get_log_channel(
        self, guild: discord.Guild
    ) -> discord.TextChannel | None:
        """
        Fetch the configured log channel for a guild.
        Returns None if not configured or channel doesn't exist.
        """
        if not self.bot.db.pool:
            return None

        row = await self.bot.db.pool.fetchrow(
            "SELECT log_channel_id FROM server_configs WHERE guild_id = $1",
            guild.id,
        )
        if not row or not row["log_channel_id"]:
            return None

        return guild.get_channel(row["log_channel_id"])

    async def _send_log_embed(
        self, guild: discord.Guild, embed: discord.Embed
    ) -> None:
        """Send an embed to the log channel. Silently skips if not configured."""
        channel = await self._get_log_channel(guild)
        if channel:
            try:
                await channel.send(embed=embed)
            except discord.Forbidden:
                logger.warning(
                    f"Cannot send to log channel in {guild.name} — missing permissions"
                )
            except Exception as e:
                logger.error(f"Log channel send error: {e}")

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_message_delete — Ghost Ping Tracker + Deletion Log
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_message_delete(self, message: discord.Message) -> None:
        """
        Fires when a message is deleted.
        If the deleted message contained mentions → GHOST_PING.
        Otherwise → MESSAGE_DELETE.
        """
        # Skip bot messages and DMs
        if not message.guild:
            return
        if message.author.bot:
            return

        pool = self.bot.db.pool
        if not pool:
            return

        content_preview = (message.content[:200] + "...") if len(message.content) > 200 else message.content

        # ── Ghost Ping Detection ───────────────────────────────
        # A ghost ping is when someone mentions a user/role and then
        # deletes the message before the target can see it.
        mentioned_users = [u for u in message.mentions if not u.bot]
        mentioned_roles = list(message.role_mentions)

        if mentioned_users or mentioned_roles:
            # This is a ghost ping
            mentioned_names = (
                [f"@{u}" for u in mentioned_users]
                + [f"@{r.name}" for r in mentioned_roles]
            )

            details = {
                "channel_id": message.channel.id,
                "channel_name": message.channel.name,
                "content": content_preview,
                "mentioned_users": [u.id for u in mentioned_users],
                "mentioned_roles": [r.id for r in mentioned_roles],
            }

            # ALWAYS write to database
            await insert_audit_log(
                pool=pool,
                guild_id=message.guild.id,
                actor_id=message.author.id,
                target_id=mentioned_users[0].id if mentioned_users else None,
                action_type="GHOST_PING",
                details=details,
                severity="WARN",
            )

            # Send embed to log channel (if configured)
            embed = discord.Embed(
                title="👻 Ghost Ping Detected",
                description=(
                    f"**{message.author.mention}** deleted a message that "
                    f"mentioned: {', '.join(mentioned_names)}"
                ),
                color=discord.Color.purple(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.add_field(
                name="Channel",
                value=message.channel.mention,
                inline=True,
            )
            embed.add_field(
                name="Mentions",
                value=", ".join(mentioned_names),
                inline=True,
            )
            if content_preview:
                embed.add_field(
                    name="Message Content",
                    value=f"```{content_preview}```",
                    inline=False,
                )
            embed.set_thumbnail(url=message.author.display_avatar.url)
            embed.set_footer(text=f"User ID: {message.author.id}")

            await self._send_log_embed(message.guild, embed)

            logger.info(
                f"👻 Ghost ping by {message.author} ({message.author.id}) "
                f"in #{message.channel.name} — mentioned: {mentioned_names}"
            )
            return

        # ── Standard Message Deletion ──────────────────────────
        details = {
            "channel_id": message.channel.id,
            "channel_name": message.channel.name,
            "content": content_preview,
        }

        await insert_audit_log(
            pool=pool,
            guild_id=message.guild.id,
            actor_id=message.author.id,
            target_id=None,
            action_type="MESSAGE_DELETE",
            details=details,
        )

        embed = discord.Embed(
            title="🗑️ Message Deleted",
            description=f"A message by **{message.author}** was deleted in {message.channel.mention}.",
            color=discord.Color.light_grey(),
            timestamp=datetime.now(timezone.utc),
        )
        if content_preview:
            embed.add_field(
                name="Content",
                value=f"```{content_preview}```",
                inline=False,
            )
        embed.set_thumbnail(url=message.author.display_avatar.url)
        embed.set_footer(text=f"Author ID: {message.author.id}")

        await self._send_log_embed(message.guild, embed)

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_message_edit
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_message_edit(
        self, before: discord.Message, after: discord.Message
    ) -> None:
        """Fires when a message is edited."""
        if not after.guild:
            return
        if after.author.bot:
            return

        # Skip if content didn't actually change (embed loading, etc.)
        if before.content == after.content:
            return

        pool = self.bot.db.pool
        if not pool:
            return

        before_preview = (before.content[:150] + "...") if len(before.content) > 150 else before.content
        after_preview = (after.content[:150] + "...") if len(after.content) > 150 else after.content

        details = {
            "channel_id": after.channel.id,
            "channel_name": after.channel.name,
            "before": before_preview,
            "after": after_preview,
            "message_id": after.id,
        }

        await insert_audit_log(
            pool=pool,
            guild_id=after.guild.id,
            actor_id=after.author.id,
            target_id=None,
            action_type="MESSAGE_EDIT",
            details=details,
        )

        embed = discord.Embed(
            title="✏️ Message Edited",
            description=f"**{after.author}** edited a message in {after.channel.mention}.",
            color=discord.Color.gold(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(
            name="Before",
            value=f"```{before_preview}```" if before_preview else "*Empty*",
            inline=False,
        )
        embed.add_field(
            name="After",
            value=f"```{after_preview}```" if after_preview else "*Empty*",
            inline=False,
        )
        embed.add_field(
            name="Jump to Message",
            value=f"[Click here]({after.jump_url})",
            inline=True,
        )
        embed.set_thumbnail(url=after.author.display_avatar.url)
        embed.set_footer(text=f"Author ID: {after.author.id}")

        await self._send_log_embed(after.guild, embed)

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_member_join
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        """Fires when a member joins the guild."""
        pool = self.bot.db.pool
        if not pool:
            return

        # Calculate account age
        account_age = datetime.now(timezone.utc) - member.created_at
        age_days = account_age.days
        age_str = f"{age_days} day{'s' if age_days != 1 else ''}"

        # Flag new accounts (< 7 days old)
        is_new_account = age_days < 7
        severity = "WARN" if is_new_account else "INFO"

        details = {
            "account_created": str(member.created_at),
            "account_age_days": age_days,
            "is_new_account": is_new_account,
            "has_avatar": member.avatar is not None,
            "member_count": member.guild.member_count,
        }

        await insert_audit_log(
            pool=pool,
            guild_id=member.guild.id,
            actor_id=None,
            target_id=member.id,
            action_type="MEMBER_JOIN",
            details=details,
            severity=severity,
        )

        embed = discord.Embed(
            title="📥 Member Joined",
            description=f"{member.mention} joined the server.",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(name="Account Age", value=age_str, inline=True)
        embed.add_field(
            name="Member #",
            value=str(member.guild.member_count),
            inline=True,
        )
        if is_new_account:
            embed.add_field(
                name="⚠️ New Account",
                value=f"Created only **{age_str}** ago",
                inline=False,
            )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.set_footer(text=f"User ID: {member.id}")

        await self._send_log_embed(member.guild, embed)

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_member_remove (leave / kick)
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_remove(self, member: discord.Member) -> None:
        """Fires when a member leaves or is kicked from the guild."""
        pool = self.bot.db.pool
        if not pool:
            return

        # Collect the roles the member had (for potential restore)
        role_names = [r.name for r in member.roles if r.name != "@everyone"]

        details = {
            "roles": role_names,
            "joined_at": str(member.joined_at) if member.joined_at else None,
            "member_count": member.guild.member_count,
        }

        await insert_audit_log(
            pool=pool,
            guild_id=member.guild.id,
            actor_id=None,
            target_id=member.id,
            action_type="MEMBER_LEAVE",
            details=details,
        )

        embed = discord.Embed(
            title="📤 Member Left",
            description=f"**{member}** left the server.",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc),
        )
        if role_names:
            embed.add_field(
                name="Roles",
                value=", ".join(f"`{r}`" for r in role_names[:15]),
                inline=False,
            )
        embed.add_field(
            name="Members Now",
            value=str(member.guild.member_count),
            inline=True,
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.set_footer(text=f"User ID: {member.id}")

        await self._send_log_embed(member.guild, embed)

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_member_ban
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_ban(
        self, guild: discord.Guild, user: discord.User
    ) -> None:
        """Fires when a member is banned from the guild."""
        pool = self.bot.db.pool
        if not pool:
            return

        # Try to find who banned them via the audit log
        banner_id = None
        reason = "Unknown"
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.ban, limit=5
            ):
                if entry.target and entry.target.id == user.id:
                    banner_id = entry.user.id if entry.user else None
                    reason = entry.reason or "No reason provided"
                    break
        except discord.Forbidden:
            pass

        details = {
            "reason": reason,
            "banned_by": banner_id,
        }

        await insert_audit_log(
            pool=pool,
            guild_id=guild.id,
            actor_id=banner_id,
            target_id=user.id,
            action_type="BAN",
            details=details,
            severity="WARN",
        )

        embed = discord.Embed(
            title="🔨 Member Banned",
            description=f"**{user}** was banned from the server.",
            color=discord.Color.dark_red(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        if banner_id:
            banner = guild.get_member(banner_id)
            if banner:
                embed.add_field(
                    name="Banned By",
                    value=banner.mention,
                    inline=True,
                )
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.set_footer(text=f"User ID: {user.id}")

        await self._send_log_embed(guild, embed)

        logger.info(
            f"🔨 Ban logged: {user} ({user.id}) in {guild.name} — {reason}"
        )

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_member_unban
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_unban(
        self, guild: discord.Guild, user: discord.User
    ) -> None:
        """Fires when a member is unbanned from the guild."""
        pool = self.bot.db.pool
        if not pool:
            return

        # Try to find who unbanned them via the audit log
        unbanner_id = None
        reason = "Unknown"
        try:
            async for entry in guild.audit_logs(
                action=discord.AuditLogAction.unban, limit=5
            ):
                if entry.target and entry.target.id == user.id:
                    unbanner_id = entry.user.id if entry.user else None
                    reason = entry.reason or "No reason provided"
                    break
        except discord.Forbidden:
            pass

        details = {
            "reason": reason,
            "unbanned_by": unbanner_id,
        }

        await insert_audit_log(
            pool=pool,
            guild_id=guild.id,
            actor_id=unbanner_id,
            target_id=user.id,
            action_type="UNBAN",
            details=details,
        )

        embed = discord.Embed(
            title="🔓 Member Unbanned",
            description=f"**{user}** has been unbanned.",
            color=discord.Color.teal(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(name="Reason", value=reason, inline=False)
        if unbanner_id:
            unbanner = guild.get_member(unbanner_id)
            if unbanner:
                embed.add_field(
                    name="Unbanned By",
                    value=unbanner.mention,
                    inline=True,
                )
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.set_footer(text=f"User ID: {user.id}")

        await self._send_log_embed(guild, embed)

        logger.info(
            f"🔓 Unban logged: {user} ({user.id}) in {guild.name}"
        )

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_member_update — Role Assigned / Removed
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_update(
        self, before: discord.Member, after: discord.Member
    ) -> None:
        """Log role changes (added/removed) for members."""
        if before.roles == after.roles:
            return  # No role change

        guild = after.guild
        pool = self.bot.db.pool
        if not pool:
            return

        before_roles = set(before.roles)
        after_roles = set(after.roles)

        added = after_roles - before_roles
        removed = before_roles - after_roles

        if not added and not removed:
            return

        # Build details
        details = {}
        if added:
            details["roles_added"] = [r.name for r in added]
        if removed:
            details["roles_removed"] = [r.name for r in removed]

        action = "ROLE_CHANGE"
        description_parts = []

        if added:
            description_parts.append(
                f"**Added:** {', '.join(r.mention for r in added)}"
            )
        if removed:
            description_parts.append(
                f"**Removed:** {', '.join(r.mention for r in removed)}"
            )

        await insert_audit_log(
            pool=pool,
            guild_id=guild.id,
            actor_id=None,
            target_id=after.id,
            action_type=action,
            details=details,
        )

        embed = discord.Embed(
            title="🏷️ Role Updated",
            description=(
                f"**Member:** {after.mention}\n"
                + "\n".join(description_parts)
            ),
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_thumbnail(url=after.display_avatar.url)
        embed.set_footer(text=f"User ID: {after.id}")

        await self._send_log_embed(guild, embed)

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_guild_channel_create / on_guild_channel_delete
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_guild_channel_create(self, channel: discord.abc.GuildChannel) -> None:
        """Log channel creation."""
        guild = channel.guild
        pool = self.bot.db.pool
        if not pool:
            return

        await insert_audit_log(
            pool=pool,
            guild_id=guild.id,
            actor_id=None,
            target_id=channel.id,
            action_type="CHANNEL_CREATE",
            details={"channel_name": channel.name, "type": str(channel.type)},
        )

        embed = discord.Embed(
            title="📁 Channel Created",
            description=f"**#{channel.name}** ({channel.type})",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text=f"Channel ID: {channel.id}")
        await self._send_log_embed(guild, embed)

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: discord.abc.GuildChannel) -> None:
        """Log channel deletion (separate from anti-nuke; this is pure audit logging)."""
        guild = channel.guild
        pool = self.bot.db.pool
        if not pool:
            return

        await insert_audit_log(
            pool=pool,
            guild_id=guild.id,
            actor_id=None,
            target_id=channel.id,
            action_type="CHANNEL_DELETE",
            details={"channel_name": channel.name, "type": str(channel.type)},
        )

        embed = discord.Embed(
            title="🗑️ Channel Deleted",
            description=f"**#{channel.name}** ({channel.type})",
            color=discord.Color.dark_red(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text=f"Channel ID: {channel.id}")
        await self._send_log_embed(guild, embed)

    # ══════════════════════════════════════════════════════════════
    #  EVENT: on_command — Log all bot commands executed
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_command(self, ctx: commands.Context) -> None:
        """Log every bot command invocation to the audit trail."""
        if not ctx.guild:
            return

        pool = self.bot.db.pool
        if not pool:
            return

        await insert_audit_log(
            pool=pool,
            guild_id=ctx.guild.id,
            actor_id=ctx.author.id,
            target_id=None,
            action_type="COMMAND_EXEC",
            details={
                "command": ctx.command.qualified_name if ctx.command else str(ctx.invoked_with),
                "args": ctx.message.content[:200],
                "channel": ctx.channel.name,
            },
        )


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AuditLogging(bot))

