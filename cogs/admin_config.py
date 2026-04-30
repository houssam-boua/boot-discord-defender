# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Admin Configuration Cog
#  Prefix commands for server-specific bot configuration.
#
#  Commands:
#    !set-prefix [new_prefix]        — Change the bot command prefix
#    !set-log-channel [#channel]     — Set the audit/alert log channel
#    !set-raid-limit [joins] [secs]  — Set auto-lockdown thresholds
#
#  All commands require Administrator permission (via @is_staff()).
#  Settings persist in the `server_configs` PostgreSQL table.
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

from utils.permissions import is_staff, NotStaff

import logging

logger = logging.getLogger("antiraid.config")


class AdminConfig(commands.Cog, name="⚙️ Configuration"):
    """Server configuration commands — Admin only."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ── Helper: Ensure a server_configs row exists ─────────────
    async def _ensure_guild_config(self, guild_id: int) -> None:
        """
        Insert a default config row for this guild if one doesn't exist.
        Uses ON CONFLICT DO NOTHING so it's safe to call on every command.
        """
        await self.bot.db.pool.execute(
            """
            INSERT INTO server_configs (guild_id)
            VALUES ($1)
            ON CONFLICT (guild_id) DO NOTHING
            """,
            guild_id,
        )

    # ══════════════════════════════════════════════════════════════
    #  !set-prefix [new_prefix]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="set-prefix",
        aliases=["setprefix", "prefix"],
        help="Change the bot command prefix for this server.",
        usage="<new_prefix>",
    )
    @is_staff()
    async def set_prefix(self, ctx: commands.Context, new_prefix: str) -> None:
        """
        Update the command prefix for this server.

        Args:
            new_prefix: The new prefix string (1-5 characters).
        """
        # ── Validation ─────────────────────────────────────────
        if len(new_prefix) > 5:
            embed = discord.Embed(
                title="❌ Invalid Prefix",
                description="Prefix must be **5 characters or fewer**.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        if new_prefix.startswith("`") or "\n" in new_prefix:
            embed = discord.Embed(
                title="❌ Invalid Prefix",
                description="Prefix cannot contain backticks or newlines.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Persist to database ────────────────────────────────
        await self._ensure_guild_config(ctx.guild.id)

        await self.bot.db.pool.execute(
            """
            UPDATE server_configs
            SET prefix = $1
            WHERE guild_id = $2
            """,
            new_prefix,
            ctx.guild.id,
        )

        # ── Update in-memory cache ─────────────────────────────
        self.bot.prefix_cache[ctx.guild.id] = new_prefix

        # ── Confirmation ───────────────────────────────────────
        embed = discord.Embed(
            title="✅ Prefix Updated",
            description=(
                f"Command prefix changed to: **`{new_prefix}`**\n\n"
                f"Example: `{new_prefix}help`"
            ),
            color=discord.Color.green(),
        )
        embed.set_footer(text=f"Changed by {ctx.author}", icon_url=ctx.author.display_avatar.url)
        await ctx.send(embed=embed)

        logger.info(
            f"Prefix changed to '{new_prefix}' in guild {ctx.guild.name} "
            f"({ctx.guild.id}) by {ctx.author} ({ctx.author.id})"
        )

    # ══════════════════════════════════════════════════════════════
    #  !set-log-channel [#channel]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="set-log-channel",
        aliases=["setlogchannel", "logchannel"],
        help="Set the channel where the bot sends security alerts and audit logs.",
        usage="<#channel>",
    )
    @is_staff()
    async def set_log_channel(
        self, ctx: commands.Context, channel: discord.TextChannel
    ) -> None:
        """
        Designate a text channel for all bot alerts, audit logs, and security reports.

        Args:
            channel: A text channel mention (e.g., #security-logs).
        """
        # ── Verify bot can send messages in the target channel ──
        bot_perms = channel.permissions_for(ctx.guild.me)
        if not bot_perms.send_messages or not bot_perms.embed_links:
            embed = discord.Embed(
                title="❌ Missing Permissions",
                description=(
                    f"I need **Send Messages** and **Embed Links** permissions "
                    f"in {channel.mention} to use it as the log channel."
                ),
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Persist to database ────────────────────────────────
        await self._ensure_guild_config(ctx.guild.id)

        await self.bot.db.pool.execute(
            """
            UPDATE server_configs
            SET log_channel_id = $1
            WHERE guild_id = $2
            """,
            channel.id,
            ctx.guild.id,
        )

        # ── Confirmation ───────────────────────────────────────
        embed = discord.Embed(
            title="✅ Log Channel Set",
            description=(
                f"Security alerts and audit logs will be sent to: {channel.mention}"
            ),
            color=discord.Color.green(),
        )
        embed.set_footer(text=f"Changed by {ctx.author}", icon_url=ctx.author.display_avatar.url)
        await ctx.send(embed=embed)

        # Also send a test message to the log channel
        test_embed = discord.Embed(
            title="🛡️ AntiRaid — Log Channel Active",
            description=(
                "This channel has been configured as the **security log channel**.\n"
                "All bot alerts, audit events, and security reports will appear here."
            ),
            color=discord.Color.blurple(),
        )
        test_embed.set_footer(text=f"Configured by {ctx.author}")
        await channel.send(embed=test_embed)

        logger.info(
            f"Log channel set to #{channel.name} ({channel.id}) in guild "
            f"{ctx.guild.name} ({ctx.guild.id}) by {ctx.author} ({ctx.author.id})"
        )

    # ══════════════════════════════════════════════════════════════
    #  !set-raid-limit [joins] [seconds]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="set-raid-limit",
        aliases=["setraidlimit", "raidlimit"],
        help="Set the join-spike threshold that triggers Auto-Lockdown.",
        usage="<max_joins> <time_window_seconds>",
    )
    @is_staff()
    async def set_raid_limit(
        self, ctx: commands.Context, joins: int, seconds: int
    ) -> None:
        """
        Configure the auto-lockdown trigger thresholds.
        If more than `joins` members join within `seconds`, the server locks down.

        Args:
            joins: Maximum number of joins before lockdown triggers.
            seconds: Time window in seconds to track joins.
        """
        # ── Validation ─────────────────────────────────────────
        if joins < 2:
            embed = discord.Embed(
                title="❌ Invalid Value",
                description="Join limit must be **at least 2** to avoid false lockdowns.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        if seconds < 1 or seconds > 300:
            embed = discord.Embed(
                title="❌ Invalid Value",
                description="Time window must be between **1** and **300** seconds.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Persist to database ────────────────────────────────
        await self._ensure_guild_config(ctx.guild.id)

        await self.bot.db.pool.execute(
            """
            UPDATE server_configs
            SET raid_limit_count = $1,
                raid_limit_seconds = $2
            WHERE guild_id = $3
            """,
            joins,
            seconds,
            ctx.guild.id,
        )

        # ── Confirmation ───────────────────────────────────────
        embed = discord.Embed(
            title="✅ Raid Limit Updated",
            description=(
                f"**Auto-Lockdown** will trigger if **{joins} members** "
                f"join within **{seconds} second{'s' if seconds != 1 else ''}**."
            ),
            color=discord.Color.green(),
        )
        embed.add_field(
            name="📊 Threshold",
            value=f"`{joins}` joins / `{seconds}s` window",
            inline=True,
        )
        embed.set_footer(text=f"Changed by {ctx.author}", icon_url=ctx.author.display_avatar.url)
        await ctx.send(embed=embed)

        logger.info(
            f"Raid limit set to {joins} joins / {seconds}s in guild "
            f"{ctx.guild.name} ({ctx.guild.id}) by {ctx.author} ({ctx.author.id})"
        )

    # ══════════════════════════════════════════════════════════════
    #  !set-quarantine-role [@role]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="set-quarantine-role",
        aliases=["setquarantinerole"],
        help="Set the role assigned to quarantined members.",
        usage="<@role>",
    )
    @is_staff()
    async def set_quarantine_role(
        self, ctx: commands.Context, role: discord.Role
    ) -> None:
        """Designate the quarantine role for suspected users."""
        await self._ensure_guild_config(ctx.guild.id)
        await self.bot.db.pool.execute(
            "UPDATE server_configs SET quarantine_role_id = $1 WHERE guild_id = $2",
            role.id, ctx.guild.id,
        )

        embed = discord.Embed(
            title="✅ Quarantine Role Set",
            description=f"Quarantine role set to: {role.mention}",
            color=discord.Color.green(),
        )
        embed.set_footer(text=f"Changed by {ctx.author}", icon_url=ctx.author.display_avatar.url)
        await ctx.send(embed=embed)
        logger.info(f"Quarantine role set to {role.name} in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !set-account-age [hours]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="set-account-age",
        aliases=["setaccountage", "minage"],
        help="Set minimum account age (in hours) to join without flagging.",
        usage="<hours>",
    )
    @is_staff()
    async def set_account_age(self, ctx: commands.Context, hours: int) -> None:
        """Set the minimum account age required to bypass alt-detection."""
        if hours < 0 or hours > 8760:
            embed = discord.Embed(
                title="❌ Invalid Value",
                description="Hours must be between **0** and **8760** (1 year).",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        await self._ensure_guild_config(ctx.guild.id)
        await self.bot.db.pool.execute(
            "UPDATE server_configs SET min_account_age_hours = $1 WHERE guild_id = $2",
            hours, ctx.guild.id,
        )

        embed = discord.Embed(
            title="✅ Account Age Updated",
            description=f"Minimum account age set to **{hours} hours**.",
            color=discord.Color.green(),
        )
        embed.set_footer(text=f"Changed by {ctx.author}", icon_url=ctx.author.display_avatar.url)
        await ctx.send(embed=embed)
        logger.info(f"Min account age set to {hours}h in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !toggle [module] [on/off]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="toggle",
        help="Toggle a security module on or off.",
        usage="<captcha|proxycheck|antinuke|antispam> <on|off>",
    )
    @is_staff()
    async def toggle(self, ctx: commands.Context, module: str, state: str) -> None:
        """Enable or disable a security module."""
        module = module.lower()
        state = state.lower()

        column_map = {
            "captcha": "captcha_enabled",
            "proxycheck": "proxycheck_enabled",
            "antinuke": "antinuke_enabled",
            "antispam": "antispam_enabled",
        }

        if module not in column_map:
            embed = discord.Embed(
                title="❌ Unknown Module",
                description=(
                    f"Valid modules: `captcha`, `proxycheck`, `antinuke`, `antispam`."
                ),
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        if state not in ("on", "off", "true", "false", "1", "0"):
            embed = discord.Embed(
                title="❌ Invalid State",
                description="State must be **on** or **off**.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        enabled = state in ("on", "true", "1")
        column = column_map[module]

        await self._ensure_guild_config(ctx.guild.id)
        await self.bot.db.pool.execute(
            f"UPDATE server_configs SET {column} = $1 WHERE guild_id = $2",
            enabled, ctx.guild.id,
        )

        status = "✅ Enabled" if enabled else "❌ Disabled"
        embed = discord.Embed(
            title=f"⚙️ Module Toggled",
            description=f"**{module.title()}** has been **{status.split(' ')[1].lower()}**.",
            color=discord.Color.green() if enabled else discord.Color.orange(),
        )
        embed.set_footer(text=f"Changed by {ctx.author}", icon_url=ctx.author.display_avatar.url)
        await ctx.send(embed=embed)
        logger.info(f"Toggle {module}={enabled} in {ctx.guild.name} by {ctx.author}")

    # ══════════════════════════════════════════════════════════════
    #  !whitelist add/remove/list
    # ══════════════════════════════════════════════════════════════

    @commands.group(
        name="whitelist",
        aliases=["wl"],
        help="Manage spam filter exemptions (roles/channels).",
        invoke_without_command=True,
    )
    @is_staff()
    async def whitelist(self, ctx: commands.Context) -> None:
        """Show whitelist help if no subcommand given."""
        embed = discord.Embed(
            title="🛡️ Whitelist Management",
            description=(
                f"`{ctx.prefix}whitelist add <@role / #channel>` — Add exemption\n"
                f"`{ctx.prefix}whitelist remove <@role / #channel>` — Remove exemption\n"
                f"`{ctx.prefix}whitelist list` — View all exemptions"
            ),
            color=discord.Color.blurple(),
        )
        await ctx.send(embed=embed)

    @whitelist.command(name="add", help="Exempt a role or channel from spam filters.")
    @is_staff()
    async def whitelist_add(
        self, ctx: commands.Context,
        entity: discord.Role | discord.TextChannel,
    ) -> None:
        """Add a role or channel to the whitelist."""
        pool = self.bot.db.pool
        entity_type = "role" if isinstance(entity, discord.Role) else "channel"

        try:
            await pool.execute(
                """INSERT INTO whitelists (guild_id, entity_id, entity_type, added_by)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (guild_id, entity_id, entity_type) DO NOTHING""",
                ctx.guild.id, entity.id, entity_type, ctx.author.id,
            )
        except Exception as e:
            await ctx.send(f"❌ Database error: `{e}`")
            return

        embed = discord.Embed(
            title="✅ Whitelist Updated",
            description=f"**{entity.mention}** ({entity_type}) is now exempt from spam filters.",
            color=discord.Color.green(),
        )
        await ctx.send(embed=embed)
        logger.info(f"Whitelist add: {entity_type} {entity.name} in {ctx.guild.name}")

    @whitelist.command(name="remove", help="Remove a role or channel exemption.")
    @is_staff()
    async def whitelist_remove(
        self, ctx: commands.Context,
        entity: discord.Role | discord.TextChannel,
    ) -> None:
        """Remove a role or channel from the whitelist."""
        pool = self.bot.db.pool
        entity_type = "role" if isinstance(entity, discord.Role) else "channel"

        result = await pool.execute(
            """DELETE FROM whitelists
               WHERE guild_id = $1 AND entity_id = $2 AND entity_type = $3""",
            ctx.guild.id, entity.id, entity_type,
        )
        rows = int(result.split()[-1])

        if rows == 0:
            embed = discord.Embed(
                title="❌ Not Found",
                description=f"{entity.mention} is not in the whitelist.",
                color=discord.Color.orange(),
            )
        else:
            embed = discord.Embed(
                title="✅ Whitelist Updated",
                description=f"**{entity.mention}** has been removed from the whitelist.",
                color=discord.Color.green(),
            )
        await ctx.send(embed=embed)

    @whitelist.command(name="list", help="View all current exemptions.")
    @is_staff()
    async def whitelist_list(self, ctx: commands.Context) -> None:
        """Display all whitelisted roles and channels."""
        pool = self.bot.db.pool
        rows = await pool.fetch(
            "SELECT entity_id, entity_type FROM whitelists WHERE guild_id = $1 ORDER BY entity_type",
            ctx.guild.id,
        )

        if not rows:
            embed = discord.Embed(
                title="🛡️ Whitelist",
                description="No exemptions configured.",
                color=discord.Color.light_grey(),
            )
            await ctx.send(embed=embed)
            return

        lines = []
        for row in rows:
            etype = row["entity_type"]
            eid = row["entity_id"]
            if etype == "role":
                role = ctx.guild.get_role(eid)
                lines.append(f"🔹 **Role:** {role.mention if role else f'`{eid}` (deleted)'}")
            elif etype == "channel":
                ch = ctx.guild.get_channel(eid)
                lines.append(f"🔸 **Channel:** {ch.mention if ch else f'`{eid}` (deleted)'}")
            else:
                lines.append(f"👤 **User:** `{eid}`")

        embed = discord.Embed(
            title=f"🛡️ Whitelist — {len(rows)} Exemptions",
            description="\n".join(lines),
            color=discord.Color.blurple(),
        )
        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  Error Handler — clean responses for permission denials
    #  and missing/invalid arguments
    # ══════════════════════════════════════════════════════════════

    @set_prefix.error
    @set_log_channel.error
    @set_raid_limit.error
    @set_quarantine_role.error
    @set_account_age.error
    @toggle.error
    async def config_command_error(
        self, ctx: commands.Context, error: commands.CommandError
    ) -> None:
        """Unified error handler for all config commands."""

        # ── Permission denied ──────────────────────────────────
        if isinstance(error, NotStaff):
            embed = discord.Embed(
                title="🔒 Access Denied",
                description=error.message,
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed, delete_after=10)
            return

        # ── Missing required argument ──────────────────────────
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

        # ── Bad argument type (e.g., text instead of number) ───
        if isinstance(error, commands.BadArgument):
            embed = discord.Embed(
                title="❌ Invalid Argument",
                description=(
                    f"One of the arguments you provided is invalid.\n\n"
                    f"**Usage:** `{ctx.prefix}{ctx.command.qualified_name} {ctx.command.usage or ''}`"
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        # ── Unexpected error — log it ──────────────────────────
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
    await bot.add_cog(AdminConfig(bot))

