# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Appeal System
#  Allows users to appeal automated punishments via DM.
#
#  Flow:
#    1. Punishment issued → bot DMs user with !appeal instructions
#    2. User replies !appeal <text> in DMs within 24h
#    3. Appeal embed posted to log channel with Approve/Deny buttons
#    4a. Approved → punishment lifted + user notified
#    4b. Denied   → punishment stays + user notified
#    5. APScheduler expires pending appeals older than 48h
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands
from datetime import datetime, timezone
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler

logger = logging.getLogger("antiraid.appeals")

async def send_appeal_dm(
    user: discord.User | discord.Member,
    guild_name: str,
    punishment_type: str,
    reason: str,
) -> bool:
    """
    DM the user after a punishment is issued.
    Returns True if DM delivered, False if DMs are closed.
    NEVER raises — silent fail always.
    """
    try:
        msg = (
            f"⚠️ You were **{punishment_type}** in **{guild_name}**.\n"
            f"**Reason:** {reason}\n\n"
            f"If you believe this was a mistake, you can appeal within **24 hours**.\n"
            f"Reply to this message with:\n"
            f"```\n!appeal <your explanation>\n```"
        )
        await user.send(msg)
        return True
    except discord.Forbidden:
        logger.debug(f"Cannot DM {user} ({user.id}) — DMs closed")
        return False
    except Exception as e:
        logger.warning(f"Failed to DM {user} ({user.id}): {e}")
        return False

class AppealsView(discord.ui.View):
    """
    Persistent Approve/Deny buttons on appeal embeds.
    Buttons are disabled after the first mod interaction.
    Timeout=None — persists until explicitly disabled.
    """

    def __init__(self, appeal_id: int, bot: commands.Bot) -> None:
        super().__init__(timeout=None)
        self.appeal_id = appeal_id
        self.bot = bot

    @discord.ui.button(
        label="✅ Approve",
        style=discord.ButtonStyle.success,
        custom_id="appeal_approve",
    )
    async def approve(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        await self._handle_decision(interaction, approved=True)

    @discord.ui.button(
        label="❌ Deny",
        style=discord.ButtonStyle.danger,
        custom_id="appeal_deny",
    )
    async def deny(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ) -> None:
        await self._handle_decision(interaction, approved=False)

    async def _handle_decision(
        self,
        interaction: discord.Interaction,
        approved: bool,
    ) -> None:
        """Shared logic for both buttons."""
        # Fetch appeal from DB
        row = await self.bot.db.pool.fetchrow(
            "SELECT * FROM appeals WHERE id = $1", self.appeal_id
        )
        if not row:
            await interaction.response.send_message(
                "❌ Appeal not found.", ephemeral=True
            )
            return

        if row["status"] != "pending":
            await interaction.response.send_message(
                f"⚠️ This appeal is already **{row['status']}**.", ephemeral=True
            )
            return

        new_status = "approved" if approved else "denied"

        # Update DB
        await self.bot.db.pool.execute(
            """
            UPDATE appeals
            SET status = $1, reviewed_by = $2, reviewed_at = NOW()
            WHERE id = $3
            """,
            new_status,
            interaction.user.id,
            self.appeal_id,
        )

        # Disable buttons
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(view=self)

        guild = interaction.guild
        user_id = row["user_id"]

        if approved:
            await self._lift_punishment(
                interaction, guild, user_id, row["punishment_type"]
            )

        # DM the user the decision
        user = self.bot.get_user(user_id)
        if user:
            dm_msg = (
                f"✅ Your appeal in **{guild.name}** was **approved**. "
                f"Your punishment has been lifted."
                if approved
                else
                f"❌ Your appeal in **{guild.name}** was **reviewed and denied**. "
                f"Your punishment remains in place."
            )
            try:
                await user.send(dm_msg)
            except discord.Forbidden:
                pass

        logger.info(
            f"Appeal #{self.appeal_id} {new_status} by "
            f"{interaction.user} ({interaction.user.id})"
        )

        await interaction.followup.send(
            f"{'✅ Appeal approved' if approved else '❌ Appeal denied'} — "
            f"<@{user_id}> has been notified.",
            ephemeral=True,
        )

    async def _lift_punishment(
        self,
        interaction: discord.Interaction,
        guild: discord.Guild,
        user_id: int,
        punishment_type: str,
    ) -> None:
        """Lift the actual Discord punishment based on type."""
        try:
            if punishment_type == "mute":
                member = guild.get_member(user_id)
                if not member:
                    member = await guild.fetch_member(user_id)
                if member:
                    await member.timeout(None, reason="[AntiRaid] Appeal approved")

            elif punishment_type == "ban":
                await guild.unban(
                    discord.Object(id=user_id),
                    reason="[AntiRaid] Appeal approved",
                )

            elif punishment_type == "role_strip":
                # Re-use the existing restore logic via recovery cog
                row = await self.bot.db.pool.fetchrow(
                    """
                    SELECT stripped_role_ids, stripped_role_names
                    FROM admin_role_strips
                    WHERE guild_id = $1 AND user_id = $2
                    ORDER BY stripped_at DESC LIMIT 1
                    """,
                    guild.id,
                    user_id,
                )
                if row:
                    member = guild.get_member(user_id)
                    if member:
                        roles = [
                            r for rid in row["stripped_role_ids"]
                            if (r := guild.get_role(rid))
                        ]
                        if roles:
                            await member.add_roles(
                                *roles,
                                reason="[AntiRaid] Appeal approved — restoring stripped roles",
                                atomic=False,
                            )

        except discord.Forbidden:
            logger.warning(
                f"Cannot lift {punishment_type} for {user_id} — missing permissions"
            )
        except discord.NotFound:
            logger.info(f"User {user_id} not found in guild — already left")
        except Exception as e:
            logger.error(f"Failed to lift {punishment_type} for {user_id}: {e}")


class Appeals(commands.Cog, name="⚖️ Appeals"):
    """
    Appeal system for automated punishments.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._scheduler: AsyncIOScheduler | None = None

    async def cog_load(self) -> None:
        """Start the appeal expiry scheduler."""
        from services.punishment_scheduler import scheduler as shared_scheduler
        shared_scheduler.add_job(
            self._expire_old_appeals,
            trigger="interval",
            seconds=1800,   # every 30 minutes
            id="expire_appeals",
            replace_existing=True,
            args=[],
        )
        logger.info("✅ Appeals expiry job registered (interval: 30min)")

    async def cog_unload(self) -> None:
        """Remove the scheduler job cleanly."""
        from services.punishment_scheduler import scheduler as shared_scheduler
        try:
            shared_scheduler.remove_job("expire_appeals")
        except Exception:
            pass

    # ── Expiry job ─────────────────────────────────────────────────

    async def _expire_old_appeals(self) -> None:
        """
        APScheduler job: close pending appeals older than 48 hours.
        Runs every 30 minutes alongside _lift_expired_punishments.
        """
        if not self.bot.db.pool:
            return
        try:
            rows = await self.bot.db.pool.fetch(
                """
                UPDATE appeals
                SET status = 'expired'
                WHERE status = 'pending'
                  AND expires_at <= NOW()
                RETURNING id, user_id, guild_id, punishment_type
                """
            )
            for row in rows:
                logger.info(
                    f"⏰ Appeal #{row['id']} expired for user {row['user_id']}"
                )
                user = self.bot.get_user(row["user_id"])
                if user:
                    try:
                        await user.send(
                            f"⏰ Your appeal was not reviewed within 48 hours "
                            f"and has **expired**. Please contact a moderator directly."
                        )
                    except discord.Forbidden:
                        pass
        except Exception as e:
            logger.error(f"Appeal expiry job failed: {e}")

    # ── on_message listener — DM appeal submission ─────────────────

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        """
        Listen for !appeal <text> sent in DMs.
        Ignores all guild messages and bot messages.
        """
        # DMs only, no bots
        if message.guild is not None:
            return
        if message.author.bot:
            return

        content = message.content.strip()
        if not content.lower().startswith("!appeal"):
            return

        appeal_text = content[len("!appeal"):].strip()
        if not appeal_text:
            await message.channel.send(
                "❌ Please include your explanation. Example:\n"
                "```\n!appeal I didn't post that link\n```"
            )
            return

        await self._process_appeal(message.author, appeal_text)

    async def _process_appeal(
        self, user: discord.User, appeal_text: str
    ) -> None:
        """Validate and save an appeal from a DM."""
        if not self.bot.db.pool:
            await user.send(
                "❌ Appeal system is temporarily unavailable. "
                "Please contact a moderator directly."
            )
            return

        # Check: does this user have a recent pending punishment?
        # Look for a punishment issued within the last 24h
        punishment_row = await self.bot.db.pool.fetchrow(
            """
            SELECT guild_id, punishment_type, reason
            FROM temporal_punishments
            WHERE user_id = $1
              AND active = TRUE
              AND issued_at >= NOW() - INTERVAL '24 hours'
            ORDER BY issued_at DESC
            LIMIT 1
            """,
            user.id,
        )

        # Also check nuke bans (stored in audit_logs, not temporal_punishments)
        if not punishment_row:
            punishment_row = await self.bot.db.pool.fetchrow(
                """
                SELECT guild_id,
                       'ban' AS punishment_type,
                       details->>'nuke_type' AS reason
                FROM audit_logs
                WHERE actor_id = $1
                  AND action_type = 'ANTI_NUKE_TRIGGER'
                  AND created_at >= NOW() - INTERVAL '24 hours'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                user.id,
            )

        if not punishment_row:
            await user.send(
                "❌ No recent punishment found for your account within the last 24 hours. "
                "If you believe this is an error, contact a moderator directly."
            )
            return

        guild_id         = punishment_row["guild_id"]
        punishment_type  = punishment_row["punishment_type"] or "unknown"
        punishment_reason = punishment_row["reason"] or "No reason recorded"

        # Check: already appealed this punishment?
        existing = await self.bot.db.pool.fetchrow(
            """
            SELECT id, status FROM appeals
            WHERE guild_id = $1
              AND user_id  = $2
              AND status   IN ('pending', 'approved', 'denied')
              AND created_at >= NOW() - INTERVAL '24 hours'
            """,
            guild_id,
            user.id,
        )
        if existing:
            await user.send(
                f"⚠️ You already have a **{existing['status']}** appeal. "
                f"You cannot submit multiple appeals for the same punishment."
            )
            return

        # Save appeal to DB
        appeal_id = await self.bot.db.pool.fetchval(
            """
            INSERT INTO appeals
                (guild_id, user_id, punishment_type, punishment_reason,
                 appeal_text, status, created_at)
            VALUES ($1, $2, $3, $4, $5, 'pending', NOW())
            RETURNING id
            """,
            guild_id,
            user.id,
            punishment_type,
            punishment_reason,
            appeal_text,
        )

        # Post to log channel
        await self._post_appeal_embed(
            guild_id, user, punishment_type, punishment_reason,
            appeal_text, appeal_id
        )

        await user.send(
            "✅ Your appeal has been submitted and will be reviewed by a moderator.\n"
            "You will be notified of the decision within 48 hours."
        )
        logger.info(
            f"📥 Appeal #{appeal_id} submitted by {user} ({user.id}) "
            f"in guild {guild_id} — type: {punishment_type}"
        )

    async def _post_appeal_embed(
        self,
        guild_id: int,
        user: discord.User,
        punishment_type: str,
        punishment_reason: str,
        appeal_text: str,
        appeal_id: int,
    ) -> None:
        """Post the appeal embed with Approve/Deny buttons to the log channel."""
        guild = self.bot.get_guild(guild_id)
        if not guild:
            return

        row = await self.bot.db.pool.fetchrow(
            "SELECT log_channel_id FROM server_configs WHERE guild_id = $1",
            guild_id,
        )
        if not row or not row["log_channel_id"]:
            return

        log_channel = guild.get_channel(row["log_channel_id"])
        if not log_channel:
            return

        embed = discord.Embed(
            title="⚖️ New Appeal — Pending Review",
            color=discord.Color.orange(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.add_field(
            name="User",
            value=f"<@{user.id}> (`{user.id}`)",
            inline=True,
        )
        embed.add_field(
            name="Punishment",
            value=f"`{punishment_type}`",
            inline=True,
        )
        embed.add_field(
            name="Original Reason",
            value=punishment_reason,
            inline=False,
        )
        embed.add_field(
            name="Appeal Text",
            value=appeal_text[:1000],   # Discord field limit
            inline=False,
        )
        embed.set_thumbnail(url=user.display_avatar.url)
        embed.set_footer(text=f"Appeal #{appeal_id} — Expires in 48h")

        view = AppealsView(appeal_id=appeal_id, bot=self.bot)

        try:
            await log_channel.send(embed=embed, view=view)
        except Exception as e:
            logger.error(f"Failed to post appeal #{appeal_id} to log channel: {e}")

    # ── !appeals list command ───────────────────────────────────────

    @commands.command(
        name="appeals",
        aliases=["appeal-list", "pending-appeals"],
        help="List all pending appeals for this server.",
    )
    @commands.has_permissions(manage_guild=True)
    async def appeals_list(self, ctx: commands.Context) -> None:
        """Show all pending appeals."""
        rows = await self.bot.db.pool.fetch(
            """
            SELECT id, user_id, punishment_type, created_at, expires_at
            FROM appeals
            WHERE guild_id = $1 AND status = 'pending'
            ORDER BY created_at ASC
            """,
            ctx.guild.id,
        )

        if not rows:
            await ctx.send("✅ No pending appeals.")
            return

        lines = [f"**{len(rows)} pending appeal(s):**\n"]
        for r in rows:
            created = r["created_at"].strftime("%Y-%m-%d %H:%M UTC")
            expires = r["expires_at"].strftime("%Y-%m-%d %H:%M UTC")
            lines.append(
                f"• **#{r['id']}** — <@{r['user_id']}> "
                f"(`{r['punishment_type']}`) | submitted {created} | "
                f"expires {expires}"
            )

        await ctx.send("\n".join(lines)[:2000])


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Appeals(bot))
