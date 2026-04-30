# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Verification Cog
#  Blueprint reference: Module 1 — Gatekeeping & Verification
#
#  on_member_join flow:
#    1. Alt-Account Check → kick if too young or default avatar
#    2. CAPTCHA Flow (if enabled):
#       a. Restrict user (no roles granted yet)
#       b. DM the CAPTCHA image
#       c. If DMs closed → fallback to #verify-here / system channel
#       d. wait_for reply (5 min timeout, 3 attempts)
#       e. Success → grant access | Fail → kick
#
#  All events logged to audit_logs via insert_audit_log.
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import asyncio
import logging
from datetime import datetime, timezone

from security.audit_integrity import insert_audit_log
from services.captcha import generate_captcha
from services.proxycheck import check_ip, is_suspicious_ip

logger = logging.getLogger("antiraid.verification")

# ── Defaults ──────────────────────────────────────────────────
DEFAULT_MIN_ACCOUNT_AGE_HOURS = 24
CAPTCHA_TIMEOUT_SECONDS = 300   # 5 minutes
CAPTCHA_MAX_ATTEMPTS = 3


class Verification(commands.Cog, name="🔑 Verification"):
    """
    Gatekeeping & verification system.
    Listens to on_member_join and enforces alt-account detection
    and CAPTCHA challenges before granting server access.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ══════════════════════════════════════════════════════════════
    #  Helper: Fetch guild verification config from DB
    # ══════════════════════════════════════════════════════════════

    async def _get_config(self, guild_id: int) -> dict:
        """Fetch verification-related settings from server_configs."""
        config = {
            "captcha_enabled": True,
            "min_account_age_hours": DEFAULT_MIN_ACCOUNT_AGE_HOURS,
            "quarantine_role_id": None,
            "log_channel_id": None,
        }

        if not self.bot.db.pool:
            return config

        row = await self.bot.db.pool.fetchrow(
            """
            SELECT captcha_enabled, min_account_age_hours,
                   quarantine_role_id, log_channel_id
            FROM server_configs
            WHERE guild_id = $1
            """,
            guild_id,
        )
        if row:
            config["captcha_enabled"] = row["captcha_enabled"]
            config["min_account_age_hours"] = row["min_account_age_hours"]
            config["quarantine_role_id"] = row["quarantine_role_id"]
            config["log_channel_id"] = row["log_channel_id"]

        return config

    # ══════════════════════════════════════════════════════════════
    #  Helper: Send embed to log channel
    # ══════════════════════════════════════════════════════════════

    async def _send_log(
        self, guild: discord.Guild, embed: discord.Embed, config: dict
    ) -> None:
        """Send an embed to the log channel (if configured)."""
        if not config["log_channel_id"]:
            return

        channel = guild.get_channel(config["log_channel_id"])
        if channel:
            try:
                await channel.send(embed=embed)
            except Exception as e:
                logger.error(f"Failed to send verification log: {e}")

    # ══════════════════════════════════════════════════════════════
    #  Helper: Find a fallback channel for CAPTCHA when DMs are closed
    # ══════════════════════════════════════════════════════════════

    async def _find_verify_channel(
        self, guild: discord.Guild
    ) -> discord.TextChannel | None:
        """
        Try to find a #verify-here channel. Falls back to the system channel.
        Blueprint: "If DMs are closed → user is redirected to #verify-here."
        """
        # Look for a channel named "verify-here" or "verification"
        for channel in guild.text_channels:
            if channel.name in ("verify-here", "verification", "verify"):
                perms = channel.permissions_for(guild.me)
                if perms.send_messages:
                    return channel

        # Fall back to the system channel
        if guild.system_channel:
            perms = guild.system_channel.permissions_for(guild.me)
            if perms.send_messages:
                return guild.system_channel

        return None

    # ══════════════════════════════════════════════════════════════
    #  Main Listener: on_member_join
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_member_join(self, member: discord.Member) -> None:
        """
        Core verification flow triggered when a new member joins.
        Steps: Alt-Account Check → CAPTCHA (if enabled) → Grant Access.
        """
        # Ignore bots
        if member.bot:
            return

        guild = member.guild
        pool = self.bot.db.pool
        if not pool:
            return

        config = await self._get_config(guild.id)

        # ══════════════════════════════════════════════════════════
        #  STEP 1: Alt-Account Detection
        # ══════════════════════════════════════════════════════════

        account_age_hours = (
            datetime.now(timezone.utc) - member.created_at
        ).total_seconds() / 3600

        min_age = config["min_account_age_hours"]
        has_default_avatar = member.avatar is None

        # Check 1a: Account too young
        if account_age_hours < min_age:
            await self._kick_alt_account(
                member=member,
                reason=f"Account age ({account_age_hours:.1f}h) below minimum ({min_age}h)",
                config=config,
            )
            return

        # Check 1b: Default avatar (no custom profile picture)
        if has_default_avatar and account_age_hours < (min_age * 2):
            # Only flag default avatars on relatively new accounts
            # (don't kick established accounts just for no avatar)
            await self._kick_alt_account(
                member=member,
                reason=f"Default avatar + new account ({account_age_hours:.1f}h old)",
                config=config,
            )
            return

        # ══════════════════════════════════════════════════════════
        #  STEP 2: CAPTCHA Flow (if enabled)
        # ══════════════════════════════════════════════════════════

        # STEP 1.5: IP Reputation Hook (activated by web-gate integration)
        ip_address: str | None = None  # Populated by web-gate when available
        if await self._check_ip_reputation(member, ip_address, config):
            try:
                await member.kick(reason="[AntiRaid] VPN/Proxy/Tor detected")
            except discord.Forbidden:
                pass
            return

        if not config["captcha_enabled"]:
            # CAPTCHA disabled — log the join and let them through
            await insert_audit_log(
                pool=pool,
                guild_id=guild.id,
                actor_id=None,
                target_id=member.id,
                action_type="VERIFICATION_SKIP",
                details={
                    "reason": "captcha_disabled",
                    "account_age_hours": round(account_age_hours, 1),
                },
            )
            return

        # Prevent duplicate CAPTCHA sessions
        pool = self.bot.db.pool
        if pool:
            existing = await pool.fetchrow(
                """SELECT id, completed FROM captcha_challenges
                   WHERE guild_id = $1 AND user_id = $2""",
                guild.id, member.id,
            )
            if existing and not existing["completed"]:
                return  # Active session exists — no duplicate
        try:
            await self._run_captcha_flow(member, config)
        finally:
            if pool:
                try:
                    await pool.execute(
                        """DELETE FROM captcha_challenges
                           WHERE guild_id = $1 AND user_id = $2""",
                        guild.id, member.id,
                    )
                except Exception as e:
                    logger.error(f"Failed to clean CAPTCHA session: {e}")

    # ══════════════════════════════════════════════════════════════
    #  IP Reputation Hook
    # ══════════════════════════════════════════════════════════════

    async def _check_ip_reputation(
        self,
        member: discord.Member,
        ip_address: str | None,
        config: dict,
    ) -> bool:
        """
        IP reputation check via Proxycheck.io.
        ip_address is None in the pure Discord flow — Discord never exposes IPs.
        Wire a web-gate (OAuth2 callback page) to supply the real IP later.
        Returns True if suspicious (caller should kick). Fails open on error.
        """
        if not ip_address:
            return False
        api_key = getattr(self.bot.config, "PROXYCHECK_API_KEY", None)
        if not api_key:
            logger.warning("PROXYCHECK_API_KEY not set — skipping IP check")
            return False
        try:
            result = await check_ip(ip_address, api_key)
            suspicious = is_suspicious_ip(result)
            if suspicious:
                proxy_type = result.get(ip_address, {}).get("type", "unknown")
                pool = self.bot.db.pool
                if pool:
                    await insert_audit_log(
                        pool=pool,
                        guild_id=member.guild.id,
                        actor_id=self.bot.user.id,
                        target_id=member.id,
                        action_type="KICK_PROXY_IP",
                        details={
                            "ip": ip_address,
                            "proxy_type": proxy_type,
                            "risk_score": result.get(ip_address, {}).get("risk", 0),
                        },
                        severity="WARN",
                    )
            return suspicious
        except Exception as e:
            logger.error(f"Proxycheck error for {member}: {e}")
            return False  # Always fail open

    # ══════════════════════════════════════════════════════════════
    #  Alt-Account Kick
    # ══════════════════════════════════════════════════════════════

    async def _kick_alt_account(
        self,
        member: discord.Member,
        reason: str,
        config: dict,
    ) -> None:
        """Kick a suspected alt account and log the incident."""
        pool = self.bot.db.pool

        # Try to DM the user before kicking
        try:
            embed = discord.Embed(
                title="🚫 Access Denied",
                description=(
                    f"You have been kicked from **{member.guild.name}** "
                    f"because your account was flagged as a potential alt.\n\n"
                    f"**Reason:** {reason}\n\n"
                    f"If this is a mistake, please contact the server staff."
                ),
                color=discord.Color.red(),
            )
            await member.send(embed=embed)
        except discord.Forbidden:
            pass  # DMs closed

        # Execute the kick
        try:
            await member.kick(reason=f"[AntiRaid] Alt detection: {reason}")
        except discord.Forbidden:
            logger.warning(
                f"Cannot kick {member} ({member.id}) — missing permissions"
            )
            return

        # Log to audit_logs (ALWAYS)
        if pool:
            await insert_audit_log(
                pool=pool,
                guild_id=member.guild.id,
                actor_id=self.bot.user.id,
                target_id=member.id,
                action_type="ALT_KICK",
                details={
                    "reason": reason,
                    "account_age_hours": round(
                        (datetime.now(timezone.utc) - member.created_at).total_seconds() / 3600, 1
                    ),
                    "has_avatar": member.avatar is not None,
                },
                severity="WARN",
            )

        # Log to log channel (if configured)
        embed = discord.Embed(
            title="🚨 Alt Account Kicked",
            description=(
                f"**{member}** (`{member.id}`) was kicked on join.\n\n"
                f"**Reason:** {reason}"
            ),
            color=discord.Color.dark_red(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(
            name="Account Created",
            value=discord.utils.format_dt(member.created_at, style="R"),
            inline=True,
        )
        embed.add_field(
            name="Has Avatar",
            value="Yes" if member.avatar else "No",
            inline=True,
        )
        await self._send_log(member.guild, embed, config)

        logger.info(
            f"🚨 Alt kicked: {member} ({member.id}) from {member.guild.name} — {reason}"
        )

    # ══════════════════════════════════════════════════════════════
    #  CAPTCHA Flow
    # ══════════════════════════════════════════════════════════════

    async def _run_captcha_flow(
        self, member: discord.Member, config: dict
    ) -> None:
        """
        Execute the full CAPTCHA verification flow:
          1. Generate CAPTCHA image
          2. DM the challenge (fallback to #verify-here if DMs closed)
          3. Wait for correct response (3 attempts, 5 min timeout)
          4. Grant access on success / kick on failure
        """
        guild = member.guild
        pool = self.bot.db.pool

        # ── Generate the CAPTCHA ───────────────────────────────
        code, captcha_file = generate_captcha()

        pool = self.bot.db.pool
        if pool:
            try:
                await pool.execute(
                    """INSERT INTO captcha_challenges
                           (guild_id, user_id, answer, expires_at)
                       VALUES ($1, $2, $3, NOW() + $4::interval)
                       ON CONFLICT (guild_id, user_id)
                       DO UPDATE SET answer = EXCLUDED.answer,
                                     attempts = 0,
                                     expires_at = EXCLUDED.expires_at,
                                     completed = FALSE""",
                    guild.id, member.id, code,
                    f"{CAPTCHA_TIMEOUT_SECONDS} seconds",
                )
            except Exception as e:
                logger.error(f"Failed to persist CAPTCHA challenge: {e}")

        challenge_embed = discord.Embed(
            title="🔑 CAPTCHA Verification Required",
            description=(
                f"Welcome to **{guild.name}**!\n\n"
                f"To verify you're human, please type the text "
                f"shown in the image below.\n\n"
                f"• **Attempts:** {CAPTCHA_MAX_ATTEMPTS}\n"
                f"• **Time limit:** {CAPTCHA_TIMEOUT_SECONDS // 60} minutes\n"
                f"• The code is **case-insensitive**."
            ),
            color=discord.Color.blurple(),
        )
        challenge_embed.set_image(url="attachment://captcha_challenge.png")
        challenge_embed.set_footer(text=f"Server: {guild.name}")

        # ── Attempt DM delivery ────────────────────────────────
        dm_channel = None
        verify_channel = None
        dm_failed = False

        try:
            dm_channel = await member.create_dm()
            await dm_channel.send(embed=challenge_embed, file=captcha_file)
        except discord.Forbidden:
            dm_failed = True
            logger.info(
                f"📬 DMs closed for {member} ({member.id}) — using fallback channel"
            )

        # ── DM fallback: #verify-here or system channel ───────
        if dm_failed:
            verify_channel = await self._find_verify_channel(guild)

            if not verify_channel:
                logger.warning(
                    f"No verify channel found in {guild.name} — "
                    f"cannot deliver CAPTCHA to {member}"
                )
                # Log the failure but don't kick — guild needs to set up a channel
                if pool:
                    await insert_audit_log(
                        pool=pool,
                        guild_id=guild.id,
                        actor_id=self.bot.user.id,
                        target_id=member.id,
                        action_type="CAPTCHA_DELIVERY_FAIL",
                        details={
                            "reason": "DMs closed + no verify channel",
                        },
                        severity="WARN",
                    )
                return

            # Regenerate the file (previous one is consumed by the DM attempt)
            code, captcha_file = generate_captcha()

            fallback_embed = discord.Embed(
                title="🔑 CAPTCHA Verification Required",
                description=(
                    f"{member.mention}, I couldn't DM you! "
                    f"Please type the text shown in the image below "
                    f"to verify yourself.\n\n"
                    f"• **Attempts:** {CAPTCHA_MAX_ATTEMPTS}\n"
                    f"• **Time limit:** {CAPTCHA_TIMEOUT_SECONDS // 60} minutes\n"
                    f"• The code is **case-insensitive**."
                ),
                color=discord.Color.blurple(),
            )
            fallback_embed.set_image(url="attachment://captcha_challenge.png")

            await verify_channel.send(
                content=member.mention,
                embed=fallback_embed,
                file=captcha_file,
            )

        # ── Determine which channel to listen on ──────────────
        listen_channel = verify_channel if dm_failed else dm_channel

        # ── Wait for response (3 attempts) ─────────────────────
        def check(m: discord.Message) -> bool:
            """Check if the message is from the correct user in the correct channel."""
            if m.author.id != member.id:
                return False
            if dm_failed:
                return m.channel.id == verify_channel.id
            else:
                return isinstance(m.channel, discord.DMChannel)

        attempts = 0
        verified = False

        while attempts < CAPTCHA_MAX_ATTEMPTS:
            try:
                response = await self.bot.wait_for(
                    "message",
                    check=check,
                    timeout=CAPTCHA_TIMEOUT_SECONDS,
                )

                if response.content.strip().upper() == code.upper():
                    verified = True
                    if pool:
                        await pool.execute(
                            "UPDATE captcha_challenges SET completed = TRUE "
                            "WHERE guild_id = $1 AND user_id = $2",
                            guild.id, member.id,
                        )
                    break
                else:
                    attempts += 1
                    remaining = CAPTCHA_MAX_ATTEMPTS - attempts

                    if remaining > 0:
                        retry_embed = discord.Embed(
                            title="❌ Incorrect",
                            description=(
                                f"That wasn't right. You have "
                                f"**{remaining}** attempt{'s' if remaining != 1 else ''} left."
                            ),
                            color=discord.Color.orange(),
                        )
                        await (listen_channel).send(embed=retry_embed)

                    if pool:
                        await pool.execute(
                            "UPDATE captcha_challenges SET attempts = attempts + 1 "
                            "WHERE guild_id = $1 AND user_id = $2",
                            guild.id, member.id,
                        )

            except asyncio.TimeoutError:
                # Timed out — treat as failure
                break

        # ══════════════════════════════════════════════════════════
        #  RESULT: Success or Failure
        # ══════════════════════════════════════════════════════════

        if verified:
            await self._grant_access(member, config, listen_channel)
        else:
            await self._captcha_failed(member, config, listen_channel, attempts)

    # ══════════════════════════════════════════════════════════════
    #  CAPTCHA Success — Grant Access
    # ══════════════════════════════════════════════════════════════

    async def _grant_access(
        self,
        member: discord.Member,
        config: dict,
        channel,
    ) -> None:
        """
        Called when the user passes CAPTCHA verification.
        Assigns the verified role (if configured) and logs success.
        """
        guild = member.guild
        pool = self.bot.db.pool

        # ── Assign verified/member role ────────────────────────
        # If quarantine_role_id is set, we remove it (user was quarantined).
        # Otherwise, we could assign a "Verified" role if the guild has one.
        if config["quarantine_role_id"]:
            quarantine_role = guild.get_role(config["quarantine_role_id"])
            if quarantine_role and quarantine_role in member.roles:
                try:
                    await member.remove_roles(
                        quarantine_role,
                        reason="[AntiRaid] CAPTCHA verified — removing quarantine",
                    )
                except discord.Forbidden:
                    pass

        # ── Success notification ───────────────────────────────
        success_embed = discord.Embed(
            title="✅ Verification Complete!",
            description=(
                f"Welcome to **{guild.name}**! "
                f"You now have full access to the server."
            ),
            color=discord.Color.green(),
        )

        try:
            await channel.send(embed=success_embed)
        except Exception:
            pass

        # ── Log to database (ALWAYS) ───────────────────────────
        if pool:
            await insert_audit_log(
                pool=pool,
                guild_id=guild.id,
                actor_id=self.bot.user.id,
                target_id=member.id,
                action_type="CAPTCHA_PASS",
                details={
                    "account_age_hours": round(
                        (datetime.now(timezone.utc) - member.created_at).total_seconds() / 3600, 1
                    ),
                },
            )

        # ── Log to log channel ─────────────────────────────────
        log_embed = discord.Embed(
            title="✅ CAPTCHA Verified",
            description=f"**{member}** (`{member.id}`) passed verification.",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        log_embed.set_thumbnail(url=member.display_avatar.url)
        await self._send_log(guild, log_embed, config)

        logger.info(
            f"✅ CAPTCHA passed: {member} ({member.id}) in {guild.name}"
        )

    # ══════════════════════════════════════════════════════════════
    #  CAPTCHA Failure — Kick
    # ══════════════════════════════════════════════════════════════

    async def _captcha_failed(
        self,
        member: discord.Member,
        config: dict,
        channel,
        attempts: int,
    ) -> None:
        """
        Called when the user fails CAPTCHA (timeout or max attempts).
        Kicks the user and logs the failure.
        """
        guild = member.guild
        pool = self.bot.db.pool

        timed_out = attempts < CAPTCHA_MAX_ATTEMPTS
        reason = (
            f"CAPTCHA timed out after {CAPTCHA_TIMEOUT_SECONDS // 60} minutes"
            if timed_out
            else f"CAPTCHA failed after {CAPTCHA_MAX_ATTEMPTS} attempts"
        )

        # ── Notify the user ────────────────────────────────────
        fail_embed = discord.Embed(
            title="❌ Verification Failed",
            description=(
                f"You {'timed out' if timed_out else 'used all attempts'} "
                f"and will be removed from **{guild.name}**.\n\n"
                f"You can rejoin and try again."
            ),
            color=discord.Color.red(),
        )

        try:
            await channel.send(embed=fail_embed)
        except Exception:
            pass

        # ── Kick the user ──────────────────────────────────────
        try:
            await member.kick(reason=f"[AntiRaid] {reason}")
        except discord.Forbidden:
            logger.warning(
                f"Cannot kick {member} ({member.id}) — missing permissions"
            )

        # ── Log to database (ALWAYS) ───────────────────────────
        if pool:
            await insert_audit_log(
                pool=pool,
                guild_id=guild.id,
                actor_id=self.bot.user.id,
                target_id=member.id,
                action_type="CAPTCHA_FAIL",
                details={
                    "reason": reason,
                    "attempts_used": attempts,
                    "timed_out": timed_out,
                    "account_age_hours": round(
                        (datetime.now(timezone.utc) - member.created_at).total_seconds() / 3600, 1
                    ),
                },
                severity="WARN",
            )

        # ── Log to log channel ─────────────────────────────────
        log_embed = discord.Embed(
            title="❌ CAPTCHA Failed — User Kicked",
            description=(
                f"**{member}** (`{member.id}`) failed verification.\n\n"
                f"**Reason:** {reason}\n"
                f"**Attempts used:** {attempts}/{CAPTCHA_MAX_ATTEMPTS}"
            ),
            color=discord.Color.dark_red(),
            timestamp=datetime.now(timezone.utc),
        )
        log_embed.set_thumbnail(url=member.display_avatar.url)
        await self._send_log(guild, log_embed, config)

        logger.info(
            f"❌ CAPTCHA failed: {member} ({member.id}) in {guild.name} — {reason}"
        )


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Verification(bot))
