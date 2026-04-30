# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Anti-Spam & Anti-Flood Cog
#  Implements Module 2 from the blueprint:
#    • Zalgo text detection & removal
#    • Malicious link scanning (Layer 1 — in-memory cache)
#    • Mass mention detection
#    • Message velocity / flood detection (Redis rate limiter)
#
#  All thresholds are loaded from server_configs DB table per guild,
#  falling back to safe defaults if not configured.
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import logging
import time
from collections import deque, defaultdict
from datetime import timedelta
from utils.threat_data import ZALGO_RE

INVITE_RE = re.compile(
    r'(?:https?://)?(?:www\.)?discord(?:(?:app)?\.com/invite|\.gg(?:/invite)?)'
    r'/[\w-]{2,255}',
    re.IGNORECASE,
)
from utils.rate_limit import check_spam
from services.linkscanner import scan_message_urls

logger = logging.getLogger("antiraid.antispam")

# ── Default fallback values (from blueprint) ──────────────────
DEFAULT_MAX_MENTIONS = 5
DEFAULT_SPAM_MSG_LIMIT = 5
DEFAULT_SPAM_MSG_SECONDS = 2


class AntiSpam(commands.Cog, name="🛡️ Anti-Spam"):
    """
    Real-time message scanner for spam, phishing, Zalgo, and flood attacks.
    Listens to on_message and applies layered checks with auto-mute responses.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        # Per-guild config cache: {guild_id: {config_dict}}
        self._config_cache: dict[int, dict] = {}
        # H-4 fix: local sliding window fallback when Redis is unavailable
        self._local_spam_cache: dict[str, deque] = defaultdict(deque)

    # ══════════════════════════════════════════════════════════════
    #  Config Loader — fetches per-guild settings from DB
    # ══════════════════════════════════════════════════════════════

    async def _get_guild_config(self, guild_id: int) -> dict:
        """
        Fetch antispam configuration for a guild from the database.
        Caches the result in memory to avoid repeated DB queries.
        Falls back to defaults if no config row exists.
        """
        # Check memory cache first
        if guild_id in self._config_cache:
            return self._config_cache[guild_id]

        config = {
            "antispam_enabled": True,
            "max_mentions": DEFAULT_MAX_MENTIONS,
            "spam_msg_limit": DEFAULT_SPAM_MSG_LIMIT,
            "spam_msg_seconds": DEFAULT_SPAM_MSG_SECONDS,
            "allow_invites": False,
        }

        if self.bot.db.pool:
            row = await self.bot.db.pool.fetchrow(
                """
                SELECT antispam_enabled, max_mentions,
                       spam_msg_limit, spam_msg_seconds, allow_invites
                FROM server_configs
                WHERE guild_id = $1
                """,
                guild_id,
            )
            if row:
                config["antispam_enabled"] = row["antispam_enabled"]
                config["max_mentions"] = row["max_mentions"]
                config["spam_msg_limit"] = row["spam_msg_limit"]
                config["spam_msg_seconds"] = row["spam_msg_seconds"]
                config["allow_invites"] = row.get("allow_invites", False)

        self._config_cache[guild_id] = config
        return config

    def invalidate_config_cache(self, guild_id: int) -> None:
        """Called when an admin updates config to force a fresh DB read."""
        self._config_cache.pop(guild_id, None)

    # ══════════════════════════════════════════════════════════════
    #  Auto-Mute Helper
    # ══════════════════════════════════════════════════════════════

    async def _auto_mute(
        self,
        member: discord.Member,
        reason: str,
        duration_minutes: int = 10,
    ) -> bool:
        """
        Apply a timeout (mute) to a member using Discord's native timeout.

        Args:
            member: The guild member to mute.
            reason: The audit log reason for the mute.
            duration_minutes: How long the mute lasts (default 10 min).

        Returns:
            True if the mute was applied successfully.
        """
        try:
            await member.timeout(
                timedelta(minutes=duration_minutes),
                reason=f"[AntiRaid] {reason}",
            )
            logger.info(
                f"🔇 Auto-muted {member} ({member.id}) in {member.guild.name} "
                f"for {duration_minutes}min — Reason: {reason}"
            )
            return True
        except discord.Forbidden:
            logger.warning(
                f"⚠️ Cannot mute {member} ({member.id}) — missing permissions"
            )
            return False
        except Exception as e:
            logger.error(f"❌ Failed to mute {member}: {e}")
            return False

    # ══════════════════════════════════════════════════════════════
    #  Alert Helper — sends incident notification to log channel
    # ══════════════════════════════════════════════════════════════

    async def _send_alert(
        self,
        guild: discord.Guild,
        title: str,
        description: str,
        member: discord.Member,
        color: discord.Color = discord.Color.red(),
    ) -> None:
        """Send an embed alert to the configured log channel."""
        if not self.bot.db.pool:
            return

        row = await self.bot.db.pool.fetchrow(
            "SELECT log_channel_id FROM server_configs WHERE guild_id = $1",
            guild.id,
        )
        if not row or not row["log_channel_id"]:
            return

        log_channel = guild.get_channel(row["log_channel_id"])
        if not log_channel:
            return

        embed = discord.Embed(
            title=title,
            description=description,
            color=color,
        )
        embed.add_field(name="User", value=f"{member.mention} (`{member.id}`)", inline=True)
        embed.add_field(name="Channel", value=f"Auto-action", inline=True)
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.set_footer(text=f"Guild: {guild.name}")

        try:
            await log_channel.send(embed=embed)
        except Exception as e:
            logger.error(f"Failed to send alert to log channel: {e}")

    # ══════════════════════════════════════════════════════════════
    #  Whitelist Check — skip whitelisted roles/channels/users
    # ══════════════════════════════════════════════════════════════

    async def _is_whitelisted(self, message: discord.Message) -> bool:
        """
        Check if the message author, channel, or any of the author's roles
        is whitelisted in the database for this guild.
        """
        if not self.bot.db.pool:
            return False

        # Collect all entity IDs to check: user ID, channel ID, role IDs
        entity_ids = [message.author.id, message.channel.id]
        if isinstance(message.author, discord.Member):
            entity_ids.extend(role.id for role in message.author.roles)

        row = await self.bot.db.pool.fetchrow(
            """
            SELECT 1 FROM whitelists
            WHERE guild_id = $1 AND entity_id = ANY($2::BIGINT[])
            LIMIT 1
            """,
            message.guild.id,
            entity_ids,
        )
        return row is not None

    # ══════════════════════════════════════════════════════════════
    #  Main Listener — on_message
    # ══════════════════════════════════════════════════════════════

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        """
        Core message scanner. Runs layered checks in order:
          1. Zalgo text
          2. Malicious links
          3. Mass mentions
          4. Message velocity (flood)
        """
        # ── Skip conditions ────────────────────────────────────
        # Ignore bots, DMs, and system messages
        if message.author.bot:
            return
        if not message.guild:
            return
        if not message.content:
            return

        # Don't interfere with bot commands
        ctx = await self.bot.get_context(message)
        if ctx.valid:
            return

        member = message.author
        if not isinstance(member, discord.Member):
            return

        # Skip server owner and administrators
        if member.id == message.guild.owner_id:
            return
        if member.guild_permissions.administrator:
            return

        # ── Load guild config ──────────────────────────────────
        config = await self._get_guild_config(message.guild.id)

        if not config["antispam_enabled"]:
            return

        # ── Check whitelist ────────────────────────────────────
        if await self._is_whitelisted(message):
            return

        # ══════════════════════════════════════════════════════════
        #  CHECK 1: Zalgo Text Detection
        # ══════════════════════════════════════════════════════════
        if ZALGO_RE.search(message.content):
            try:
                await message.delete()
            except discord.Forbidden:
                pass

            logger.info(
                f"🧹 Zalgo text deleted from {member} ({member.id}) "
                f"in #{message.channel.name}"
            )

            await self._send_alert(
                guild=message.guild,
                title="🧹 Zalgo Text Blocked",
                description=(
                    f"{member.mention} sent a message containing Zalgo "
                    f"(distorted Unicode) text in {message.channel.mention}.\n"
                    f"**Action:** Message deleted."
                ),
                member=member,
                color=discord.Color.orange(),
            )
            return  # Message handled — no further checks needed

        # ══════════════════════════════════════════════════════════
        #  CHECK 2: Malicious Link Scanner (Layer 1 + Layer 2)
        # ══════════════════════════════════════════════════════════
        # Layer 1: instant in-memory domain cache lookup
        flagged_urls = scan_message_urls(message.content)

        # Layer 2: VirusTotal deep scan for URLs that passed Layer 1
        if not flagged_urls:
            from services.linkscanner import extract_urls, check_virustotal

            all_urls = extract_urls(message.content)
            for url in all_urls[:3]:  # Cap at 3 URLs per message to avoid API abuse
                vt_score = await check_virustotal(url)
                if vt_score > 0:
                    flagged_urls.append(url)

        if flagged_urls:
            try:
                await message.delete()
            except discord.Forbidden:
                pass

            # Determine source for the alert
            source = "VirusTotal Layer 2" if not scan_message_urls(message.content) else "Domain Cache"

            muted = await self._auto_mute(
                member, reason=f"Phishing link detected: {flagged_urls[0]}"
            )

            logger.warning(
                f"🔗 Malicious link from {member} ({member.id}): {flagged_urls} [via {source}]"
            )

            action_text = "Message deleted + **User muted**" if muted else "Message deleted"
            await self._send_alert(
                guild=message.guild,
                title="🔗 Phishing Link Detected",
                description=(
                    f"{member.mention} posted a malicious link in "
                    f"{message.channel.mention}.\n\n"
                    f"**Detection:** {source}\n"
                    f"**Flagged URLs:**\n"
                    + "\n".join(f"• `{u}`" for u in flagged_urls[:5])
                    + f"\n\n**Action:** {action_text}"
                ),
                member=member,
            )
            return

        # ══════════════════════════════════════════════════════════
        #  CHECK 2.5: Discord Invite Link Detection
        # ══════════════════════════════════════════════════════════
        if INVITE_RE.search(message.content):
            if not config.get("allow_invites", False):
                try:
                    await message.delete()
                except discord.Forbidden:
                    pass
                logger.info(
                    f"Invite link blocked from {member} ({member.id}) "
                    f"in #{message.channel.name}"
                )
                await self._auto_mute(
                    member=member,
                    guild=message.guild,
                    reason="Unauthorized Discord invite link",
                )
                await self._send_alert(
                    guild=message.guild,
                    title="🔗 Invite Link Blocked",
                    description=(
                        f"{member.mention} posted a Discord invite link "
                        f"in {message.channel.mention}.\n"
                        f"**Action:** Message deleted + auto-muted."
                    ),
                    member=member,
                    color=discord.Color.orange(),
                )
                return

        # ══════════════════════════════════════════════════════════
        #  CHECK 3: Mass Mention Detection
        # ══════════════════════════════════════════════════════════
        total_mentions = len(message.mentions) + len(message.role_mentions)
        max_mentions = config["max_mentions"]

        if total_mentions > max_mentions:
            try:
                await message.delete()
            except discord.Forbidden:
                pass

            muted = await self._auto_mute(
                member,
                reason=f"Mass mentions ({total_mentions} pings, limit: {max_mentions})",
            )

            logger.warning(
                f"📢 Mass mention from {member} ({member.id}): "
                f"{total_mentions} mentions (limit: {max_mentions})"
            )

            action_text = "Message deleted + **User muted**" if muted else "Message deleted"
            await self._send_alert(
                guild=message.guild,
                title="📢 Mass Mention Detected",
                description=(
                    f"{member.mention} mentioned **{total_mentions} users/roles** "
                    f"in a single message (limit: {max_mentions}).\n\n"
                    f"**Action:** {action_text}"
                ),
                member=member,
            )
            return

        # ══════════════════════════════════════════════════════════
        #  CHECK 4: Message Velocity / Flood Detection (Redis)
        # ══════════════════════════════════════════════════════════
        if self.bot.redis:
            is_flooding = await check_spam(
                redis=self.bot.redis,
                user_id=member.id,
                guild_id=message.guild.id,
                limit=config["spam_msg_limit"],
                window=config["spam_msg_seconds"],
            )
        else:
            # H-4 fix: local fallback when Redis is unavailable
            is_flooding = self._check_flood_fallback(
                user_id=member.id,
                guild_id=message.guild.id,
                limit=config["spam_msg_limit"],
                window=config["spam_msg_seconds"],
            )

        if is_flooding:
            muted = await self._auto_mute(
                member,
                reason=(
                    f"Message flood ({config['spam_msg_limit']}+ msgs "
                    f"in {config['spam_msg_seconds']}s)"
                ),
            )

            logger.warning(
                f"🌊 Flood detected from {member} ({member.id}) in "
                f"{message.guild.name} — auto-muted"
            )

            await self._send_alert(
                guild=message.guild,
                title="🌊 Message Flood Detected",
                description=(
                    f"{member.mention} exceeded the message velocity limit.\n"
                    f"**Threshold:** {config['spam_msg_limit']} messages "
                    f"in {config['spam_msg_seconds']}s\n\n"
                    f"**Action:** {'**User muted**' if muted else 'Mute failed (missing permissions)'}"
                ),
                member=member,
            )

    # ══════════════════════════════════════════════════════════════
    #  H-4 Fix: Local sliding window fallback (no Redis)
    # ══════════════════════════════════════════════════════════════

    def _check_flood_fallback(
        self, user_id: int, guild_id: int, limit: int, window: int
    ) -> bool:
        """
        In-memory sliding window using deque when Redis is unavailable.
        Not distributed, but prevents complete loss of flood protection.
        """
        key = f"{guild_id}:{user_id}"
        now = time.time()
        timestamps = self._local_spam_cache[key]

        # Prune old entries outside the window
        while timestamps and timestamps[0] < now - window:
            timestamps.popleft()

        timestamps.append(now)
        return len(timestamps) > limit


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AntiSpam(bot))
