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
import asyncio
import re
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
from services.linkscanner import scan_message_urls, is_known_malicious

logger = logging.getLogger("antiraid.antispam")

# ── Default fallback values (from blueprint) ──────────────────
DEFAULT_MAX_MENTIONS = 5
DEFAULT_SPAM_MSG_LIMIT = 5
DEFAULT_SPAM_MSG_SECONDS = 2

# Trusted domains — skipped by VirusTotal to save quota and time.
# Subdomains are matched automatically by _is_safe_domain().
_SAFE_DOMAINS: frozenset[str] = frozenset({
    "youtube.com", "youtu.be",
    "github.com", "githubusercontent.com",
    "wikipedia.org",
    "twitter.com", "x.com",
    "twitch.tv",
    "reddit.com", "redd.it",
    "discord.com", "discordapp.com",
    "google.com", "googleapis.com",
    "instagram.com",
    "linkedin.com",
    "stackoverflow.com",
    "imgur.com",
    "tenor.com", "giphy.com",
})

def _is_safe_domain(url: str) -> bool:
    """
    Return True if the URL belongs to a known-safe domain.
    Handles subdomains: en.wikipedia.org → wikipedia.org → True.
    Returns False on any parse error (fail closed for safety).
    """
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname or ""
        hostname = hostname.removeprefix("www.")
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            if ".".join(parts[i:]) in _SAFE_DOMAINS:
                return True
        return False
    except Exception:
        return False

async def _safe_delete(
    message: discord.Message, *, reason: str = ""
) -> None:
    """Delete a message and log the outcome clearly."""
    try:
        await message.delete()
    except discord.NotFound:
        pass  # Already deleted — fine
    except discord.Forbidden:
        logger.warning(
            f"⚠️ Cannot delete msg {message.id} in "
            f"#{message.channel.name} — bot missing MANAGE_MESSAGES. "
            f"Reason: {reason}"
        )
    except Exception as e:
        logger.error(
            f"❌ Unexpected error deleting msg {message.id}: {e}"
        )


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

    async def _strip_admin_roles(
        self,
        member: discord.Member,
        reason: str,
    ) -> list[discord.Role]:
        """
        Strip all roles that grant administrator permission from a member.
        Used when timeout fails because the member has admin privileges.

        Returns list of stripped roles (for logging and DB record).
        Skips managed roles (bot roles) — Discord forbids removing them.
        """
        admin_roles = [
            r for r in member.roles
            if r.permissions.administrator
            and not r.managed          # never try to remove bot-managed roles
            and not r.is_default()     # never try to remove @everyone
        ]

        if not admin_roles:
            return []

        try:
            await member.remove_roles(
                *admin_roles,
                reason=f"[AntiRaid] {reason} — stripping admin roles to allow mute",
                atomic=False,
            )
            logger.warning(
                f"🛡️ Stripped {len(admin_roles)} admin role(s) from "
                f"{member} ({member.id}): "
                f"{[r.name for r in admin_roles]}"
            )
            return admin_roles
        except discord.Forbidden:
            logger.error(
                f"❌ Cannot strip admin roles from {member} ({member.id}) "
                f"— bot role is too low in hierarchy"
            )
            return []
        except Exception as e:
            logger.error(
                f"❌ Failed to strip admin roles from {member}: {e}"
            )
            return []

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

        # Skip server owner and the bot itself
        if member.id == message.guild.owner_id:
            return
        if member.id == self.bot.user.id:
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
            await _safe_delete(message, reason="Zalgo text")

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
            # Only scan URLs that are not on the trusted safelist
            unknown_urls = [u for u in all_urls if not _is_safe_domain(u)]

            for url in unknown_urls[:5]:
                try:
                    vt_score = await check_virustotal(url)
                    if vt_score >= 2:
                        flagged_urls.append(url)
                except asyncio.TimeoutError:
                    logger.warning(
                        f"⏱️ VT timeout scanning {url} from "
                        f"{member} ({member.id}) — leaving message"
                    )
                except Exception as e:
                    logger.warning(
                        f"⚠️ VT scan error for {url}: {e} — leaving message"
                    )

        # ── CHECK 2b: Scan embed URLs ──────────────────────────
        if not flagged_urls and message.embeds:
            for embed in message.embeds:
                for url in filter(None, [
                    embed.url,
                    embed.thumbnail.url if embed.thumbnail else None,
                    embed.image.url if embed.image else None,
                ]):
                    if _is_safe_domain(url):
                        continue
                    if is_known_malicious(url):
                        flagged_urls.append(url)
                    else:
                        try:
                            vt_score = await check_virustotal(url)
                            if vt_score >= 2:
                                flagged_urls.append(url)
                        except Exception:
                            pass

        # ── CHECK 2c: Scan attachment filenames/URLs ────────────
        if not flagged_urls and message.attachments:
            for att in message.attachments:
                if not _is_safe_domain(att.url) and is_known_malicious(att.url):
                    flagged_urls.append(att.url)
                for url in re.findall(r'https?://\S+', att.filename):
                    if not _is_safe_domain(url) and is_known_malicious(url):
                        flagged_urls.append(url)

        if flagged_urls:
            await _safe_delete(message, reason="Malicious link")

            # Determine detection source for the alert
            source = (
                "VirusTotal Layer 2"
                if not scan_message_urls(message.content)
                else "Domain Cache"
            )

            mute_reason = f"Phishing link detected: {flagged_urls[0]}"

            # ── Attempt 1: standard timeout ────────────────────────
            muted = await self._auto_mute(member, reason=mute_reason)
            stripped_roles: list[discord.Role] = []

            # ── Attempt 2: admin bypass — strip roles then re-mute ─
            if not muted:
                stripped_roles = await self._strip_admin_roles(
                    member,
                    reason=mute_reason,
                )
                if stripped_roles:
                    # Re-attempt timeout now that admin roles are gone
                    muted = await self._auto_mute(member, reason=mute_reason)

            # ── DM user with appeal instructions ──────────────
            if muted:
                from cogs.appeals import send_appeal_dm
                await send_appeal_dm(
                    member,
                    guild_name=message.guild.name,
                    punishment_type="muted",
                    reason=mute_reason,
                )

            # ── Build action summary ───────────────────────────────
            action_parts = ["Message deleted"]
            if muted:
                action_parts.append("**User muted (10 min)**")
            if stripped_roles:
                names = ", ".join(f"`{r.name}`" for r in stripped_roles)
                action_parts.append(f"**Admin roles stripped:** {names}")
            if not muted and not stripped_roles:
                action_parts.append(
                    "⚠️ Mute failed — bot role may be too low in hierarchy"
                )

            action_text = " + ".join(action_parts)

            # ── Save stripped roles to DB for audit/restore ────────
            if stripped_roles:
                try:
                    import json as _json
                    await self.bot.db.pool.execute(
                        """
                        INSERT INTO admin_role_strips
                            (guild_id, user_id, stripped_role_ids,
                             stripped_role_names, reason, stripped_at)
                        VALUES ($1, $2, $3, $4, $5, NOW())
                        ON CONFLICT DO NOTHING
                        """,
                        message.guild.id,
                        member.id,
                        [r.id for r in stripped_roles],
                        [r.name for r in stripped_roles],
                        mute_reason,
                    )
                except Exception as e:
                    logger.warning(
                        f"⚠️ Failed to save admin role strip to DB: {e} "
                        f"— mute still applied"
                    )

            logger.warning(
                f"🔗 Malicious link from {member} ({member.id}): "
                f"{flagged_urls} [via {source}] — "
                f"muted={muted}, stripped={[r.name for r in stripped_roles]}"
            )

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
                await _safe_delete(message, reason="Discord invite link")
                logger.info(
                    f"Invite link blocked from {member} ({member.id}) "
                    f"in #{message.channel.name}"
                )
                muted_invite = await self._auto_mute(
                    member,
                    reason="Unauthorized Discord invite link",
                )
                if muted_invite:
                    from cogs.appeals import send_appeal_dm
                    await send_appeal_dm(
                        member,
                        guild_name=message.guild.name,
                        punishment_type="muted",
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
            await _safe_delete(message, reason="Mass mentions")

            muted = await self._auto_mute(
                member,
                reason=f"Mass mentions ({total_mentions} pings, limit: {max_mentions})",
            )
            if muted:
                from cogs.appeals import send_appeal_dm
                await send_appeal_dm(
                    member,
                    guild_name=message.guild.name,
                    punishment_type="muted",
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
            # Delete the message that triggered the flood threshold
            await _safe_delete(message, reason="Message flood")

            # Bulk-delete the member's recent spam messages
            try:
                def is_flood_msg(m: discord.Message) -> bool:
                    return (
                        m.author.id == member.id
                        and m.id != message.id
                    )
                spam_msgs = [
                    m async for m in message.channel.history(limit=50)
                    if is_flood_msg(m)
                ][:9]   # up to 9 more + 1 triggering = 10 total
                if spam_msgs:
                    await message.channel.delete_messages(
                        spam_msgs,
                        reason=f"[AntiRaid] Flood cleanup — {member}",
                    )
                    logger.info(
                        f"🧹 Bulk-deleted {len(spam_msgs)} flood messages "
                        f"from {member} ({member.id}) in "
                        f"#{message.channel.name}"
                    )
            except discord.Forbidden:
                logger.warning(
                    f"⚠️ Cannot bulk-delete flood messages in "
                    f"#{message.channel.name} — missing permissions"
                )
            except Exception as e:
                logger.warning(f"⚠️ Flood cleanup failed: {e}")

            muted = await self._auto_mute(
                member,
                reason=(
                    f"Message flood ({config['spam_msg_limit']}+ msgs "
                    f"in {config['spam_msg_seconds']}s)"
                ),
            )
            if muted:
                from cogs.appeals import send_appeal_dm
                await send_appeal_dm(
                    member,
                    guild_name=message.guild.name,
                    punishment_type="muted",
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
