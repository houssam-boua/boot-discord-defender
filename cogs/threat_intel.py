# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Threat Intelligence Cog
#  Blueprint reference: Section 6 — Link Management Commands
#
#  Commands (all @is_staff() protected):
#    !link-add    [domain] [threat_level]  — Add to blocklist + cache
#    !link-remove [domain]                 — Remove from blocklist + cache
#    !link-list                            — Display blocked domains
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import logging
from datetime import datetime, timezone

from utils.permissions import is_staff, NotStaff
from services.linkscanner import (
    add_to_cache,
    remove_from_cache,
    get_cached_domains,
    get_cache_size,
)
from security.audit_integrity import insert_audit_log

logger = logging.getLogger("antiraid.threat_intel")


class ThreatIntel(commands.Cog, name="🔗 Threat Intelligence"):
    """Link management commands for the malicious domain blocklist."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ══════════════════════════════════════════════════════════════
    #  !link-add [domain] [threat_level]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="link-add",
        aliases=["linkadd", "block-domain"],
        help="Add a domain to the malicious links blocklist.",
        usage="<domain> [threat_level]",
    )
    @is_staff()
    async def link_add(
        self,
        ctx: commands.Context,
        domain: str,
        threat_level: int = 2,
    ) -> None:
        """
        Insert a domain into the malicious_links table and
        dynamically add it to the in-memory cache.

        Args:
            domain:       The domain to block (e.g., "phishing-site.com").
            threat_level: 1=low, 2=medium (default), 3=critical.
        """
        pool = self.bot.db.pool
        if not pool:
            await ctx.send("❌ Database unavailable.")
            return

        # Normalize the domain
        domain = domain.lower().strip().lstrip("www.")

        # Validate threat level
        if threat_level not in (1, 2, 3):
            embed = discord.Embed(
                title="❌ Invalid Threat Level",
                description="Threat level must be **1** (low), **2** (medium), or **3** (critical).",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed)
            return

        # ── Insert into DB ─────────────────────────────────────
        try:
            result = await pool.execute(
                """
                INSERT INTO malicious_links (domain, threat_level, source)
                VALUES ($1, $2, 'manual')
                ON CONFLICT (domain) DO UPDATE
                    SET threat_level = $2, updated_at = NOW()
                """,
                domain,
                threat_level,
            )
        except Exception as e:
            logger.error(f"Failed to insert domain {domain}: {e}")
            await ctx.send(f"❌ Database error: `{e}`")
            return

        # ── Add to in-memory cache ─────────────────────────────
        add_to_cache(domain)

        # ── Log to audit_logs ──────────────────────────────────
        await insert_audit_log(
            pool=pool,
            guild_id=ctx.guild.id,
            actor_id=ctx.author.id,
            target_id=None,
            action_type="LINK_ADD",
            details={
                "domain": domain,
                "threat_level": threat_level,
                "source": "manual",
            },
        )

        # ── Confirmation ───────────────────────────────────────
        threat_labels = {1: "🟢 Low", 2: "🟡 Medium", 3: "🔴 Critical"}
        embed = discord.Embed(
            title="🔗 Domain Blocked",
            description=(
                f"**`{domain}`** has been added to the blocklist.\n\n"
                f"**Threat Level:** {threat_labels.get(threat_level, 'Unknown')}\n"
                f"**Cache Size:** {get_cache_size()} domains"
            ),
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text=f"Added by {ctx.author}")
        await ctx.send(embed=embed)

        logger.info(
            f"🔗 Domain blocked: {domain} (level {threat_level}) "
            f"by {ctx.author} ({ctx.author.id})"
        )

    # ══════════════════════════════════════════════════════════════
    #  !link-remove [domain]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="link-remove",
        aliases=["linkremove", "unblock-domain"],
        help="Remove a domain from the malicious links blocklist.",
        usage="<domain>",
    )
    @is_staff()
    async def link_remove(
        self,
        ctx: commands.Context,
        domain: str,
    ) -> None:
        """Remove a domain from the DB and the in-memory cache."""
        pool = self.bot.db.pool
        if not pool:
            await ctx.send("❌ Database unavailable.")
            return

        domain = domain.lower().strip().lstrip("www.")

        # ── Delete from DB ─────────────────────────────────────
        result = await pool.execute(
            "DELETE FROM malicious_links WHERE domain = $1",
            domain,
        )

        # Check if anything was actually deleted
        rows_affected = int(result.split()[-1])
        if rows_affected == 0:
            embed = discord.Embed(
                title="❌ Domain Not Found",
                description=f"**`{domain}`** is not in the blocklist.",
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        # ── Remove from in-memory cache ────────────────────────
        remove_from_cache(domain)

        # ── Log to audit_logs ──────────────────────────────────
        await insert_audit_log(
            pool=pool,
            guild_id=ctx.guild.id,
            actor_id=ctx.author.id,
            target_id=None,
            action_type="LINK_REMOVE",
            details={
                "domain": domain,
            },
        )

        # ── Confirmation ───────────────────────────────────────
        embed = discord.Embed(
            title="🔓 Domain Unblocked",
            description=(
                f"**`{domain}`** has been removed from the blocklist.\n\n"
                f"**Cache Size:** {get_cache_size()} domains"
            ),
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_footer(text=f"Removed by {ctx.author}")
        await ctx.send(embed=embed)

        logger.info(
            f"🔓 Domain unblocked: {domain} by {ctx.author} ({ctx.author.id})"
        )

    # ══════════════════════════════════════════════════════════════
    #  !link-list
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="link-list",
        aliases=["linklist", "blocked-domains"],
        help="Display all currently blocked domains.",
    )
    @is_staff()
    async def link_list(self, ctx: commands.Context) -> None:
        """Show an embed of all domains in the blocklist."""
        pool = self.bot.db.pool
        if not pool:
            await ctx.send("❌ Database unavailable.")
            return

        # Fetch from DB (includes threat levels and sources)
        rows = await pool.fetch(
            """
            SELECT domain, threat_level, source, created_at
            FROM malicious_links
            ORDER BY threat_level DESC, domain ASC
            """
        )

        if not rows:
            embed = discord.Embed(
                title="🔗 Blocked Domains",
                description="No domains are currently blocked.",
                color=discord.Color.light_grey(),
            )
            await ctx.send(embed=embed)
            return

        # ── Build paginated embeds (25 per page) ───────────────
        threat_icons = {1: "🟢", 2: "🟡", 3: "🔴"}
        pages = []
        items_per_page = 25

        for page_num in range(0, len(rows), items_per_page):
            page_rows = rows[page_num : page_num + items_per_page]
            total_pages = (len(rows) - 1) // items_per_page + 1
            current_page = page_num // items_per_page + 1

            domain_lines = []
            for row in page_rows:
                icon = threat_icons.get(row["threat_level"], "⚪")
                source = row["source"] or "unknown"
                domain_lines.append(
                    f"{icon} `{row['domain']}` — {source}"
                )

            embed = discord.Embed(
                title=f"🔗 Blocked Domains ({len(rows)} total)",
                description="\n".join(domain_lines),
                color=discord.Color.dark_teal(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.set_footer(
                text=f"Page {current_page}/{total_pages} • "
                     f"Cache: {get_cache_size()} domains"
            )
            pages.append(embed)

        # Send first page (pagination can be added later)
        await ctx.send(embed=pages[0])

    # ══════════════════════════════════════════════════════════════
    #  !link-check [url]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="link-check",
        aliases=["linkcheck", "checklink"],
        help="Manually check if a URL is flagged in the blocklist.",
        usage="<url>",
    )
    @is_staff()
    async def link_check(self, ctx: commands.Context, url: str) -> None:
        """Check a URL against the in-memory malicious domain cache."""
        from services.linkscanner import is_known_malicious
        from utils.threat_data import URL_RE

        is_malicious = is_known_malicious(url)

        # Try to extract domain for display
        match = URL_RE.search(url)
        domain = match.group(1).lower().lstrip("www.") if match else url

        if is_malicious:
            # Look up threat level from DB
            threat_level = None
            pool = self.bot.db.pool
            if pool:
                row = await pool.fetchrow(
                    "SELECT threat_level, source FROM malicious_links WHERE domain = $1",
                    domain,
                )
                if row:
                    threat_level = row["threat_level"]
                    source = row["source"]

            threat_labels = {1: "🟢 Low", 2: "🟡 Medium", 3: "🔴 Critical"}
            embed = discord.Embed(
                title="🚨 MALICIOUS — Domain is BLOCKED",
                description=(
                    f"**Domain:** `{domain}`\n"
                    f"**Threat Level:** {threat_labels.get(threat_level, 'Unknown')}\n"
                    f"**Source:** {source if threat_level else 'cache'}"
                ),
                color=discord.Color.red(),
            )
        else:
            embed = discord.Embed(
                title="✅ CLEAN — Domain not in blocklist",
                description=f"**Domain:** `{domain}`\n\nNot found in the local blocklist.",
                color=discord.Color.green(),
            )

        embed.set_footer(text=f"Checked by {ctx.author}")
        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  Error Handler
    # ══════════════════════════════════════════════════════════════

    @link_add.error
    @link_remove.error
    @link_list.error
    @link_check.error
    async def threat_intel_error(
        self, ctx: commands.Context, error: commands.CommandError
    ) -> None:
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
                    f"Missing **`{error.param.name}`**.\n\n"
                    f"**Usage:** `{ctx.prefix}{ctx.command.qualified_name} "
                    f"{ctx.command.usage or ''}`"
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        logger.error(f"Threat intel error: {error}", exc_info=error)


# ── Cog Setup ─────────────────────────────────────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ThreatIntel(bot))

