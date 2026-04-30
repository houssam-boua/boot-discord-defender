# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Investigation Cog
#  Blueprint reference: Section 6 — Audit & Investigation Commands
#
#  Commands (all @is_staff() protected):
#    !verify-integrity  — Cryptographic hash chain validation
#    !security-status   — Real-time security dashboard embed
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import json
import logging
from datetime import datetime, timezone

from utils.permissions import is_staff, NotStaff
from security.audit_integrity import compute_log_hash
from services.linkscanner import get_cache_size

logger = logging.getLogger("antiraid.investigation")


class Investigation(commands.Cog, name="🔍 Investigation"):
    """Audit verification and security monitoring commands."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    # ══════════════════════════════════════════════════════════════
    #  !verify-integrity
    #  "Run hash chain validation on the entire audit log."
    #  Blueprint: Module 5 — "A !verify-integrity command checks
    #  the full chain on demand."
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="verify-integrity",
        aliases=["verify", "integrity-check"],
        help="Run SHA-256 hash chain validation on the entire audit log.",
    )
    @is_staff()
    async def verify_integrity(self, ctx: commands.Context) -> None:
        """
        Fetch all audit_logs rows for this guild ordered by ID,
        recompute the SHA-256 hash chain from "GENESIS" to the end,
        and compare each computed hash against the stored hash_signature.

        If any mismatch is found → the database has been tampered with.
        If all match → the chain is intact and verified.
        """
        pool = self.bot.db.pool
        if not pool:
            await ctx.send("❌ Database unavailable.")
            return

        # ── Show progress ──────────────────────────────────────
        status_embed = discord.Embed(
            title="🔍 Integrity Check — Running",
            description="Validating the SHA-256 hash chain...\nThis may take a moment for large logs.",
            color=discord.Color.yellow(),
        )
        status_msg = await ctx.send(embed=status_embed)

        # ── Fetch all audit log rows for this guild ────────────
        rows = await pool.fetch(
            """
            SELECT id, guild_id, actor_id, target_id,
                   action_type, details, hash_signature
            FROM audit_logs
            WHERE guild_id = $1
            ORDER BY id ASC
            """,
            ctx.guild.id,
        )

        if not rows:
            embed = discord.Embed(
                title="📋 No Audit Logs",
                description="There are no audit log entries for this server yet.",
                color=discord.Color.light_grey(),
            )
            await status_msg.edit(embed=embed)
            return

        # ── Recompute the hash chain from GENESIS ──────────────
        previous_hash = "GENESIS"
        tampered = False
        tampered_at = None
        total_checked = 0

        for row in rows:
            total_checked += 1

            # Parse the details JSONB field
            details = row["details"]
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except (json.JSONDecodeError, TypeError):
                    details = {}
            elif details is None:
                details = {}

            # Reconstruct the log_data dict exactly as insert_audit_log does
            log_data = {
                "guild_id": row["guild_id"],
                "actor_id": row["actor_id"],
                "target_id": row["target_id"],
                "action_type": row["action_type"],
                "details": details,
            }

            # Compute what the hash SHOULD be
            expected_hash = compute_log_hash(previous_hash, log_data)

            # Compare against stored hash
            if expected_hash != row["hash_signature"]:
                tampered = True
                tampered_at = row
                break

            # Move to next link in the chain
            previous_hash = row["hash_signature"]

        # ══════════════════════════════════════════════════════════
        #  RESULT
        # ══════════════════════════════════════════════════════════

        if tampered:
            # ❌ TAMPERED — chain is broken
            embed = discord.Embed(
                title="🚨 INTEGRITY VIOLATION DETECTED",
                description=(
                    f"**The audit log hash chain has been broken!**\n\n"
                    f"A record has been modified or deleted, invalidating\n"
                    f"the chain from that point forward.\n\n"
                    f"**Tampered Record:**\n"
                    f"• **ID:** `{tampered_at['id']}`\n"
                    f"• **Action:** `{tampered_at['action_type']}`\n"
                    f"• **Records checked before failure:** {total_checked}\n"
                    f"• **Total records:** {len(rows)}"
                ),
                color=discord.Color.dark_red(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.set_footer(
                text="⚠️ The database may have been tampered with. Investigate immediately."
            )

            logger.critical(
                f"🚨 INTEGRITY VIOLATION in {ctx.guild.name} — "
                f"Chain broken at record ID {tampered_at['id']}"
            )

        else:
            # ✅ VERIFIED — chain is intact
            embed = discord.Embed(
                title="✅ Integrity Verified",
                description=(
                    f"The SHA-256 hash chain is **intact and valid**.\n\n"
                    f"**Records verified:** {total_checked}\n"
                    f"**Chain status:** `GENESIS` → ... → `{previous_hash[:16]}...`\n"
                    f"**Result:** No tampering detected."
                ),
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.set_footer(
                text=f"Full chain verified by {ctx.author}"
            )

            logger.info(
                f"✅ Integrity check passed in {ctx.guild.name} — "
                f"{total_checked} records verified"
            )

        await status_msg.edit(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  !security-status
    #  "Show a real-time security dashboard summary in chat."
    #  Blueprint: Section 6 — Emergency Commands
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="security-status",
        aliases=["status", "dashboard", "sec-status"],
        help="Show a real-time security dashboard summary.",
    )
    @is_staff()
    async def security_status(self, ctx: commands.Context) -> None:
        """
        Display a rich embed showing the current security posture:
        DB/Redis health, module toggles, threat stats, recent activity.
        """
        pool = self.bot.db.pool

        # ── 1. DB Health ───────────────────────────────────────
        db_online = False
        if pool:
            try:
                await pool.fetchval("SELECT 1")
                db_online = True
            except Exception:
                pass

        # ── 2. Redis Health ────────────────────────────────────
        redis_online = False
        if self.bot.redis:
            try:
                await self.bot.redis.ping()
                redis_online = True
            except Exception:
                pass

        # ── 3. Module Toggles (from DB) ────────────────────────
        config = {
            "captcha_enabled": True,
            "antinuke_enabled": True,
            "antispam_enabled": True,
            "proxycheck_enabled": False,
        }
        if pool:
            row = await pool.fetchrow(
                """
                SELECT captcha_enabled, antinuke_enabled,
                       antispam_enabled, proxycheck_enabled
                FROM server_configs
                WHERE guild_id = $1
                """,
                ctx.guild.id,
            )
            if row:
                config = dict(row)

        # ── 4. Stats ───────────────────────────────────────────
        total_logs = 0
        recent_critical = 0
        active_punishments = 0
        blocked_domains = get_cache_size()

        if pool:
            # Total audit log entries
            total_logs = await pool.fetchval(
                "SELECT COUNT(*) FROM audit_logs WHERE guild_id = $1",
                ctx.guild.id,
            ) or 0

            # Recent critical events (last 24h)
            recent_critical = await pool.fetchval(
                """
                SELECT COUNT(*) FROM audit_logs
                WHERE guild_id = $1
                  AND severity = 'CRITICAL'
                  AND created_at > NOW() - INTERVAL '24 hours'
                """,
                ctx.guild.id,
            ) or 0

            # Active temporal punishments
            active_punishments = await pool.fetchval(
                """
                SELECT COUNT(*) FROM temporal_punishments
                WHERE guild_id = $1 AND active = TRUE
                """,
                ctx.guild.id,
            ) or 0

        # ── 5. Check lockdown status ───────────────────────────
        lockdown_active = False
        if self.bot.redis:
            try:
                lockdown_active = await self.bot.redis.exists(
                    f"lockdown_snapshot:{ctx.guild.id}"
                )
            except Exception:
                pass

        # ══════════════════════════════════════════════════════════
        #  Build the dashboard embed
        # ══════════════════════════════════════════════════════════

        embed = discord.Embed(
            title=f"🛡️ Security Status — {ctx.guild.name}",
            description="Real-time security dashboard for this server.",
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )

        # Infrastructure Health
        db_status = "🟢 Online" if db_online else "🔴 Offline"
        redis_status = "🟢 Online" if redis_online else "🔴 Offline"
        lock_status = "🔒 ACTIVE" if lockdown_active else "🟢 Normal"

        embed.add_field(
            name="🔧 Infrastructure",
            value=(
                f"**PostgreSQL:** {db_status}\n"
                f"**Redis:** {redis_status}\n"
                f"**Lockdown:** {lock_status}"
            ),
            inline=True,
        )

        # Module Status
        def toggle(val: bool) -> str:
            return "✅ Enabled" if val else "❌ Disabled"

        embed.add_field(
            name="⚙️ Modules",
            value=(
                f"**CAPTCHA:** {toggle(config.get('captcha_enabled', True))}\n"
                f"**Anti-Nuke:** {toggle(config.get('antinuke_enabled', True))}\n"
                f"**Anti-Spam:** {toggle(config.get('antispam_enabled', True))}\n"
                f"**ProxyCheck:** {toggle(config.get('proxycheck_enabled', False))}"
            ),
            inline=True,
        )

        # Threat Statistics
        embed.add_field(
            name="📊 Statistics",
            value=(
                f"**Blocked Domains:** {blocked_domains}\n"
                f"**Audit Logs:** {total_logs:,}\n"
                f"**Active Punishments:** {active_punishments}\n"
                f"**Critical (24h):** {recent_critical}"
            ),
            inline=True,
        )

        # Bot info
        embed.add_field(
            name="🤖 Bot Info",
            value=(
                f"**Latency:** {round(self.bot.latency * 1000)}ms\n"
                f"**Guilds:** {len(self.bot.guilds)}\n"
                f"**Cogs Loaded:** {len(self.bot.cogs)}"
            ),
            inline=True,
        )

        embed.set_footer(
            text=f"Requested by {ctx.author}",
            icon_url=ctx.author.display_avatar.url,
        )
        embed.set_thumbnail(url=ctx.guild.icon.url if ctx.guild.icon else "")

        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  !scan-user [@user]
    #  "Show full security profile (account age, risk score, history)"
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="scan-user",
        aliases=["scanuser", "profile"],
        help="Show full security profile for a user.",
        usage="<@user>",
    )
    @is_staff()
    async def scan_user(self, ctx: commands.Context, member: discord.Member) -> None:
        """Security dossier: age, risk score, warnings, recent audit log entries."""
        pool = self.bot.db.pool

        # Account age
        age_hours = round(
            (datetime.now(timezone.utc) - member.created_at).total_seconds() / 3600, 1
        )
        joined_ago = discord.utils.format_dt(member.joined_at, style="R") if member.joined_at else "Unknown"

        # Risk score
        risk_row = None
        if pool:
            risk_row = await pool.fetchrow(
                "SELECT * FROM risk_scores WHERE guild_id = $1 AND user_id = $2",
                ctx.guild.id, member.id,
            )

        # Warning count
        warn_count = 0
        if pool:
            warn_count = await pool.fetchval(
                "SELECT COUNT(*) FROM audit_logs WHERE guild_id=$1 AND target_id=$2 AND action_type='WARN'",
                ctx.guild.id, member.id,
            ) or 0

        # Recent log entries
        recent = []
        if pool:
            recent = await pool.fetch(
                """SELECT action_type, severity, created_at FROM audit_logs
                   WHERE guild_id = $1 AND target_id = $2
                   ORDER BY created_at DESC LIMIT 5""",
                ctx.guild.id, member.id,
            )

        # Build embed
        embed = discord.Embed(
            title=f"🔍 Security Profile — {member}",
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )
        embed.set_thumbnail(url=member.display_avatar.url)

        embed.add_field(
            name="👤 Account Info",
            value=(
                f"**ID:** `{member.id}`\n"
                f"**Created:** {discord.utils.format_dt(member.created_at, style='R')}\n"
                f"**Account Age:** {age_hours:.0f} hours\n"
                f"**Joined Server:** {joined_ago}\n"
                f"**Has Avatar:** {'Yes' if member.avatar else 'No'}\n"
                f"**Roles:** {len(member.roles) - 1}"
            ),
            inline=True,
        )

        risk_str = "No data"
        if risk_row:
            risk_str = (
                f"**Total:** {risk_row['total_score']}/100\n"
                f"Age: {risk_row['account_age_score']} · VPN: {'⚠️' if risk_row['vpn_flag'] else '✅'}\n"
                f"Spam: {risk_row['spam_velocity_score']} · Links: {risk_row['link_abuse_score']}"
            )

        embed.add_field(
            name="📊 Risk Score",
            value=risk_str,
            inline=True,
        )

        embed.add_field(
            name="⚠️ Warnings",
            value=f"**{warn_count}** on record",
            inline=True,
        )

        if recent:
            log_lines = []
            for r in recent:
                sev_icon = {"CRITICAL": "🔴", "WARN": "🟡"}.get(r["severity"], "🔵")
                ts = discord.utils.format_dt(r["created_at"], style="R")
                log_lines.append(f"{sev_icon} `{r['action_type']}` {ts}")
            embed.add_field(
                name="📋 Recent Activity",
                value="\n".join(log_lines),
                inline=False,
            )

        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  !audit-search [filters]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="audit-search",
        aliases=["auditsearch", "logsearch"],
        help="Search audit logs by user, action type, or severity.",
        usage="[user:@user] [action:TYPE] [severity:LEVEL]",
    )
    @is_staff()
    async def audit_search(self, ctx: commands.Context, *, query: str = "") -> None:
        """Search audit logs with flexible filters."""
        pool = self.bot.db.pool
        if not pool:
            await ctx.send("❌ Database unavailable.")
            return

        # Parse filters from query string
        filters = {"guild_id": ctx.guild.id}
        conditions = ["guild_id = $1"]
        params = [ctx.guild.id]
        idx = 2

        # Parse user filter
        for part in query.split():
            if part.startswith("user:"):
                try:
                    uid = int(part.split(":")[1].strip("<@!>"))
                    conditions.append(f"(actor_id = ${idx} OR target_id = ${idx})")
                    params.append(uid)
                    idx += 1
                except ValueError:
                    pass
            elif part.startswith("action:"):
                action = part.split(":")[1].upper()
                conditions.append(f"action_type = ${idx}")
                params.append(action)
                idx += 1
            elif part.startswith("severity:"):
                sev = part.split(":")[1].upper()
                conditions.append(f"severity = ${idx}")
                params.append(sev)
                idx += 1

        where = " AND ".join(conditions)
        rows = await pool.fetch(
            f"""SELECT id, action_type, actor_id, target_id, severity, created_at
                FROM audit_logs WHERE {where}
                ORDER BY created_at DESC LIMIT 15""",
            *params,
        )

        if not rows:
            await ctx.send(embed=discord.Embed(
                title="🔍 No Results", description="No matching audit log entries.",
                color=discord.Color.light_grey(),
            ))
            return

        lines = []
        for r in rows:
            sev_icon = {"CRITICAL": "🔴", "WARN": "🟡"}.get(r["severity"], "🔵")
            ts = discord.utils.format_dt(r["created_at"], style="R")
            lines.append(
                f"{sev_icon} **#{r['id']}** `{r['action_type']}` "
                f"actor:`{r['actor_id']}` target:`{r['target_id']}` {ts}"
            )

        embed = discord.Embed(
            title=f"🔍 Audit Search — {len(rows)} Results",
            description="\n".join(lines),
            color=discord.Color.blurple(),
        )
        embed.set_footer(text=f"Query: {query or '(all)'}")
        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  !case [case-id]
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="case",
        help="Retrieve a specific audit log entry by ID.",
        usage="<case_id>",
    )
    @is_staff()
    async def case(self, ctx: commands.Context, case_id: int) -> None:
        """Fetch and display a single audit log record."""
        pool = self.bot.db.pool
        if not pool:
            await ctx.send("❌ Database unavailable.")
            return

        row = await pool.fetchrow(
            """SELECT id, guild_id, actor_id, target_id, action_type,
                      details, severity, created_at, hash_signature
               FROM audit_logs WHERE id = $1 AND guild_id = $2""",
            case_id, ctx.guild.id,
        )

        if not row:
            await ctx.send(embed=discord.Embed(
                title="❌ Case Not Found",
                description=f"No audit log entry with ID `{case_id}` in this server.",
                color=discord.Color.red(),
            ))
            return

        sev_colors = {"CRITICAL": discord.Color.dark_red(), "WARN": discord.Color.orange()}
        embed = discord.Embed(
            title=f"📋 Case #{row['id']} — {row['action_type']}",
            color=sev_colors.get(row["severity"], discord.Color.blurple()),
            timestamp=row["created_at"],
        )
        embed.add_field(name="Severity", value=row["severity"], inline=True)
        embed.add_field(name="Actor", value=f"`{row['actor_id']}`", inline=True)
        embed.add_field(name="Target", value=f"`{row['target_id']}`", inline=True)

        details = row["details"]
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except (json.JSONDecodeError, TypeError):
                details = {}
        if details:
            detail_str = "\n".join(f"**{k}:** `{v}`" for k, v in list(details.items())[:10])
            embed.add_field(name="Details", value=detail_str, inline=False)

        embed.set_footer(text=f"Hash: {row['hash_signature'][:24]}...")
        await ctx.send(embed=embed)

    # ══════════════════════════════════════════════════════════════
    #  Error Handler
    # ══════════════════════════════════════════════════════════════

    @verify_integrity.error
    @security_status.error
    @scan_user.error
    @audit_search.error
    @case.error
    async def investigation_error(
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

        logger.error(f"Investigation error: {error}", exc_info=error)
        embed = discord.Embed(
            title="⚠️ Unexpected Error",
            description="Something went wrong. The error has been logged.",
            color=discord.Color.dark_red(),
        )
        await ctx.send(embed=embed)


# ── Cog Setup ─────────────────────────────────────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Investigation(bot))

