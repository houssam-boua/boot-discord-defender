# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Server Recovery System (Phase 4)
#
#  Background Snapshot Engine:
#    • Every 24 hours, captures a full structural snapshot of every
#      guild (roles + channels) and persists it to server_snapshots.
#
#  Restoration Commands:
#    • !snapshot-now    — Force an immediate snapshot.
#    • !restore-roles   — Recreate missing roles from the latest snapshot.
#    • !restore-channels — Recreate missing channels from the latest snapshot.
#
#  All commands require @is_staff() (Administrator permission).
# ══════════════════════════════════════════════════════════════════

import json
import asyncio
import discord
from discord.ext import commands, tasks

import logging
from datetime import datetime, timezone

from utils.permissions import is_staff
from security.audit_integrity import insert_audit_log

logger = logging.getLogger("antiraid.recovery")


class Recovery(commands.Cog, name="🔄 Recovery"):
    """
    Automated server snapshots and post-nuke restoration.
    Captures role & channel structure every 24 hours and provides
    admin commands to restore them after destructive attacks.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self._snapshot_tasks: dict[int, asyncio.Task] = {}

    async def cog_load(self) -> None:
        """Start the background snapshot loop when the cog loads."""
        self.snapshot_loop.start()
        logger.info("✅ Recovery snapshot loop started (interval: 24h)")

    async def cog_unload(self) -> None:
        """Stop the loop when the cog unloads."""
        # Cancel all pending debounced snapshot tasks on cog unload
        # Prevents orphaned tasks, memory leaks, and post-shutdown fires
        for task in self._snapshot_tasks.values():
            if not task.done():
                task.cancel()

        self.snapshot_loop.cancel()

    # ══════════════════════════════════════════════════════════════
    #  Background Snapshot Engine — runs every 24 hours
    # ══════════════════════════════════════════════════════════════

    @tasks.loop(hours=24)
    async def snapshot_loop(self) -> None:
        """Capture a structural snapshot of every guild."""
        if not self.bot.db.pool:
            return

        for guild in self.bot.guilds:
            try:
                await self._take_snapshot(guild)
            except Exception as e:
                logger.error(
                    f"❌ Snapshot failed for {guild.name} ({guild.id}): {e}"
                )

    @snapshot_loop.before_loop
    async def before_snapshot_loop(self) -> None:
        """
        Wait until the bot is ready, then take a baseline snapshot
        of every guild immediately. This ensures !restore commands
        are functional from the moment the bot comes online, instead
        of waiting 24 hours for the first loop iteration.
        """
        await self.bot.wait_until_ready()

        if not self.bot.db.pool:
            return

        logger.info("📸 Taking baseline snapshots for all guilds...")
        for guild in self.bot.guilds:
            try:
                await self._take_snapshot(guild)
            except Exception as e:
                logger.error(
                    f"❌ Baseline snapshot failed for {guild.name} ({guild.id}): {e}"
                )
        logger.info(
            f"📸 Baseline snapshots complete — {len(self.bot.guilds)} guild(s) captured"
        )

    # ══════════════════════════════════════════════════════════════
    #  Core: Take a full structural snapshot of a guild
    # ══════════════════════════════════════════════════════════════

    async def _take_snapshot(self, guild: discord.Guild) -> None:
        """
        Capture the current state of all roles and channels in a guild.
        Stores the result as a JSONB row in server_snapshots.
        """
        # ── Serialize Roles ────────────────────────────────────
        roles_data = []
        for role in guild.roles:
            if role.is_default():
                continue  # Skip @everyone — can't recreate it
            roles_data.append({
                "id": role.id,
                "name": role.name,
                "color": role.color.value,
                "permissions": role.permissions.value,
                "position": role.position,
                "hoist": role.hoist,
                "mentionable": role.mentionable,
            })

        # ── Serialize Channels ─────────────────────────────────
        channels_data = []
        for channel in guild.channels:
            channel_info = {
                "id": channel.id,
                "name": channel.name,
                "type": str(channel.type),
                "position": channel.position,
                "category_id": channel.category_id,
                "category_name": channel.category.name if channel.category else None,
            }

            # Serialize permission overwrites
            overwrites = []
            for target, overwrite in channel.overwrites.items():
                allow, deny = overwrite.pair()
                overwrites.append({
                    "target_id": target.id,
                    "target_type": "role" if isinstance(target, discord.Role) else "member",
                    "allow": allow.value,
                    "deny": deny.value,
                })
            channel_info["overwrites"] = overwrites

            # Channel-type-specific attributes
            if isinstance(channel, discord.TextChannel):
                channel_info["topic"] = channel.topic
                channel_info["nsfw"] = channel.nsfw
                channel_info["slowmode_delay"] = channel.slowmode_delay
            elif isinstance(channel, discord.VoiceChannel):
                channel_info["bitrate"] = channel.bitrate
                channel_info["user_limit"] = channel.user_limit

            channels_data.append(channel_info)

        # ── Serialize Member Role Assignments ─────────────────
        members_data = []
        if guild.members:
            for member in guild.members:
                if member.bot:
                    continue  # Skip bots — their roles are OAuth2-managed
                role_ids = [r.id for r in member.roles if not r.is_default()]
                if role_ids:  # Only save members who have at least one role
                    members_data.append({
                        "user_id": member.id,
                        "username": str(member),   # For debugging only
                        "role_ids": role_ids,       # List of role IDs they had
                    })
        else:
            logger.warning(
                f"⚠️ Member cache empty for {guild.name} — "
                f"member role snapshot skipped (check GUILD_MEMBERS intent)"
            )

        # ── Build snapshot JSON ────────────────────────────────
        snapshot = {
            "roles": roles_data,
            "channels": channels_data,
            "members": members_data,
            "guild_name": guild.name,
            "member_count": guild.member_count,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }

        # ── Persist to database ────────────────────────────────
        await self.bot.db.pool.execute(
            """
            INSERT INTO server_snapshots (guild_id, snapshot_type, data)
            VALUES ($1, $2, $3::jsonb)
            """,
            guild.id,
            "full",
            json.dumps(snapshot),
        )

        logger.info(
            f"📸 Snapshot saved: {guild.name} — "
            f"{len(roles_data)} roles, {len(channels_data)} channels, "
            f"{len(members_data)} members"
        )

    # ══════════════════════════════════════════════════════════════
    #  !snapshot-now — Force an immediate manual snapshot
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="snapshot-now",
        aliases=["snapshotnow", "snapshot"],
        help="Force an immediate server structure snapshot.",
    )
    @is_staff()
    async def snapshot_now(self, ctx: commands.Context) -> None:
        """Manually trigger a structural snapshot of the current guild."""
        if not self.bot.db.pool:
            await ctx.send("❌ Database is not connected.")
            return

        msg = await ctx.send(
            embed=discord.Embed(
                description="📸 Taking snapshot...",
                color=discord.Color.blurple(),
            )
        )

        try:
            await self._take_snapshot(ctx.guild)

            embed = discord.Embed(
                title="📸 Snapshot Saved",
                description=(
                    f"A full structural snapshot of **{ctx.guild.name}** has been saved.\n\n"
                    f"**Roles captured:** {len(ctx.guild.roles) - 1}\n"
                    f"**Channels captured:** {len(ctx.guild.channels)}\n\n"
                    f"Use `{ctx.prefix}restore-roles` or `{ctx.prefix}restore-channels` "
                    f"to restore from this snapshot."
                ),
                color=discord.Color.green(),
            )
            embed.set_footer(
                text=f"Triggered by {ctx.author}",
                icon_url=ctx.author.display_avatar.url,
            )
            await msg.edit(embed=embed)

            # Audit log
            if self.bot.db.pool:
                await insert_audit_log(
                    pool=self.bot.db.pool,
                    guild_id=ctx.guild.id,
                    actor_id=ctx.author.id,
                    target_id=None,
                    action_type="MANUAL_SNAPSHOT",
                    details={"roles": len(ctx.guild.roles) - 1, "channels": len(ctx.guild.channels)},
                    severity="INFO",
                )

        except Exception as e:
            await msg.edit(
                embed=discord.Embed(
                    title="❌ Snapshot Failed",
                    description=f"An error occurred: `{e}`",
                    color=discord.Color.red(),
                )
            )
            logger.error(f"Manual snapshot failed for {ctx.guild.name}: {e}")

    # ══════════════════════════════════════════════════════════════
    #  Auto-Restore: Programmatic recovery without human input
    # ══════════════════════════════════════════════════════════════

    async def restore_from_snapshot(
        self,
        guild: discord.Guild,
        *,
        triggered_by: str = "auto-nuke-detection",
    ) -> dict:
        """
        Programmatic restore triggered by anti-nuke detection.
        Restores roles and channels from the most recent snapshot
        without requiring a ctx object or any text channel.

        Returns dict with keys:
          roles_restored, channels_restored,
          roles_failed, channels_failed,
          snapshot_age_seconds
        """
        log = logging.getLogger("antiraid.recovery")
        result = {
            "roles_restored": 0,
            "channels_restored": 0,
            "roles_failed": 0,
            "channels_failed": 0,
            "members_reassigned": 0,
            "members_failed": 0,
            "snapshot_age_seconds": 0.0,
        }

        # ── Rate-guard: prevent duplicate restores within 60s ──
        if self.bot.redis:
            guard_key = f"antiraid:autorestore:{guild.id}"
            already_running = await self.bot.redis.set(
                guard_key, "1", nx=True, ex=60
            )
            if not already_running:
                log.warning(
                    f"⚠️ Auto-restore for {guild.name} already in "
                    f"progress — skipping duplicate (rate-guard 60s)"
                )
                return result

        if not self.bot.db.pool:
            log.error(
                "restore_from_snapshot: DB pool unavailable — cannot restore"
            )
            return result

        # ── Load most recent snapshot ──────────────────────────
        row = await self.bot.db.pool.fetchrow(
            """SELECT data, created_at
               FROM server_snapshots
               WHERE guild_id = $1
               ORDER BY created_at DESC
               LIMIT 1""",
            guild.id,
        )

        if not row:
            log.error(
                f"restore_from_snapshot: No snapshot found for "
                f"{guild.name} ({guild.id}) — cannot restore"
            )
            return result

        import json
        from datetime import timezone
        snapshot_age = (
            discord.utils.utcnow()
            - row["created_at"].replace(tzinfo=timezone.utc)
        ).total_seconds()
        result["snapshot_age_seconds"] = snapshot_age

        data = row["data"]
        if isinstance(data, str):
            data = json.loads(data)
            
        roles_data    = data.get("roles", [])
        channels_data = data.get("channels", [])
        members_data  = data.get("members", [])

        log.warning(
            f"🔄 AUTO-RESTORE triggered in {guild.name} ({guild.id}) "
            f"by [{triggered_by}] — snapshot age: {snapshot_age:.0f}s "
            f"| {len(roles_data)} roles, {len(channels_data)} channels"
        )

        # ── Pre-restore forensic snapshot ──────────────────────
        # Saves the current (damaged) state for forensic analysis.
        try:
            await self._take_snapshot(guild)
            log.info(f"📸 Pre-restore forensic snapshot saved for {guild.name}")
        except Exception as e:
            log.warning(
                f"⚠️ Pre-restore snapshot failed: {e} — continuing restore"
            )

        # ── Step 1: Restore Roles ──────────────────────────────
        existing_role_names = {r.name for r in guild.roles}

        for role_info in roles_data:
            role_name = role_info.get("name", "")
            if not role_name or role_name == "@everyone":
                continue
            if role_name in existing_role_names:
                continue  # Role still exists — skip

            try:
                permissions = discord.Permissions(
                    role_info.get("permissions", 0)
                )
                color_value = role_info.get("color", 0)
                color = (
                    discord.Color(color_value)
                    if color_value
                    else discord.Color.default()
                )
                await guild.create_role(
                    name=role_name,
                    permissions=permissions,
                    color=color,
                    hoist=role_info.get("hoist", False),
                    mentionable=role_info.get("mentionable", False),
                    reason=(
                        f"[AntiRaid] Auto-restore — "
                        f"triggered by {triggered_by}"
                    ),
                )
                result["roles_restored"] += 1
                log.info(f"  ✅ Role restored: {role_name}")

            except discord.Forbidden:
                result["roles_failed"] += 1
                log.warning(
                    f"  ⚠️ Cannot restore role {role_name} — missing permissions"
                )
            except Exception as e:
                result["roles_failed"] += 1
                log.error(f"  ❌ Failed to restore role {role_name}: {e}")

        # ── Step 2: Restore Channels ───────────────────────────
        existing_channel_names = {c.name for c in guild.channels}

        for ch_info in channels_data:
            ch_name = ch_info.get("name", "")
            if not ch_name:
                continue
            if ch_name in existing_channel_names:
                continue  # Channel still exists — skip

            try:
                ch_type = ch_info.get("type", "text")

                if ch_type == "text":
                    await guild.create_text_channel(
                        name=ch_name,
                        topic=ch_info.get("topic", ""),
                        slowmode_delay=ch_info.get("slowmode_delay", 0),
                        nsfw=ch_info.get("nsfw", False),
                        reason=(
                            f"[AntiRaid] Auto-restore — "
                            f"triggered by {triggered_by}"
                        ),
                    )
                elif ch_type == "voice":
                    await guild.create_voice_channel(
                        name=ch_name,
                        bitrate=min(ch_info.get("bitrate", 64000), 96000),
                        user_limit=ch_info.get("user_limit", 0),
                        reason=(
                            f"[AntiRaid] Auto-restore — "
                            f"triggered by {triggered_by}"
                        ),
                    )
                elif ch_type == "category":
                    await guild.create_category(
                        name=ch_name,
                        reason=(
                            f"[AntiRaid] Auto-restore — "
                            f"triggered by {triggered_by}"
                        ),
                    )

                result["channels_restored"] += 1
                log.info(f"  ✅ Channel restored: #{ch_name}")

            except discord.Forbidden:
                result["channels_failed"] += 1
                log.warning(
                    f"  ⚠️ Cannot restore #{ch_name} — missing permissions"
                )
            except Exception as e:
                result["channels_failed"] += 1
                log.error(f"  ❌ Failed to restore #{ch_name}: {e}")

        # ── Step 3: Re-assign Member Roles ───────────────────
        if members_data:
            log.warning(
                f"👥 Re-assigning roles to {len(members_data)} members "
                f"in {guild.name}…"
            )

            # Build a map: old_role_id → role_name (from snapshot)
            # Then: role_name → new Role object (from live guild)
            # IDs change after recreation — ALWAYS match by NAME
            old_id_to_name: dict[int, str] = {
                r["id"]: r["name"]
                for r in roles_data
                if "id" in r and "name" in r
            }
            name_to_new_role: dict[str, discord.Role] = {
                r.name: r for r in guild.roles
            }

            for member_info in members_data:
                user_id  = member_info.get("user_id")
                role_ids = member_info.get("role_ids", [])

                if not user_id or not role_ids:
                    continue

                member = guild.get_member(user_id)
                if not member:
                    continue  # Member left the server — skip silently

                roles_to_add = []
                for old_id in role_ids:
                    role_name = old_id_to_name.get(old_id)
                    if not role_name:
                        continue
                    new_role = name_to_new_role.get(role_name)
                    if new_role and new_role not in member.roles:
                        roles_to_add.append(new_role)

                if not roles_to_add:
                    continue

                try:
                    await member.add_roles(
                        *roles_to_add,
                        reason=(
                            f"[AntiRaid] Auto role re-assignment — "
                            f"triggered by {triggered_by}"
                        ),
                        atomic=False,
                    )
                    result["members_reassigned"] += 1
                    log.info(
                        f"  ✅ Roles re-assigned to {member} "
                        f"({len(roles_to_add)} roles)"
                    )
                    # Rate-limit: Discord allows ~5 role edits/sec
                    await asyncio.sleep(0.3)

                except discord.Forbidden:
                    result["members_failed"] += 1
                    log.warning(
                        f"  ⚠️ Cannot re-assign roles to {member} "
                        f"— missing permissions"
                    )
                except Exception as e:
                    result["members_failed"] += 1
                    log.error(
                        f"  ❌ Failed to re-assign roles to {member}: {e}"
                    )
        else:
            log.warning(
                "👥 No member role data in snapshot — "
                "re-assignment skipped (snapshot taken before this feature)"
            )

        # ── Step 4: Send summary embed to first available channel
        summary_lines = [
            f"🔄 **Auto-restore complete** — triggered by `{triggered_by}`",
            f"📸 Snapshot age: {snapshot_age:.0f}s",
            f"✅ Roles restored: **{result['roles_restored']}**",
            f"✅ Channels restored: **{result['channels_restored']}**",
            f"👥 Members re-assigned: **{result['members_reassigned']}**",
        ]
        if result["roles_failed"] or result["channels_failed"] or result["members_failed"]:
            summary_lines.append(
                f"⚠️ Failed: {result['roles_failed']} roles, "
                f"{result['channels_failed']} channels, "
                f"{result['members_failed']} members"
            )

        summary = "\n".join(summary_lines)
        log.warning(summary.replace("**", "").replace("`", ""))

        target_channel = None
        for ch in guild.text_channels:
            if ch.permissions_for(guild.me).send_messages:
                target_channel = ch
                break

        if target_channel:
            try:
                embed = discord.Embed(
                    title="🛡️ AntiRaid — Auto-Restore Complete",
                    description=summary,
                    color=discord.Color.green(),
                )
                embed.set_footer(text=f"Triggered by: {triggered_by}")
                await target_channel.send(embed=embed)
            except Exception:
                pass  # Never fail the restore if alert send fails

        return result

    # ══════════════════════════════════════════════════════════════
    #  Helper: Fetch the latest snapshot for a guild
    # ══════════════════════════════════════════════════════════════

    async def _get_latest_snapshot(self, guild_id: int) -> dict | None:
        """Fetch the most recent snapshot from the database."""
        row = await self.bot.db.pool.fetchrow(
            """
            SELECT data, created_at
            FROM server_snapshots
            WHERE guild_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            """,
            guild_id,
        )
        if not row:
            return None

        data = row["data"]
        if isinstance(data, str):
            data = json.loads(data)
        data["_created_at"] = row["created_at"]
        return data

    # ══════════════════════════════════════════════════════════════
    #  !restore — Recreate missing roles/channels from snapshot
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="restore",
        aliases=[
            "restore-roles",
            "restore-channels",
            "restoreroles",
            "restorechannels",
        ],
        help="Full server restore — roles, channels, and member role assignments.",
    )
    @is_staff()
    async def restore(self, ctx: commands.Context) -> None:
        """
        Full server restore from latest snapshot.
        Restores roles, channels, and re-assigns member roles.
        All previous aliases (!restore-roles, !restore-channels) still work.
        """
        await ctx.send(
            f"🔄 Running full restore from snapshot "
            f"(triggered by {ctx.author})…"
        )
        await self.restore_from_snapshot(
            ctx.guild,
            triggered_by=f"manual:restore:{ctx.author.id}",
        )
        # restore_from_snapshot sends the summary embed — no second message needed.

    @commands.command(
        name="restore-member",
        aliases=["restoremember", "restore-admin"],
        help="Re-assign stripped roles to a member from the audit log.",
    )
    @is_staff()
    async def restore_member(
        self, ctx: commands.Context, member: discord.Member
    ) -> None:
        """Re-assign the most recently stripped roles to a member."""
        row = await self.bot.db.pool.fetchrow(
            """
            SELECT stripped_role_ids, stripped_role_names,
                   stripped_at, reason
            FROM admin_role_strips
            WHERE guild_id = $1 AND user_id = $2
            ORDER BY stripped_at DESC
            LIMIT 1
            """,
            ctx.guild.id,
            member.id,
        )

        if not row:
            await ctx.send(
                f"❌ No stripped role record found for {member.mention}."
            )
            return

        role_ids   = row["stripped_role_ids"]
        role_names = row["stripped_role_names"]
        stripped_at = row["stripped_at"]
        reason     = row["reason"]

        roles_to_restore = []
        missing_names    = []

        for rid, rname in zip(role_ids, role_names):
            role = ctx.guild.get_role(rid)
            if not role:
                role = discord.utils.get(ctx.guild.roles, name=rname)
            if role:
                roles_to_restore.append(role)
            else:
                missing_names.append(rname)

        if not roles_to_restore:
            await ctx.send(
                f"❌ None of the stripped roles exist anymore: "
                f"{', '.join(role_names)}"
            )
            return

        try:
            await member.add_roles(
                *roles_to_restore,
                reason=(
                    f"[AntiRaid] Manual role restore by {ctx.author} — "
                    f"originally stripped: {reason}"
                ),
                atomic=False,
            )
            restored = ", ".join(f"`{r.name}`" for r in roles_to_restore)
            msg = (
                f"✅ Restored {len(roles_to_restore)} role(s) to "
                f"{member.mention}: {restored}\n"
                f"📅 Originally stripped: "
                f"{stripped_at.strftime('%Y-%m-%d %H:%M UTC')}\n"
                f"📝 Reason: {reason}"
            )
            if missing_names:
                msg += (
                    f"\n⚠️ These roles no longer exist: "
                    f"{', '.join(missing_names)}"
                )
            await ctx.send(msg)

        except discord.Forbidden:
            await ctx.send(
                f"❌ Missing permissions to restore roles for "
                f"{member.mention}."
            )
        except Exception as e:
            await ctx.send(f"❌ Failed to restore roles: {e}")

    # ══════════════════════════════════════════════════════════════
    #  Live Snapshot Engine — Debounced to prevent DB/API exhaustion
    # ══════════════════════════════════════════════════════════════

    async def _debounced_snapshot(
        self, guild: discord.Guild, delay: float = 5.0
    ):
        """
        Waits `delay` seconds then fires exactly one snapshot.
        If a newer event cancels this task before the delay
        expires, returns silently — no log noise, no crash.

        Safety properties:
          - asyncio.sleep() is INSIDE the try block so cancellation
            during the wait is always caught by CancelledError
          - CancelledError is caught BEFORE Exception (order matters)
          - finally always cleans up the task dict entry
        """
        try:
            await asyncio.sleep(delay)
            await self._take_snapshot(guild)
        except asyncio.CancelledError:
            return  # expected — a newer event reset the timer, silent exit
        except Exception as e:
            logging.getLogger("antiraid.recovery").warning(
                f"⚠️ Debounced snapshot failed for {guild.name}: {e}"
            )
        finally:
            self._snapshot_tasks.pop(guild.id, None)

    def _schedule_snapshot(self, guild: discord.Guild):
        """
        Cancels any pending snapshot task for this guild and
        schedules a fresh one. Always called as a plain method —
        NEVER awaited. Each guild gets its own slot so two guilds
        never cancel each other's timers.
        """
        existing = self._snapshot_tasks.get(guild.id)
        if existing and not existing.done():
            existing.cancel()
        self._snapshot_tasks[guild.id] = asyncio.create_task(
            self._debounced_snapshot(guild)
        )

    @commands.Cog.listener()
    async def on_guild_channel_create(
        self, channel: discord.abc.GuildChannel
    ):
        """Re-snapshot on channel create so new channels are never lost."""
        self._schedule_snapshot(channel.guild)

    @commands.Cog.listener()
    async def on_guild_role_create(self, role: discord.Role):
        """Re-snapshot on role create so new roles are never lost."""
        self._schedule_snapshot(role.guild)

    @commands.Cog.listener()
    async def on_guild_channel_update(
        self,
        before: discord.abc.GuildChannel,
        after: discord.abc.GuildChannel,
    ):
        """Re-snapshot on channel edits (name, topic, permissions changed)."""
        self._schedule_snapshot(after.guild)


# ── Cog Setup (required for dynamic loading) ──────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Recovery(bot))
