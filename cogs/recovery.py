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
            if guild.me.permissions_in(ch).send_messages:
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
    #  !restore-roles — Recreate missing roles from snapshot
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="restore-roles",
        aliases=["restoreroles"],
        help="Restore missing roles from the latest server snapshot.",
    )
    @is_staff()
    async def restore_roles(self, ctx: commands.Context) -> None:
        """Recreate roles that exist in the snapshot but are missing from the guild."""
        if not self.bot.db.pool:
            await ctx.send("❌ Database is not connected.")
            return

        snapshot = await self._get_latest_snapshot(ctx.guild.id)
        if not snapshot:
            await ctx.send(
                embed=discord.Embed(
                    title="❌ No Snapshot Found",
                    description=(
                        f"No snapshot exists for this server. "
                        f"Run `{ctx.prefix}snapshot-now` first."
                    ),
                    color=discord.Color.red(),
                )
            )
            return

        # Compare snapshot roles against current guild roles
        current_role_ids = {r.id for r in ctx.guild.roles}
        saved_roles = snapshot.get("roles", [])
        missing_roles = [r for r in saved_roles if r["id"] not in current_role_ids]

        if not missing_roles:
            await ctx.send(
                embed=discord.Embed(
                    title="✅ All Roles Present",
                    description="No missing roles detected — your server matches the snapshot.",
                    color=discord.Color.green(),
                )
            )
            return

        # Confirmation message
        role_list = "\n".join(f"• `{r['name']}` (color: #{r['color']:06X})" for r in missing_roles[:20])
        confirm_embed = discord.Embed(
            title="🔄 Restore Roles?",
            description=(
                f"Found **{len(missing_roles)}** missing role(s):\n\n"
                f"{role_list}\n\n"
                f"Recreating now... (positions may differ from original)"
            ),
            color=discord.Color.orange(),
        )
        confirm_embed.set_footer(
            text=f"Snapshot from: {snapshot.get('_created_at', 'unknown')}"
        )
        status_msg = await ctx.send(embed=confirm_embed)

        # Recreate missing roles (sorted by position, lowest first)
        missing_roles.sort(key=lambda r: r["position"])
        restored = []
        failed = []

        for role_data in missing_roles:
            try:
                new_role = await ctx.guild.create_role(
                    name=role_data["name"],
                    color=discord.Color(role_data["color"]),
                    permissions=discord.Permissions(role_data["permissions"]),
                    hoist=role_data.get("hoist", False),
                    mentionable=role_data.get("mentionable", False),
                    reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                )
                restored.append(new_role.name)
            except discord.Forbidden:
                failed.append(role_data["name"])
            except discord.HTTPException as e:
                failed.append(f"{role_data['name']} ({e})")

            # M-3 fix: avoid Discord API rate limits
            await asyncio.sleep(0.5)

        # Result embed
        result_embed = discord.Embed(
            title="🔄 Role Restoration Complete",
            color=discord.Color.green() if not failed else discord.Color.orange(),
        )
        if restored:
            result_embed.add_field(
                name=f"✅ Restored ({len(restored)})",
                value="\n".join(f"• `{r}`" for r in restored[:25]),
                inline=False,
            )
        if failed:
            result_embed.add_field(
                name=f"❌ Failed ({len(failed)})",
                value="\n".join(f"• `{r}`" for r in failed[:25]),
                inline=False,
            )
        result_embed.set_footer(
            text=f"Triggered by {ctx.author}",
            icon_url=ctx.author.display_avatar.url,
        )
        await status_msg.edit(embed=result_embed)

        # Audit log
        if self.bot.db.pool:
            await insert_audit_log(
                pool=self.bot.db.pool,
                guild_id=ctx.guild.id,
                actor_id=ctx.author.id,
                target_id=None,
                action_type="RESTORE_ROLES",
                details={
                    "restored": restored,
                    "failed": failed,
                    "total_missing": len(missing_roles),
                },
                severity="WARN",
            )

        logger.info(
            f"🔄 Role restore in {ctx.guild.name}: "
            f"{len(restored)} restored, {len(failed)} failed"
        )

    # ══════════════════════════════════════════════════════════════
    #  !restore-channels — Recreate missing channels from snapshot
    # ══════════════════════════════════════════════════════════════

    @commands.command(
        name="restore-channels",
        aliases=["restorechannels"],
        help="Restore missing channels from the latest server snapshot.",
    )
    @is_staff()
    async def restore_channels(self, ctx: commands.Context) -> None:
        """Recreate channels that exist in the snapshot but are missing from the guild."""
        if not self.bot.db.pool:
            await ctx.send("❌ Database is not connected.")
            return

        snapshot = await self._get_latest_snapshot(ctx.guild.id)
        if not snapshot:
            await ctx.send(
                embed=discord.Embed(
                    title="❌ No Snapshot Found",
                    description=(
                        f"No snapshot exists for this server. "
                        f"Run `{ctx.prefix}snapshot-now` first."
                    ),
                    color=discord.Color.red(),
                )
            )
            return

        # Compare snapshot channels against current guild channels
        current_channel_ids = {c.id for c in ctx.guild.channels}
        saved_channels = snapshot.get("channels", [])
        missing_channels = [c for c in saved_channels if c["id"] not in current_channel_ids]

        if not missing_channels:
            await ctx.send(
                embed=discord.Embed(
                    title="✅ All Channels Present",
                    description="No missing channels detected — your server matches the snapshot.",
                    color=discord.Color.green(),
                )
            )
            return

        # Warning + confirmation
        channel_list = "\n".join(
            f"• `#{c['name']}` ({c['type']})"
            for c in missing_channels[:20]
        )
        confirm_embed = discord.Embed(
            title="🔄 Restore Channels?",
            description=(
                f"Found **{len(missing_channels)}** missing channel(s):\n\n"
                f"{channel_list}\n\n"
                f"⚠️ **Warning:** Restored channels will be empty — "
                f"message history **cannot** be recovered.\n\n"
                f"Recreating now..."
            ),
            color=discord.Color.orange(),
        )
        confirm_embed.set_footer(
            text=f"Snapshot from: {snapshot.get('_created_at', 'unknown')}"
        )
        status_msg = await ctx.send(embed=confirm_embed)

        # Build a map of current categories by name for matching
        category_map: dict[str, discord.CategoryChannel] = {
            c.name: c for c in ctx.guild.categories
        }

        # Recreate missing channels
        restored = []
        failed = []

        for ch_data in missing_channels:
            try:
                # Find the parent category
                category = None
                if ch_data.get("category_name"):
                    category = category_map.get(ch_data["category_name"])

                # Rebuild permission overwrites
                overwrites = {}
                for ow in ch_data.get("overwrites", []):
                    if ow["target_type"] == "role":
                        target = ctx.guild.get_role(ow["target_id"])
                    else:
                        target = ctx.guild.get_member(ow["target_id"])

                    if target:
                        overwrites[target] = discord.PermissionOverwrite.from_pair(
                            discord.Permissions(ow["allow"]),
                            discord.Permissions(ow["deny"]),
                        )

                ch_type = ch_data["type"]

                if ch_type == "text":
                    new_ch = await ctx.guild.create_text_channel(
                        name=ch_data["name"],
                        category=category,
                        topic=ch_data.get("topic"),
                        nsfw=ch_data.get("nsfw", False),
                        slowmode_delay=ch_data.get("slowmode_delay", 0),
                        overwrites=overwrites,
                        reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                    )
                    restored.append(f"#{new_ch.name}")

                elif ch_type == "voice":
                    new_ch = await ctx.guild.create_voice_channel(
                        name=ch_data["name"],
                        category=category,
                        bitrate=ch_data.get("bitrate", 64000),
                        user_limit=ch_data.get("user_limit", 0),
                        overwrites=overwrites,
                        reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                    )
                    restored.append(f"🔊 {new_ch.name}")

                elif ch_type == "category":
                    new_cat = await ctx.guild.create_category(
                        name=ch_data["name"],
                        overwrites=overwrites,
                        reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                    )
                    # Update the category map so child channels can find it
                    category_map[new_cat.name] = new_cat
                    restored.append(f"📁 {new_cat.name}")

                elif ch_type == "stage_voice":
                    new_ch = await ctx.guild.create_stage_channel(
                        name=ch_data["name"],
                        category=category,
                        overwrites=overwrites,
                        reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                    )
                    restored.append(f"🎙️ {new_ch.name}")

                elif ch_type == "forum":
                    new_ch = await ctx.guild.create_forum(
                        name=ch_data["name"],
                        category=category,
                        overwrites=overwrites,
                        reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                    )
                    restored.append(f"💬 {new_ch.name}")

                else:
                    # Unknown channel type — try as text
                    new_ch = await ctx.guild.create_text_channel(
                        name=ch_data["name"],
                        category=category,
                        overwrites=overwrites,
                        reason=f"[AntiRaid] Restored from snapshot by {ctx.author}",
                    )
                    restored.append(f"#{new_ch.name}")

            except discord.Forbidden:
                failed.append(ch_data["name"])
            except discord.HTTPException as e:
                failed.append(f"{ch_data['name']} ({e})")

            # M-3 fix: avoid Discord API rate limits
            await asyncio.sleep(0.5)

        # Result embed
        result_embed = discord.Embed(
            title="🔄 Channel Restoration Complete",
            color=discord.Color.green() if not failed else discord.Color.orange(),
        )
        if restored:
            result_embed.add_field(
                name=f"✅ Restored ({len(restored)})",
                value="\n".join(f"• {c}" for c in restored[:25]),
                inline=False,
            )
        if failed:
            result_embed.add_field(
                name=f"❌ Failed ({len(failed)})",
                value="\n".join(f"• `{c}`" for c in failed[:25]),
                inline=False,
            )
        result_embed.add_field(
            name="⚠️ Important",
            value="Message history from deleted channels **cannot** be recovered.",
            inline=False,
        )
        result_embed.set_footer(
            text=f"Triggered by {ctx.author}",
            icon_url=ctx.author.display_avatar.url,
        )
        await status_msg.edit(embed=result_embed)

        # Audit log
        if self.bot.db.pool:
            await insert_audit_log(
                pool=self.bot.db.pool,
                guild_id=ctx.guild.id,
                actor_id=ctx.author.id,
                target_id=None,
                action_type="RESTORE_CHANNELS",
                details={
                    "restored": restored,
                    "failed": failed,
                    "total_missing": len(missing_channels),
                },
                severity="WARN",
            )

        logger.info(
            f"🔄 Channel restore in {ctx.guild.name}: "
            f"{len(restored)} restored, {len(failed)} failed"
        )

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
