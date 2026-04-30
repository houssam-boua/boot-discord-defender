# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Permission Guards
#  Custom command checks for admin-only access control.
#
#  Current implementation: Discord Administrator permission check.
#  Future: Will add DB-backed role whitelists (Phase 2).
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands


class NotStaff(commands.CheckFailure):
    """
    Custom exception raised when a non-admin user tries to invoke
    a staff-only command. Allows the error handler to send a clean
    denial message instead of a generic error.
    """

    def __init__(self, message: str = "You do not have permission to use this command."):
        self.message = message
        super().__init__(self.message)


def is_staff():
    """
    Command decorator that restricts access to Discord Administrators.

    Usage:
        @commands.command()
        @is_staff()
        async def my_command(self, ctx):
            ...

    Checks (in order):
        1. Command must be used inside a guild (not DMs).
        2. Server owner always passes.
        3. User must have the Discord "Administrator" permission.

    Raises:
        NotStaff: If the user fails all checks.

    Future enhancement:
        - Check against a DB-stored list of authorized role IDs
          per guild (whitelists table, entity_type = 'role').
    """

    async def predicate(ctx: commands.Context) -> bool:
        # ── Block DM usage ─────────────────────────────────────
        if not ctx.guild:
            raise NotStaff("⚠️ This command can only be used inside a server.")

        author = ctx.author

        # ── Server owner always passes ─────────────────────────
        if author.id == ctx.guild.owner_id:
            return True

        # ── Check Discord Administrator permission ─────────────
        if isinstance(author, discord.Member) and author.guild_permissions.administrator:
            return True

        # ── Denied ─────────────────────────────────────────────
        raise NotStaff(
            "🔒 **Access Denied** — This command requires **Administrator** permissions."
        )

    return commands.check(predicate)
