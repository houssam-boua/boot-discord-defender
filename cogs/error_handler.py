# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Global Error Handler
#  Catches all unhandled command errors and sends clean,
#  user-friendly embeds instead of raw tracebacks.
#
#  Handled errors:
#    • NotStaff (custom)         — "You lack admin access."
#    • MissingRequiredArgument   — Shows which arg is missing + usage
#    • BadArgument               — Invalid argument type/format
#    • CommandNotFound           — Silently ignored
#    • BotMissingPermissions     — Lists what perms the bot needs
#    • CommandOnCooldown         — Shows retry time
#    • MemberNotFound            — User not found in server
#    • Unexpected                — Logged + generic message
# ══════════════════════════════════════════════════════════════════

import discord
from discord.ext import commands

import logging
import traceback

from utils.permissions import NotStaff

logger = logging.getLogger("antiraid.errors")


class ErrorHandler(commands.Cog, name="⚠️ Error Handler"):
    """
    Global error handler — catches all command errors that were
    not already handled by a per-cog error handler.
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.Cog.listener()
    async def on_command_error(
        self, ctx: commands.Context, error: commands.CommandError
    ) -> None:
        """
        Centralized error handler for all commands.
        Per-cog handlers take priority — this only fires for
        errors that were NOT caught by a local handler.
        """

        # ── Skip if the cog already handled it ─────────────────
        if hasattr(ctx.command, "on_error"):
            return

        # Unwrap the original exception if wrapped by CommandInvokeError
        if isinstance(error, commands.CommandInvokeError):
            error = error.original

        # ══════════════════════════════════════════════════════════
        #  1. CommandNotFound — Silently ignore
        # ══════════════════════════════════════════════════════════

        if isinstance(error, commands.CommandNotFound):
            return  # Don't spam the chat for typos

        # ══════════════════════════════════════════════════════════
        #  2. NotStaff — Custom permission denial
        # ══════════════════════════════════════════════════════════

        if isinstance(error, NotStaff):
            embed = discord.Embed(
                title="🔒 Access Denied",
                description=error.message,
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed, delete_after=15)
            return

        # ══════════════════════════════════════════════════════════
        #  3. CheckFailure — Generic check failure (non-NotStaff)
        # ══════════════════════════════════════════════════════════

        if isinstance(error, commands.CheckFailure):
            embed = discord.Embed(
                title="🔒 Permission Check Failed",
                description="You do not have the required permissions to run this command.",
                color=discord.Color.red(),
            )
            await ctx.send(embed=embed, delete_after=15)
            return

        # ══════════════════════════════════════════════════════════
        #  4. MissingRequiredArgument
        # ══════════════════════════════════════════════════════════

        if isinstance(error, commands.MissingRequiredArgument):
            usage = ctx.command.usage or ""
            embed = discord.Embed(
                title="❌ Missing Argument",
                description=(
                    f"You're missing the **`{error.param.name}`** argument.\n\n"
                    f"**Usage:**\n"
                    f"```{ctx.prefix}{ctx.command.qualified_name} {usage}```"
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        # ══════════════════════════════════════════════════════════
        #  5. BadArgument / MemberNotFound / etc.
        # ══════════════════════════════════════════════════════════

        if isinstance(error, commands.MemberNotFound):
            embed = discord.Embed(
                title="❌ Member Not Found",
                description=(
                    f"Could not find member **`{error.argument}`** in this server.\n"
                    f"Make sure you're mentioning them or using their exact name."
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        if isinstance(error, commands.BadArgument):
            usage = ctx.command.usage or ""
            embed = discord.Embed(
                title="❌ Invalid Argument",
                description=(
                    f"One of your arguments is the wrong type or format.\n\n"
                    f"**Usage:**\n"
                    f"```{ctx.prefix}{ctx.command.qualified_name} {usage}```"
                ),
                color=discord.Color.orange(),
            )
            await ctx.send(embed=embed)
            return

        # ══════════════════════════════════════════════════════════
        #  6. BotMissingPermissions
        # ══════════════════════════════════════════════════════════

        if isinstance(error, commands.BotMissingPermissions):
            missing = ", ".join(
                f"`{p.replace('_', ' ').title()}`"
                for p in error.missing_permissions
            )
            embed = discord.Embed(
                title="⚠️ Bot Missing Permissions",
                description=(
                    f"I need the following permissions to run this command:\n\n"
                    f"{missing}\n\n"
                    f"Please update my role permissions and try again."
                ),
                color=discord.Color.dark_orange(),
            )
            await ctx.send(embed=embed)
            return

        # ══════════════════════════════════════════════════════════
        #  7. CommandOnCooldown
        # ══════════════════════════════════════════════════════════

        if isinstance(error, commands.CommandOnCooldown):
            embed = discord.Embed(
                title="⏳ Cooldown Active",
                description=(
                    f"This command is on cooldown.\n"
                    f"Try again in **{error.retry_after:.1f}** seconds."
                ),
                color=discord.Color.greyple(),
            )
            await ctx.send(embed=embed, delete_after=error.retry_after)
            return

        # ══════════════════════════════════════════════════════════
        #  8. Unhandled — Log and show generic message
        # ══════════════════════════════════════════════════════════

        logger.error(
            f"Unhandled error in command '{ctx.command}' "
            f"invoked by {ctx.author} ({ctx.author.id}) "
            f"in #{ctx.channel} ({ctx.guild}): {error}",
            exc_info=error,
        )

        embed = discord.Embed(
            title="⚠️ Unexpected Error",
            description=(
                "An unexpected error occurred while running this command.\n"
                "The error has been logged and will be investigated.\n\n"
                "If this persists, please contact the bot administrator."
            ),
            color=discord.Color.dark_red(),
        )
        embed.set_footer(
            text=f"Command: {ctx.prefix}{ctx.command or 'unknown'}"
        )

        try:
            await ctx.send(embed=embed)
        except discord.Forbidden:
            pass  # Can't even send messages — nothing we can do


# ── Cog Setup ─────────────────────────────────────────────────
async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ErrorHandler(bot))
