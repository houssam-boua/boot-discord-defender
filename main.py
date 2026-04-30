# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Main Entry Point
#  Enterprise-grade Discord SOC Bot
#
#  Initializes:
#    • discord.ext.commands.Bot with all Privileged Gateway Intents
#    • asyncpg connection pool to Supabase PostgreSQL
#    • Redis connection for rate limiting / caching
#    • Dynamic Cog loading from the cogs/ directory
#
#  The database pool and Redis client are attached directly to the
#  bot instance so every Cog can access them via self.bot.db / self.bot.redis
# ══════════════════════════════════════════════════════════════════

import asyncio
import logging
import sys
from pathlib import Path

import discord
from discord.ext import commands

import redis.asyncio as aioredis

from config import Config
from database.connection import Database

# ── Logging Setup ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("antiraid")

# L-3 fix: Security-critical cogs — if any fail to load,
# the bot owner is notified via DM on startup.
CRITICAL_COGS = {"cogs.antinuke", "cogs.antispam", "cogs.verification"}


# ── Per-Guild Dynamic Prefix ──────────────────────────────────
# Fetches the custom prefix from PostgreSQL (server_configs table).
# Falls back to DEFAULT_PREFIX if the guild hasn't configured one.
async def get_prefix(bot: commands.Bot, message: discord.Message) -> str:
    if not message.guild:
        return Config.DEFAULT_PREFIX

    # Try cache first (avoids a DB query on every message)
    cached = bot.prefix_cache.get(message.guild.id)
    if cached:
        return cached

    # Fetch from database
    if bot.db.pool:
        row = await bot.db.pool.fetchrow(
            "SELECT prefix FROM server_configs WHERE guild_id = $1",
            message.guild.id,
        )
        if row:
            bot.prefix_cache[message.guild.id] = row["prefix"]
            return row["prefix"]

    return Config.DEFAULT_PREFIX


# ── Bot Subclass ──────────────────────────────────────────────
class AntiRaidBot(commands.Bot):
    """
    Custom Bot subclass that holds shared resources:
      • self.db       — Database wrapper (asyncpg pool)
      • self.redis    — Redis async client
      • self.prefix_cache — in-memory guild prefix cache
    """

    def __init__(self) -> None:
        # Enable ALL Privileged Gateway Intents
        intents = discord.Intents.all()

        super().__init__(
            command_prefix=get_prefix,
            intents=intents,
            help_command=commands.DefaultHelpCommand(),
            case_insensitive=True,
            owner_ids=set(),  # Populated from Discord application info
        )

        # Shared resources — initialized in setup_hook
        self.db = Database()
        self.redis: aioredis.Redis | None = None
        self.prefix_cache: dict[int, str] = {}
        self._ready_fired: bool = False
        self.failed_cogs: list[str] = []  # L-3 fix: tracked for owner alert

    async def setup_hook(self) -> None:
        """
        Called once when the bot starts, before connecting to the Gateway.
        Establishes all external connections and loads Cogs.
        """
        logger.info("🚀 Running setup_hook — initializing services...")

        # ── 1. Connect to PostgreSQL (Supabase) ───────────────
        try:
            await self.db.connect(
                dsn=Config.DATABASE_URL,
                min_size=Config.DB_MIN_CONNECTIONS,
                max_size=Config.DB_MAX_CONNECTIONS,
            )
        except ConnectionError:
            logger.critical("Cannot start without database. Exiting.")
            await self.close()
            return

        # ── 2. Connect to Redis ────────────────────────────────
        try:
            self.redis = aioredis.from_url(
                Config.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=5,
            )
            await self.redis.ping()
            logger.info("✅ Redis connection established.")
        except Exception as e:
            logger.warning(
                f"⚠️ Redis connection failed: {e} — "
                "rate limiting features will be unavailable."
            )
            self.redis = None

        # ── 3. Load link scanner cache from DB ─────────────────
        try:
            from services.linkscanner import load_cache_from_db
            await load_cache_from_db(self.db.pool)
        except Exception as e:
            logger.warning(f"⚠️ Link scanner cache load failed: {e}")

        # ── 4. Start punishment scheduler ──────────────────────
        try:
            from services.punishment_scheduler import start_scheduler
            start_scheduler(self)
        except Exception as e:
            logger.warning(f"⚠️ Punishment scheduler failed to start: {e}")

        # ── 4b. Recover punishments from previous session ──────
        try:
            from services.punishment_scheduler import recover_punishments_on_boot
            await recover_punishments_on_boot(self)
        except Exception as e:
            logger.warning(f"⚠️ Punishment recovery failed: {e}")

        # ── 5. Load all Cogs dynamically ───────────────────────
        await self._load_cogs()

        logger.info("✅ setup_hook complete — ready to connect to Gateway.")

    async def _load_cogs(self) -> None:
        """
        Dynamically discover and load all .py Cog files from the cogs/ directory.
        Skips __init__.py and files that don't define a proper Cog yet.
        """
        cogs_dir = Path(__file__).parent / "cogs"
        self.failed_cogs = []  # L-3 fix: reset on each load

        for cog_file in sorted(cogs_dir.glob("*.py")):
            if cog_file.name.startswith("__"):
                continue

            cog_module = f"cogs.{cog_file.stem}"
            try:
                await self.load_extension(cog_module)
                logger.info(f"  ✅ Loaded cog: {cog_module}")
            except commands.errors.NoEntryPointError:
                # Cog file exists but has no setup() function yet — skip silently
                logger.debug(f"  ⏭️  Skipped {cog_module} (no setup function)")
            except Exception as e:
                logger.error(f"  ❌ Failed to load {cog_module}: {e}")
                # L-3 fix: track critical cog failures for owner alert
                if cog_module in CRITICAL_COGS:
                    self.failed_cogs.append(cog_module)

    async def on_ready(self) -> None:
        """Fired when the bot connects/reconnects to Discord."""
        # ── Guard: on_ready fires on EVERY gateway reconnect ──
        if self._ready_fired:
            logger.info(
                f"🔄 Gateway reconnected — {self.user} "
                f"(Guilds: {len(self.guilds)}, Latency: {round(self.latency * 1000)}ms)"
            )
            return

        self._ready_fired = True

        logger.info(
            f"\n{'═' * 50}\n"
            f"  🛡️  AntiRaid Bot is ONLINE\n"
            f"{'═' * 50}\n"
            f"  User     : {self.user} (ID: {self.user.id})\n"
            f"  Guilds   : {len(self.guilds)}\n"
            f"  Latency  : {round(self.latency * 1000)}ms\n"
            f"  Prefix   : {Config.DEFAULT_PREFIX}\n"
            f"{'═' * 50}"
        )

        # Set the bot's status
        activity = discord.Activity(
            type=discord.ActivityType.watching,
            name=f"{len(self.guilds)} servers | {Config.DEFAULT_PREFIX}help",
        )
        await self.change_presence(
            status=discord.Status.online,
            activity=activity,
        )

        # L-3 fix: DM the bot owner if critical security cogs failed to load
        if self.failed_cogs:
            logger.critical(
                f"🚨 CRITICAL COGS FAILED TO LOAD: {', '.join(self.failed_cogs)}"
            )
            try:
                app_info = await self.application_info()
                owner = app_info.owner
                if owner:
                    failed_list = "\n".join(f"• `{c}`" for c in self.failed_cogs)
                    embed = discord.Embed(
                        title="🚨 CRITICAL — Security Cogs Failed to Load",
                        description=(
                            f"The following **security-critical** cogs failed to load "
                            f"on startup. Your server(s) may be **unprotected**.\n\n"
                            f"{failed_list}\n\n"
                            f"Check the Railway/console logs for the full error traceback."
                        ),
                        color=discord.Color.dark_red(),
                    )
                    embed.set_footer(text="AntiRaid Security Bot — Automated Alert")
                    await owner.send(embed=embed)
                    logger.info("📩 Critical cog failure alert sent to bot owner.")
            except Exception as e:
                logger.warning(f"Could not DM owner about failed cogs: {e}")

    async def close(self) -> None:
        """Graceful shutdown — close all external connections."""
        logger.info("🔌 Shutting down — closing connections...")

        # Stop punishment scheduler
        try:
            from services.punishment_scheduler import stop_scheduler
            stop_scheduler()
        except Exception:
            pass

        # H-3 fix: close the singleton aiohttp session
        try:
            from services.linkscanner import close_session
            await close_session()
        except Exception:
            pass

        # Close Redis
        if self.redis:
            await self.redis.close()
            logger.info("  ✅ Redis closed.")

        # Close PostgreSQL pool
        await self.db.close()

        # Close Discord gateway
        await super().close()
        logger.info("  ✅ Bot fully shut down.")


# ── Entry Point ───────────────────────────────────────────────
def main() -> None:
    """Validate config, then launch the bot."""
    # Validate environment variables before anything else
    Config.validate()
    Config.display()

    # Create and run the bot
    bot = AntiRaidBot()

    try:
        bot.run(
            Config.DISCORD_TOKEN,
            log_handler=None,  # We handle logging ourselves
        )
    except discord.LoginFailure:
        logger.critical(
            "❌ INVALID DISCORD_TOKEN — "
            "check your .env file or Railway dashboard."
        )
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt — shutting down.")


if __name__ == "__main__":
    main()
