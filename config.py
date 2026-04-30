# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Configuration
#  Loads all environment variables from .env file securely.
#  Validates that critical variables are present at startup.
# ══════════════════════════════════════════════════════════════════

import os
import sys
from dotenv import load_dotenv

# Load .env file (ignored in production — Railway injects vars directly)
load_dotenv()


class Config:
    """
    Centralized configuration loaded from environment variables.
    Raises SystemExit immediately if any critical variable is missing,
    preventing the bot from starting in a broken state.
    """

    # ── Discord ────────────────────────────────────────────────
    DISCORD_TOKEN: str = os.getenv("DISCORD_TOKEN", "")

    # ── Database (Supabase PostgreSQL) ─────────────────────────
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")

    # ── Cache (Redis) ──────────────────────────────────────────
    REDIS_URL: str = os.getenv("REDIS_URL", "")

    # ── External APIs ──────────────────────────────────────────
    PROXYCHECK_API_KEY: str = os.getenv("PROXYCHECK_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # ── Bot Defaults ───────────────────────────────────────────
    DEFAULT_PREFIX: str = os.getenv("DEFAULT_PREFIX", "!")

    # ── Database Pool Settings ─────────────────────────────────
    DB_MIN_CONNECTIONS: int = int(os.getenv("DB_MIN_CONNECTIONS", "5"))
    DB_MAX_CONNECTIONS: int = int(os.getenv("DB_MAX_CONNECTIONS", "20"))

    @classmethod
    def validate(cls) -> None:
        """
        Validate that all critical environment variables are set.
        Called once at startup before any connections are made.
        """
        missing: list[str] = []

        if not cls.DISCORD_TOKEN:
            missing.append("DISCORD_TOKEN")
        if not cls.DATABASE_URL:
            missing.append("DATABASE_URL")
        if not cls.REDIS_URL:
            missing.append("REDIS_URL")

        if missing:
            print(
                f"\n{'=' * 60}\n"
                f"  ❌ FATAL: Missing required environment variables:\n"
                f"     {', '.join(missing)}\n"
                f"\n"
                f"  Copy .env.example → .env and fill in your values.\n"
                f"{'=' * 60}\n"
            )
            sys.exit(1)

    @classmethod
    def display(cls) -> None:
        """Print a sanitized config summary for startup diagnostics."""
        def mask(value: str) -> str:
            if not value:
                return "❌ NOT SET"
            return value[:6] + "..." + value[-4:] if len(value) > 12 else "****"

        print(
            f"\n{'═' * 50}\n"
            f"  🛡️  AntiRaid Bot — Configuration\n"
            f"{'═' * 50}\n"
            f"  DISCORD_TOKEN    : {mask(cls.DISCORD_TOKEN)}\n"
            f"  DATABASE_URL     : {mask(cls.DATABASE_URL)}\n"
            f"  REDIS_URL        : {mask(cls.REDIS_URL)}\n"
            f"  PROXYCHECK_KEY   : {mask(cls.PROXYCHECK_API_KEY)}\n"
            f"  VIRUSTOTAL_KEY   : {mask(cls.VIRUSTOTAL_API_KEY)}\n"
            f"  DEFAULT_PREFIX   : {cls.DEFAULT_PREFIX}\n"
            f"  DB_POOL          : {cls.DB_MIN_CONNECTIONS}–{cls.DB_MAX_CONNECTIONS} connections\n"
            f"{'═' * 50}\n"
        )
