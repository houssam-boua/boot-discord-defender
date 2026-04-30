# ══════════════════════════════════════════════════════════════════
#  AntiRaid Security Bot — Database Migration Runner
#  ─────────────────────────────────────────────────────────────────
#  Reads all numbered .sql files from database/migrations/ and
#  executes them in order against the Supabase PostgreSQL instance.
#
#  Usage:
#      cd bot/
#      python run_migrations.py
#
#  The script loads DATABASE_URL from your .env file automatically.
#  All migrations use IF NOT EXISTS — safe to run multiple times.
# ══════════════════════════════════════════════════════════════════

import asyncio
import sys
import time
import io
from pathlib import Path

import asyncpg
from dotenv import load_dotenv
import os

# ── Fix Windows console encoding (cp1252 → UTF-8) ─────────────
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ── Constants ──────────────────────────────────────────────────
MIGRATIONS_DIR = Path(__file__).parent / "database" / "migrations"
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           🛡️  AntiRaid — Database Migration Runner           ║
╚══════════════════════════════════════════════════════════════╝
"""


def get_migration_files() -> list[Path]:
    """
    Discover all numbered .sql migration files and return them sorted.
    Only picks up files matching the pattern: NNN_*.sql (e.g., 001_initial_schema.sql).
    Skips utility files like supabase_setup.sql.
    """
    files = sorted(
        f for f in MIGRATIONS_DIR.glob("*.sql")
        if f.name[0].isdigit()
    )
    return files


async def run_migrations() -> None:
    """Connect to PostgreSQL and execute all migration files in order."""

    print(BANNER)

    # ── Load environment ───────────────────────────────────────
    env_path = Path(__file__).parent / ".env"
    load_dotenv(dotenv_path=env_path)
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        print("  ❌ FATAL: DATABASE_URL not found in .env file.")
        print("     Make sure your .env file exists and contains DATABASE_URL.")
        sys.exit(1)

    # Mask the URL for display (show host only)
    try:
        host_part = database_url.split("@")[1].split("/")[0]
        print(f"  📡 Target: ...@{host_part}")
    except IndexError:
        print(f"  📡 Target: (custom DSN)")

    # ── Discover migration files ───────────────────────────────
    migration_files = get_migration_files()

    if not migration_files:
        print(f"\n  ⚠️  No migration files found in: {MIGRATIONS_DIR}")
        print("     Expected files like: 001_initial_schema.sql, 002_audit_logs.sql")
        sys.exit(1)

    print(f"  📂 Found {len(migration_files)} migration(s):\n")
    for f in migration_files:
        print(f"     • {f.name}")

    # ── Connect to database ────────────────────────────────────
    print(f"\n{'─' * 60}")
    print("  🔌 Connecting to PostgreSQL...")

    conn = None

    # Try direct connection first
    try:
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        conn = await asyncpg.connect(dsn=database_url, timeout=15, ssl=ssl_ctx)

    except OSError as e:
        # DNS or network error on direct host — try the Supabase pooler
        print(f"  ⚠️  Direct connection failed ({e})")
        print("  🔄 Trying Supabase connection pooler (IPv4)...")

        try:
            # Extract project ref from: db.<project_ref>.supabase.co
            import re
            match = re.search(r"@db\.([a-z0-9]+)\.supabase\.co", database_url)
            if match:
                project_ref = match.group(1)

                # Detect region by resolving the pooler
                # Default Supabase pooler pattern:
                #   postgresql://postgres.<ref>:<pass>@aws-0-<region>.pooler.supabase.com:6543/postgres
                # We rewrite the URL to use the pooler
                pooler_url = database_url.replace(
                    f"@db.{project_ref}.supabase.co:5432",
                    f"@aws-0-eu-west-3.pooler.supabase.com:6543"
                ).replace(
                    "postgres:",           # user without project ref
                    f"postgres.{project_ref}:",  # user with project ref
                    1  # only first occurrence
                )

                try:
                    pooler_host = pooler_url.split("@")[1].split("/")[0]
                    print(f"  📡 Pooler: ...@{pooler_host}")
                except IndexError:
                    pass

                conn = await asyncpg.connect(dsn=pooler_url, timeout=15, ssl=ssl_ctx)
            else:
                print("  ❌ Could not extract project ref from DATABASE_URL.")
                print("     Expected format: postgresql://...@db.<ref>.supabase.co:5432/postgres")
                sys.exit(1)

        except asyncpg.InvalidPasswordError:
            print("  ❌ Authentication failed — check your DATABASE_URL password.")
            sys.exit(1)
        except Exception as e2:
            print(f"  ❌ Pooler connection also failed: {e2}")
            print("\n  💡 TIP: Go to Supabase Dashboard → Project Settings → Database")
            print("     Copy the 'Connection Pooling' URI (Session mode) and use that as DATABASE_URL.")
            sys.exit(1)

    except asyncpg.InvalidPasswordError:
        print("  ❌ Authentication failed — check your DATABASE_URL password.")
        sys.exit(1)
    except Exception as e:
        print(f"  ❌ Connection failed: {e}")
        sys.exit(1)

    print("  ✅ Connected!\n")

    # ── Execute migrations ─────────────────────────────────────
    success_count = 0
    failed_count = 0
    total_start = time.perf_counter()

    for migration_file in migration_files:
        file_start = time.perf_counter()
        filename = migration_file.name

        print(f"  ▶ Running: {filename}...", end=" ", flush=True)

        try:
            sql = migration_file.read_text(encoding="utf-8")

            # Execute the entire file as a single transaction
            async with conn.transaction():
                await conn.execute(sql)

            elapsed = (time.perf_counter() - file_start) * 1000
            print(f"✅ ({elapsed:.0f}ms)")
            success_count += 1

        except asyncpg.DuplicateTableError:
            # Table already exists (shouldn't happen with IF NOT EXISTS, but just in case)
            print(f"⏭️  Already exists (skipped)")
            success_count += 1

        except Exception as e:
            print(f"❌ FAILED")
            print(f"     Error: {e}")
            failed_count += 1

    # ── Summary ────────────────────────────────────────────────
    total_elapsed = (time.perf_counter() - total_start) * 1000

    print(f"\n{'─' * 60}")
    print(f"  📊 Migration Summary:")
    print(f"     ✅ Succeeded : {success_count}")
    if failed_count:
        print(f"     ❌ Failed    : {failed_count}")
    print(f"     ⏱️  Total time: {total_elapsed:.0f}ms")

    # ── Verify tables were created ─────────────────────────────
    print(f"\n{'─' * 60}")
    print("  🔍 Verifying tables...\n")

    rows = await conn.fetch(
        """
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
        ORDER BY tablename
        """
    )

    expected_tables = {
        "server_configs",
        "whitelists",
        "malicious_links",
        "temporal_punishments",
        "audit_logs",
        "risk_scores",
        "server_snapshots",
    }

    existing_tables = {row["tablename"] for row in rows}

    for table in sorted(expected_tables):
        status = "✅" if table in existing_tables else "❌ MISSING"
        print(f"     {status}  {table}")

    # Check for any extra tables
    extra = existing_tables - expected_tables
    if extra:
        print(f"\n     ℹ️  Other tables in schema: {', '.join(sorted(extra))}")

    # ── Cleanup ────────────────────────────────────────────────
    await conn.close()

    if failed_count:
        print(f"\n  ⚠️  {failed_count} migration(s) failed. Check the errors above.")
        sys.exit(1)
    else:
        print(f"\n  🎉 All migrations applied successfully! Database is ready.")


# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    try:
        asyncio.run(run_migrations())
    except KeyboardInterrupt:
        print("\n  Cancelled by user.")
