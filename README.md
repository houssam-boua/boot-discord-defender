<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/discord.py-2.3+-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="discord.py">
  <img src="https://img.shields.io/badge/PostgreSQL-Supabase-3FCF8E?style=for-the-badge&logo=supabase&logoColor=white" alt="Supabase">
  <img src="https://img.shields.io/badge/Redis-Async-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis">
  <img src="https://img.shields.io/badge/Railway-Deploy-0B0D0E?style=for-the-badge&logo=railway&logoColor=white" alt="Railway">
</p>

<h1 align="center">🛡️ AntiRaid — Enterprise Discord Security Bot</h1>

<p align="center">
  <strong>A miniature SOC (Security Operations Center) embedded inside Discord.</strong><br>
  Tamper-proof audit logs · Hybrid anti-nuke detection · Automated raid defense · CAPTCHA verification
</p>

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Setup & Installation](#setup--installation)
- [Database Migration](#database-migration)
- [Command Reference](#command-reference)
- [Event Listeners](#event-listeners)
- [Security Patterns](#security-patterns)
- [Deployment (Railway)](#deployment-railway)
- [Future Enhancements](#future-enhancements)
- [License](#license)

---

## Overview

AntiRaid is **not** a simple moderation bot — it is an enterprise-grade Discord security platform that provides layered, automated defenses against:

| Threat | Defense |
|---|---|
| **Raid attacks** | Join-spike detection → auto-lockdown |
| **Nuke attacks** | Audit-log-attributed mass-action detection → role strip |
| **Phishing & malware** | 27+ seeded domains · O(1) in-memory cache |
| **Account compromises** | Mass-ban/kick rate tracking per admin |
| **Alt-account infiltration** | Account age + avatar checks + CAPTCHA |
| **Log tampering** | SHA-256 hash-chained audit trail |

All configuration is done via **prefix commands** accessible exclusively to authorized administrators. No web dashboard required — the entire SOC operates within Discord.

---

## Key Features

### 🔐 Tamper-Proof Audit Logging (Module 5)
Every event generates an immutable database record linked to the previous record via SHA-256 hash chaining. If any historical row is modified or deleted, the chain breaks — detectable on demand with `!verify-integrity`.

```
GENESIS → SHA256(prev + data₁) → SHA256(prev + data₂) → ... → current
```

### 🛡️ Hybrid Anti-Nuke Detection (Module 3)
Combines **real-time Discord events** with **Audit Log verification** for both speed and attribution accuracy:

```
Real-time Events              +    Audit Log Verification
─────────────────                  ──────────────────────
on_guild_channel_delete            Who performed the action?
on_member_ban                      Timestamp accuracy check
on_member_remove                   Cross-reference actor ID
on_guild_role_delete
on_member_join (bot)
```

When an admin exceeds the configured threshold (e.g., 3 bans in 10 seconds), their roles are **immediately stripped** and the incident is logged as `CRITICAL`.

### 🚨 Automated Raid Defense (Module 4)
Redis-backed join velocity tracking triggers automatic server lockdown:

```
10 joins in 3 seconds → AUTO-LOCKDOWN
  ├── Snapshot @everyone permissions → Redis (7-day TTL)
  ├── Set send_messages = False on all text channels
  ├── Log to audit_logs (CRITICAL severity)
  └── @here alert in log channel
```

Use `!unlockdown` to restore — works for both manual and automatic lockdowns.

### 🔑 CAPTCHA Verification (Module 1)
- **DM-first flow** with fallback to a `#verify-here` channel
- Pillow-generated image CAPTCHAs with noise lines, character rotation, and blur
- Alt-account detection: account age < N hours → auto-kick
- Default avatar → flagged for staff review

### ⚡ Anti-Spam Engine (Module 2)
Four-layer message scanning on every incoming message:

1. **Zalgo text** — Unicode combining character abuse → blocked
2. **Link scanner** — O(1) in-memory domain cache (27+ seeded phishing domains)
3. **Mass mentions** — Exceeds configured ping limit → delete + auto-mute
4. **Flood detection** — Redis INCR+EXPIRE velocity tracking → auto-mute

### 🔗 Threat Intelligence
Runtime-managed malicious domain blocklist with DB persistence and live cache sync:

```
!link-add evil.com 3    →  INSERT into DB + add to memory cache
!link-remove evil.com   →  DELETE from DB + remove from cache
!link-check https://evil.com  →  Instant O(1) cache lookup
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Discord Gateway                          │
│          (Events: messages, joins, bans, role changes)          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Bot Core (discord.py)                       │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│   │ 10 Cogs  │  │ Services │  │  Utils   │  │   Security   │  │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
  ┌──────────────┐ ┌──────────┐ ┌─────────────┐
  │  Supabase    │ │  Redis   │ │  External   │
  │ (PostgreSQL) │ │  Cache   │ │    APIs     │
  │  7 tables    │ │ counters │ │ Proxycheck  │
  └──────────────┘ └──────────┘ └─────────────┘
```

**Core Design Principles:**
- **Stateful** — All settings persist in PostgreSQL. Zero data loss on restart.
- **Modular** — Each cog is an independent, hot-swappable security module.
- **Append-Only Audit** — Logs are write-once with hash chaining. Tampering breaks the chain.
- **DB-First** — Logs are stored in the database, not in Discord messages. Even if the log channel is deleted, records survive.

---

## Project Structure

```
bot/
├── main.py                         # Entry point + AntiRaidBot class
├── config.py                       # .env loader + validation
├── run_migrations.py               # Automated DB migration runner
├── requirements.txt                # 8 dependencies
├── Procfile                        # Railway deployment config
├── .env.example                    # Environment variable template
├── .gitignore
│
├── database/
│   ├── __init__.py
│   ├── connection.py               # asyncpg pool wrapper
│   └── migrations/
│       ├── 001_initial_schema.sql   # server_configs, whitelists,
│       │                            # malicious_links, temporal_punishments
│       ├── 002_audit_logs.sql       # Hash-chained audit table
│       ├── 003_risk_scoring.sql     # risk_scores + server_snapshots
│       └── 004_seed_phishing.sql    # 27 phishing domains
│
├── cogs/                            # 10 dynamically loaded modules
│   ├── admin_config.py              # Config commands (9)
│   ├── antinuke.py                  # Internal protection (5 listeners)
│   ├── antiraid.py                  # Auto-lockdown (1 listener)
│   ├── antispam.py                  # Message scanning (1 listener)
│   ├── error_handler.py             # Global error handler
│   ├── investigation.py             # Audit + security commands (5)
│   ├── logging.py                   # Event audit logging (10 listeners)
│   ├── moderation.py                # Emergency + mod commands (12)
│   ├── threat_intel.py              # Link management (4)
│   └── verification.py             # CAPTCHA + alt detection (1 listener)
│
├── services/
│   ├── captcha.py                   # Pillow-based CAPTCHA generator
│   ├── linkscanner.py               # In-memory domain cache + scanner
│   ├── proxycheck.py                # Proxycheck.io API wrapper
│   └── punishment_scheduler.py      # APScheduler (30s interval)
│
├── utils/
│   ├── permissions.py               # @is_staff() decorator + NotStaff
│   ├── rate_limit.py                # Redis INCR+EXPIRE helper
│   └── threat_data.py               # Phishing seeds + regex patterns
│
└── security/
    └── audit_integrity.py           # SHA-256 hash chain implementation
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Bot Framework** | `discord.py ≥ 2.3.0` | Async event handling & commands |
| **Language** | Python 3.11+ | Core runtime |
| **Primary Database** | PostgreSQL via **Supabase** | Persistent config, logs, punishments |
| **DB Driver** | `asyncpg ≥ 0.29.0` | Async PostgreSQL queries |
| **Cache** | `redis[asyncio] ≥ 5.0.0` | In-memory rate limiting & lockdown snapshots |
| **Task Scheduler** | `APScheduler ≥ 3.10.0` | Auto-lift temp bans/mutes |
| **HTTP Client** | `aiohttp ≥ 3.9.0` | External API calls |
| **CAPTCHA** | `Pillow ≥ 10.0.0` | Image-based challenge generation |
| **IP Intelligence** | Proxycheck.io API | VPN/Proxy/Tor detection |
| **Integrity** | SHA-256 Hash Chaining | Tamper-proof audit verification |
| **Hosting** | Railway | Bot process + Redis addon |

---

## Setup & Installation

### Prerequisites
- Python 3.11+
- A [Supabase](https://supabase.com) project (free tier works)
- A [Redis](https://railway.app) instance (Railway addon or any Redis provider)
- A [Discord Bot Token](https://discord.com/developers/applications)

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/antiraid-bot.git
cd antiraid-bot/bot
```

### 2. Create a Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your real values:

```env
# ── Discord ────────────────────────────────────────────────────
DISCORD_TOKEN=your_bot_token_here

# ── Database (Supabase PostgreSQL) ─────────────────────────────
DATABASE_URL=postgresql://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres

# ── Cache (Redis) ──────────────────────────────────────────────
REDIS_URL=redis://default:password@host:port

# ── External APIs ──────────────────────────────────────────────
PROXYCHECK_API_KEY=your_proxycheck_key
VIRUSTOTAL_API_KEY=your_virustotal_key

# ── Bot Config ────────────────────────────────────────────────
DEFAULT_PREFIX=!
```

> ⚠️ **Never commit `.env` to version control.** It is already in `.gitignore`.

### 5. Run Database Migrations

```bash
python run_migrations.py
```

This will create all 7 tables and seed 27 phishing domains:

```
✅ 001_initial_schema.sql — Applied
✅ 002_audit_logs.sql — Applied
✅ 003_risk_scoring.sql — Applied
✅ 004_seed_phishing_domains.sql — Applied
```

### 6. Start the Bot

```bash
python main.py
```

Expected output:
```
══════════════════════════════════════════════════
  🛡️  AntiRaid Bot is ONLINE
══════════════════════════════════════════════════
  User     : AntiRaid#1234 (ID: 123456789)
  Guilds   : 1
  Latency  : 42ms
  Prefix   : !
══════════════════════════════════════════════════
```

### 7. Discord Bot Permissions

When inviting the bot, ensure it has these permissions (or Administrator):

- Manage Channels
- Manage Roles
- Kick Members
- Ban Members
- Manage Messages
- Send Messages
- Embed Links
- Read Message History
- View Audit Log

**Required Gateway Intents** (enable in Developer Portal):
- ✅ Presence Intent
- ✅ Server Members Intent
- ✅ Message Content Intent

---

## Database Migration

The bot uses 7 PostgreSQL tables:

| Table | Purpose |
|---|---|
| `server_configs` | Per-guild settings (prefix, thresholds, toggles) |
| `whitelists` | Spam filter exemptions (roles, channels) |
| `malicious_links` | Blocked domain registry |
| `audit_logs` | Hash-chained tamper-proof event log |
| `temporal_punishments` | Temp bans/mutes with expiry timestamps |
| `risk_scores` | Per-user composite risk scores |
| `server_snapshots` | Server state backups for restore commands |

Run all migrations automatically:

```bash
python run_migrations.py
```

---

## Command Reference

> All commands require **Administrator** permission. Prefix is `!` (configurable via `!set-prefix`).

### ⚙️ Configuration — `admin_config.py`

| Command | Description |
|---|---|
| `!set-prefix [prefix]` | Change the bot command prefix |
| `!set-log-channel [#channel]` | Set the security alert channel |
| `!set-raid-limit [joins] [seconds]` | Set auto-lockdown threshold |
| `!set-quarantine-role [@role]` | Set the quarantine role |
| `!set-account-age [hours]` | Minimum account age to join |
| `!toggle [module] [on/off]` | Toggle captcha/proxycheck/antinuke/antispam |
| `!whitelist add [@role / #channel]` | Exempt from spam filters |
| `!whitelist remove [@role / #channel]` | Remove exemption |
| `!whitelist list` | View all exemptions |

### 🚨 Emergency — `moderation.py`

| Command | Description |
|---|---|
| `!lockdown` | Lock all channels immediately |
| `!unlockdown` | Restore pre-lockdown permissions |
| `!panic-mode` | Lockdown + enable all defenses + alert staff |
| `!slowmode-all [seconds]` | Apply slowmode to every channel (0 to remove) |
| `!purge [number]` | Delete last N messages in current channel |
| `!purge-user [@user]` | Delete all messages from a user (all channels) |

### 🔨 Moderation — `moderation.py`

| Command | Description |
|---|---|
| `!temp-ban [@user] [duration] [reason]` | Temporary ban (auto-lifted) |
| `!temp-mute [@user] [duration] [reason]` | Temporary mute (auto-lifted) |
| `!quarantine [@user]` | Strip roles + assign quarantine role |
| `!unquarantine [@user]` | Restore quarantined user's roles |
| `!warn [@user] [reason]` | Issue a formal warning (logged to DB) |
| `!warnings [@user]` | View warning history |

### 🔍 Investigation — `investigation.py`

| Command | Description |
|---|---|
| `!verify-integrity` | Run SHA-256 hash chain validation |
| `!security-status` | Real-time security dashboard |
| `!scan-user [@user]` | Full security profile (age, risk, warnings) |
| `!audit-search [filters]` | Search logs (`user:` `action:` `severity:`) |
| `!case [id]` | Retrieve a specific audit log entry |

### 🔗 Link Management — `threat_intel.py`

| Command | Description |
|---|---|
| `!link-add [domain] [level]` | Block a domain (1=low, 2=med, 3=critical) |
| `!link-remove [domain]` | Unblock a domain |
| `!link-list` | View all blocked domains |
| `!link-check [url]` | Check if a URL is flagged |

---

## Event Listeners

The bot passively monitors 20 Discord events:

| Module | Event | Action |
|---|---|---|
| **Audit Logging** | `on_message_delete` | Ghost ping detection + deletion log |
| **Audit Logging** | `on_message_edit` | Edit tracking |
| **Audit Logging** | `on_member_join` | Join log with account age |
| **Audit Logging** | `on_member_remove` | Leave/kick log |
| **Audit Logging** | `on_member_ban` | Ban log with attribution |
| **Audit Logging** | `on_member_unban` | Unban log |
| **Audit Logging** | `on_member_update` | Role assigned/removed |
| **Audit Logging** | `on_guild_channel_create` | Channel creation log |
| **Audit Logging** | `on_guild_channel_delete` | Channel deletion log |
| **Audit Logging** | `on_command` | All bot commands executed |
| **Anti-Nuke** | `on_member_ban` | Mass ban detection |
| **Anti-Nuke** | `on_member_remove` | Mass kick detection |
| **Anti-Nuke** | `on_guild_channel_delete` | Channel nuke detection |
| **Anti-Nuke** | `on_guild_role_delete` | Role nuke detection |
| **Anti-Nuke** | `on_member_join` | Unauthorized bot detection |
| **Anti-Raid** | `on_member_join` | Join spike → auto-lockdown |
| **Anti-Spam** | `on_message` | Zalgo + links + mentions + flood |
| **Verification** | `on_member_join` | Alt check + CAPTCHA flow |
| **Error Handler** | `on_command_error` | Global error handling |

---

## Security Patterns

### Hash Chain (Tamper-Proof Logging)
```python
current_hash = SHA256(previous_hash + JSON(log_data))
```
Each audit log entry stores a `hash_signature` computed from the previous entry's hash plus the current entry's data. If any historical row is modified, the entire chain breaks from that point forward. `!verify-integrity` recomputes the full chain on demand.

### Redis Rate Limiting
```python
key = f"spam:{guild_id}:{user_id}"
count = await redis.incr(key)
if count == 1:
    await redis.expire(key, window_seconds)
return count > limit
```
Used for spam detection, anti-nuke action tracking, and raid join-spike detection.

### Permission Guard
```python
@commands.command()
@is_staff()   # Custom decorator — checks Admin permission
async def my_command(self, ctx):
    ...
```
Every admin command is protected by the `@is_staff()` guard. Non-admins receive a clean "Access Denied" embed.

---

## Deployment (Railway)

### Services to Deploy

```
Railway Project
├── Service: bot          → Python process (main.py)
└── Service: redis        → Redis plugin (Railway addon)
```

### Procfile

```
worker: python main.py
```

### Environment Variables

Set these in the Railway dashboard under **Variables**:

```
DISCORD_TOKEN
DATABASE_URL
REDIS_URL          ← auto-provided by Railway Redis addon
PROXYCHECK_API_KEY
VIRUSTOTAL_API_KEY
DEFAULT_PREFIX
```

### Deploy Steps

1. Push your repository to GitHub
2. Create a new Railway project
3. Add a **Redis** addon (provides `REDIS_URL` automatically)
4. Set the remaining environment variables
5. Deploy — Railway detects the `Procfile` and starts the worker

---

## Future Enhancements

| Feature | Phase | Description |
|---|---|---|
| **VirusTotal Layer 2** | Phase 4 | Deep URL scanning via VirusTotal API (auto-learn new threats) |
| **Risk Score Engine** | Phase 4 | Auto-calculate composite scores (0–100) per user. Auto-quarantine at ≥ 80 |
| **Server Snapshots** | Phase 4 | Periodic full server state backup for `!restore-roles` / `!restore-channels` |
| **ML Anomaly Detection** | Phase 5 | Behavioral baseline per guild — detect abnormal patterns |
| **Community Threat Feed** | Phase 5 | Shared malicious link updates across bot instances |
| **Multi-Guild Management** | Phase 5 | Centralized dashboard for multiple servers |
| **Incident Reports** | Phase 5 | Auto-generated security incident summaries |

---

## Startup & Shutdown Sequence

### Startup
```
main.py → setup_hook()
  1. Connect PostgreSQL (Supabase)
  2. Connect Redis
  3. Load link scanner cache (27+ domains)
  4. Start punishment scheduler (30s)
  5. Load all 10 cogs dynamically
→ on_ready() → Bot is ONLINE
```

### Shutdown
```
close()
  1. Stop punishment scheduler
  2. Close Redis connection
  3. Close PostgreSQL pool
  4. Close Discord gateway
```

---

## License

This project is for educational and portfolio purposes. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Built with 🛡️ for enterprise-grade Discord security.</strong>
</p>
