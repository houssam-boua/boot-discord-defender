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
  Tamper-proof audit logs · Hybrid anti-nuke detection · Automated raid defense · CAPTCHA verification · Self-healing server recovery · Appeal system
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
| **Nuke attacks** | Audit-log-attributed mass-action detection → role strip → auto-ban → auto-restore |
| **Phishing & malware** | 27+ seeded domains · O(1) in-memory cache · VirusTotal Layer 2 · Embed & attachment scanning |
| **Account compromises** | Mass-ban/kick rate tracking per admin → automatic role strip + ban |
| **Admin gone rogue** | Admin posts malicious link → roles stripped → muted → logged to DB |
| **Alt-account infiltration** | Account age + avatar checks + CAPTCHA |
| **Log tampering** | SHA-256 hash-chained audit trail |
| **Server destruction** | Debounced live snapshots → automatic full-server restore (roles + channels + member assignments) |

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

When an admin exceeds the configured threshold (e.g., 3 bans in 10 seconds), their roles are **immediately stripped**, the attacker is **automatically banned** (with 1-day message purge), and the server is **automatically restored** from the latest snapshot — all within seconds, with zero human intervention.

### 🔄 Self-Healing Server Recovery
The bot continuously maintains debounced snapshots of every guild's structure (roles, channels, permissions, member role assignments). When a nuke is detected:

```
Nuke Detected → Attacker Banned → Auto-Restore Triggered
  ├── Recreate deleted roles (with permissions + colors + hierarchy)
  ├── Recreate deleted channels (with categories + overwrites)
  ├── Re-assign member roles from snapshot
  └── Post recovery summary embed to first available channel
```

Manual restore is also available via `!restore` and `!restore-member`.

### ⚖️ Appeal System
Punished users can appeal via DM within 24 hours. Appeals are posted to the log channel with interactive Approve/Deny buttons that persist across bot restarts:

```
User Punished → Bot DMs !appeal instructions
  → User replies: !appeal <explanation>
  → Embed + buttons posted to mod log channel
  → Mod clicks Approve → punishment lifted + user notified
  → Mod clicks Deny → user notified
  → No action in 48h → auto-expired + user notified
```

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
Multi-layer message scanning on every incoming message:

1. **Zalgo text** — Unicode combining character abuse → blocked
2. **Link scanner** — O(1) in-memory domain cache (27+ seeded phishing domains)
3. **VirusTotal Layer 2** — Deep URL scanning for unknown domains (capped at 5 URLs per message)
4. **Embed URL scanning** — Checks embed URLs, thumbnails, and images for malicious content
5. **Attachment scanning** — Inspects attachment URLs and filenames for embedded malicious links
6. **Invite link blocking** — Unauthorized Discord invite links → delete + auto-mute
7. **Mass mentions** — Exceeds configured ping limit → delete + auto-mute
8. **Flood detection** — Redis INCR+EXPIRE velocity tracking → auto-mute + bulk-delete all flood messages

### 🔒 Admin Bypass Protection
If an administrator posts a malicious link and cannot be timed out due to role hierarchy:
1. Bot strips all roles that grant Administrator permission
2. Re-attempts the timeout (now succeeds)
3. Stripped roles are saved to `admin_role_strips` table for audit/restore
4. Roles can be restored via `!restore-member @user`

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
│   │ 12 Cogs  │  │ Services │  │  Utils   │  │   Security   │  │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
  ┌──────────────┐ ┌──────────┐ ┌─────────────┐
  │  Supabase    │ │  Redis   │ │  External   │
  │ (PostgreSQL) │ │  Cache   │ │    APIs     │
  │  9 tables    │ │ counters │ │ Proxycheck  │
  │              │ │ snapshots│ │ VirusTotal  │
  └──────────────┘ └──────────┘ └─────────────┘
```

**Core Design Principles:**
- **Stateful** — All settings persist in PostgreSQL. Zero data loss on restart.
- **Self-Healing** — Nuke damage is automatically repaired from live snapshots.
- **Modular** — Each cog is an independent, hot-swappable security module.
- **Append-Only Audit** — Logs are write-once with hash chaining. Tampering breaks the chain.
- **DB-First** — Logs are stored in the database, not in Discord messages. Even if the log channel is deleted, records survive.
- **Fail-Safe** — Every external call (DMs, role changes, bans) is wrapped in error handling. No single failure crashes the bot.

---

## Project Structure

```
bot/
├── main.py                         # Entry point + AntiRaidBot class
├── config.py                       # .env loader + validation
├── run_migrations.py               # Automated DB migration runner
├── requirements.txt                # Python dependencies
├── Procfile                        # Railway deployment config
├── .env.example                    # Environment variable template
├── .gitignore
│
├── database/
│   ├── __init__.py
│   ├── connection.py               # asyncpg pool wrapper
│   ├── models.py                   # ORM helpers
│   └── migrations/
│       ├── 001_initial_schema.sql  # server_configs, whitelists,
│       │                           # malicious_links, temporal_punishments
│       ├── 002_audit_logs.sql      # Hash-chained audit table
│       ├── 003_risk_scoring.sql    # risk_scores + server_snapshots
│       ├── 004_seed_phishing.sql   # 27 phishing domains
│       ├── 005_missing_tables.sql  # Gap-fill for missing tables
│       ├── 006_vt_cache.sql        # VirusTotal response cache
│       ├── 007_punishment_details.sql # Punishment metadata columns
│       ├── 008_allow_invites.sql   # Invite link toggle column
│       └── 009_appeals.sql         # Appeals table + indexes
│
├── cogs/                           # 12 dynamically loaded modules
│   ├── admin_config.py             # Config commands (9)
│   ├── antinuke.py                 # Anti-nuke detection + auto-ban (5 listeners)
│   ├── antiraid.py                 # Auto-lockdown (1 listener)
│   ├── antispam.py                 # Message scanning (1 listener, 8 checks)
│   ├── appeals.py                  # Appeal system — DM submission + button review
│   ├── audit_logger.py             # Event audit logging (10 listeners)
│   ├── error_handler.py            # Global error handler
│   ├── investigation.py            # Audit + security commands (5)
│   ├── moderation.py               # Emergency + mod commands (14)
│   ├── recovery.py                 # Server snapshots + auto-restore + member roles
│   ├── threat_intel.py             # Link management (4)
│   └── verification.py            # CAPTCHA + alt detection (1 listener)
│
├── services/
│   ├── captcha.py                  # Pillow-based CAPTCHA generator
│   ├── linkscanner.py              # In-memory domain cache + VirusTotal + scanner
│   ├── proxycheck.py               # Proxycheck.io API wrapper
│   └── punishment_scheduler.py     # APScheduler (30s interval + appeal expiry)
│
├── utils/
│   ├── permissions.py              # @is_staff() decorator + NotStaff
│   ├── rate_limit.py               # Redis INCR+EXPIRE helper
│   ├── regex_filters.py            # Custom regex patterns
│   └── threat_data.py              # Phishing seeds + regex patterns
│
└── security/
    └── audit_integrity.py          # SHA-256 hash chain implementation
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Bot Framework** | `discord.py ≥ 2.3.0` | Async event handling & commands |
| **Language** | Python 3.11+ | Core runtime |
| **Primary Database** | PostgreSQL via **Supabase** | Persistent config, logs, punishments, appeals |
| **DB Driver** | `asyncpg ≥ 0.29.0` | Async PostgreSQL queries |
| **Cache** | `redis[asyncio] ≥ 5.0.0` | In-memory rate limiting & lockdown snapshots |
| **Task Scheduler** | `APScheduler ≥ 3.10.0` | Auto-lift temp bans/mutes + appeal expiry |
| **HTTP Client** | `aiohttp ≥ 3.9.0` | External API calls (VirusTotal, Proxycheck) |
| **CAPTCHA** | `Pillow ≥ 10.0.0` | Image-based challenge generation |
| **Threat Intelligence** | VirusTotal API | Deep URL scanning (Layer 2) |
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
git clone https://github.com/houssam-boua/boot-discord-defender.git
cd boot-discord-defender/bot
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

This will create all 9 tables and seed 27 phishing domains:

```
✅ 001_initial_schema.sql — Applied
✅ 002_audit_logs.sql — Applied
✅ 003_risk_scoring.sql — Applied
✅ 004_seed_phishing_domains.sql — Applied
✅ 005_missing_tables.sql — Applied
✅ 006_vt_cache.sql — Applied
✅ 007_punishment_details.sql — Applied
✅ 008_allow_invites.sql — Applied
✅ 009_appeals.sql — Applied
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

The bot uses 9 PostgreSQL tables:

| Table | Purpose |
|---|---|
| `server_configs` | Per-guild settings (prefix, thresholds, toggles) |
| `whitelists` | Spam filter exemptions (roles, channels) |
| `malicious_links` | Blocked domain registry |
| `audit_logs` | Hash-chained tamper-proof event log |
| `temporal_punishments` | Temp bans/mutes with expiry timestamps |
| `risk_scores` | Per-user composite risk scores |
| `server_snapshots` | Server state backups (roles, channels, member assignments) |
| `admin_role_strips` | Tracks stripped admin roles for audit/restore |
| `appeals` | User punishment appeals with status tracking |

Run all migrations automatically:

```bash
python run_migrations.py
```

---

## Command Reference

> All commands require **Administrator** or **Staff** permission unless noted. Prefix is `!` (configurable via `!set-prefix`).

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
| `!purge-all` | Wipe ALL messages in current channel (with confirmation gate, bulk-deletes recent, skips 14d+) |

### 🔨 Moderation — `moderation.py`

| Command | Description |
|---|---|
| `!temp-ban [@user] [duration] [reason]` | Temporary ban (auto-lifted) |
| `!temp-mute [@user] [duration] [reason]` | Temporary mute (auto-lifted) |
| `!quarantine [@user]` | Strip roles + assign quarantine role |
| `!unquarantine [@user]` | Restore quarantined user's roles |
| `!warn [@user] [reason]` | Issue a formal warning (logged to DB) |
| `!warnings [@user]` | View warning history |

### 🔄 Recovery — `recovery.py`

| Command | Description |
|---|---|
| `!snapshot-now` | Force an immediate server snapshot |
| `!restore` | Full server restore — roles, channels, and member role assignments from latest snapshot |
| `!restore-member [@user]` | Re-assign stripped admin roles to a member from the audit log |

> **Note:** `!restore-roles` and `!restore-channels` are preserved as aliases of `!restore` for backwards compatibility.

### ⚖️ Appeals — `appeals.py`

| Command | Where | Description |
|---|---|---|
| `!appeal <text>` | DM only | Submit an appeal for a recent punishment (within 24h) |
| `!appeals` | Server | List all pending appeals (requires `manage_guild`) |

Appeals also expose interactive **Approve** / **Deny** buttons on the embed posted to the log channel. These buttons persist across bot restarts.

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

The bot passively monitors 20+ Discord events:

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
| **Anti-Nuke** | `on_member_ban` | Mass ban detection → role strip → ban → auto-restore |
| **Anti-Nuke** | `on_member_remove` | Mass kick detection |
| **Anti-Nuke** | `on_guild_channel_delete` | Channel nuke detection → auto-restore |
| **Anti-Nuke** | `on_guild_role_delete` | Role nuke detection → auto-restore |
| **Anti-Nuke** | `on_member_join` | Unauthorized bot detection |
| **Anti-Raid** | `on_member_join` | Join spike → auto-lockdown |
| **Anti-Spam** | `on_message` | Zalgo + links + embeds + attachments + mentions + flood |
| **Verification** | `on_member_join` | Alt check + CAPTCHA flow |
| **Recovery** | `on_guild_*` | Debounced live snapshots on structural changes |
| **Appeals** | `on_message` (DM) | `!appeal` command processing |
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

### Admin Bypass Protection
```python
# Admin posts malicious link → timeout fails (403 Forbidden)
# → Strip all roles granting Administrator
# → Re-attempt timeout (now succeeds)
# → Save stripped roles to admin_role_strips table
# → Roles can be restored via !restore-member @user
```

### Debounced Live Snapshots
```python
# Structural change detected (role/channel create/delete/update)
# → Cancel any pending snapshot task
# → Wait 5 seconds (debounce window)
# → If no new events: take snapshot
# → If new event arrives: reset timer
# Thread-safe, burst-resistant, zero log noise
```

### Permission Guard
```python
@commands.command()
@is_staff()   # Custom decorator — checks Admin permission
async def my_command(self, ctx):
    ...
```
Every admin command is protected by the `@is_staff()` guard. Non-admins receive a clean "Access Denied" embed.

---

## Automated Response Flows

### Nuke Detection → Full Auto-Recovery
```
Attacker deletes channels/roles rapidly
  → Anti-nuke threshold exceeded (3 actions in 10s)
  → Strip all roles from attacker
  → Ban attacker (delete_message_days=1)
  → DM attacker with appeal instructions
  → Auto-trigger restore_from_snapshot()
    ├── Recreate missing roles (permissions, colors, hierarchy)
    ├── Recreate missing channels (categories, overwrites)
    ├── Re-assign member roles from snapshot
    └── Post recovery summary embed
  → Total recovery time: < 30 seconds
```

### Malicious Link → Layered Response
```
Message received
  → Layer 1: In-memory domain cache (O(1) lookup)
  → Layer 2: VirusTotal deep scan (unknown domains only)
  → Layer 2b: Embed URL scanning (thumbnails, images)
  → Layer 2c: Attachment URL/filename scanning
  → If flagged:
    ├── Delete message immediately
    ├── Attempt timeout (10 min)
    ├── If admin (403) → strip admin roles → re-mute
    ├── DM user with appeal instructions
    └── Alert in log channel
```

### Flood Detection → Bulk Cleanup
```
User sends 5+ messages in 2 seconds
  → Delete triggering message
  → Bulk-delete up to 9 more recent messages (10 total)
  → Auto-mute user
  → DM user with appeal instructions
  → Alert in log channel
```

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
| **ML Anomaly Detection** | Phase 5 | Behavioral baseline per guild — detect abnormal patterns |
| **Community Threat Feed** | Phase 5 | Shared malicious link updates across bot instances |
| **Multi-Guild Management** | Phase 5 | Centralized dashboard for multiple servers |
| **Incident Reports** | Phase 5 | Auto-generated security incident summaries |
| **Web Dashboard** | Phase 6 | Browser-based config & analytics UI |

---

## Startup & Shutdown Sequence

### Startup
```
main.py → setup_hook()
  1. Connect PostgreSQL (Supabase)
  2. Connect Redis
  3. Load link scanner cache (27+ domains)
  4. Start punishment scheduler (30s)
  5. Load all 12 cogs dynamically
  6. Re-register pending appeal button views
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
