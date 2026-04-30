-- ══════════════════════════════════════════════════════════════════
--  AntiRaid Security Bot — Supabase SQL Setup
--  ─────────────────────────────────────────────────────────────────
--  INSTRUCTIONS:
--    1. Open your Supabase project dashboard
--    2. Go to "SQL Editor" (left sidebar)
--    3. Click "New Query"
--    4. Paste this ENTIRE file and click "Run"
--    5. You should see "Success. No rows returned" — that means it worked.
--
--  This creates ALL tables needed for Phase 1.
--  Safe to run multiple times (uses IF NOT EXISTS).
-- ══════════════════════════════════════════════════════════════════


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  TABLE 1: server_configs                                     ║
-- ║  One row per Discord guild — stores all bot settings.        ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS server_configs (
    guild_id              BIGINT PRIMARY KEY,           -- Discord guild (server) ID
    prefix                VARCHAR(10)   DEFAULT '!',    -- Command prefix per server
    raid_limit_count      INT           DEFAULT 10,     -- Joins before auto-lockdown triggers
    raid_limit_seconds    INT           DEFAULT 3,      -- Time window for raid detection
    log_channel_id        BIGINT,                       -- Channel ID for bot alerts/logs
    quarantine_role_id    BIGINT,                       -- Role assigned to quarantined members
    min_account_age_hours INT           DEFAULT 24,     -- Min account age to pass verification
    captcha_enabled       BOOLEAN       DEFAULT TRUE,   -- CAPTCHA verification toggle
    proxycheck_enabled    BOOLEAN       DEFAULT FALSE,  -- VPN/Proxy IP detection toggle
    antinuke_enabled      BOOLEAN       DEFAULT TRUE,   -- Anti-nuke module toggle
    antispam_enabled      BOOLEAN       DEFAULT TRUE,   -- Anti-spam module toggle
    max_mentions          INT           DEFAULT 5,      -- Max mentions per message before mute
    spam_msg_limit        INT           DEFAULT 5,      -- Max messages in spam window
    spam_msg_seconds      INT           DEFAULT 2,      -- Spam detection time window (seconds)
    created_at            TIMESTAMP     DEFAULT NOW()   -- Row creation timestamp
);


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  TABLE 2: whitelists                                         ║
-- ║  Entities (roles/channels/users) exempt from security filters║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS whitelists (
    id           SERIAL PRIMARY KEY,
    guild_id     BIGINT       NOT NULL,
    entity_id    BIGINT       NOT NULL,
    entity_type  VARCHAR(20)  NOT NULL,     -- 'role' | 'channel' | 'user'
    added_by     BIGINT,                    -- Admin who added this whitelist entry
    added_at     TIMESTAMP    DEFAULT NOW(),
    UNIQUE(guild_id, entity_id, entity_type)
);


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  TABLE 3: malicious_links                                    ║
-- ║  Known phishing/malware domains — matched against messages.  ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS malicious_links (
    id           SERIAL PRIMARY KEY,
    domain       TEXT         UNIQUE NOT NULL,
    threat_level INT          DEFAULT 1,     -- 1=low, 2=medium, 3=critical
    source       TEXT,                       -- 'manual' | 'auto' | 'community' | 'seed'
    created_at   TIMESTAMP    DEFAULT NOW(),
    updated_at   TIMESTAMP    DEFAULT NOW()
);


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  TABLE 4: temporal_punishments                               ║
-- ║  Temp bans/mutes — auto-lifted by APScheduler on expiry.    ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS temporal_punishments (
    id               BIGSERIAL PRIMARY KEY,
    guild_id         BIGINT       NOT NULL,
    user_id          BIGINT       NOT NULL,
    punishment_type  VARCHAR(20)  NOT NULL,  -- 'ban' | 'mute' | 'quarantine'
    expires_at       TIMESTAMP    NOT NULL,
    reason           TEXT,
    issued_by        BIGINT,                 -- Admin who issued the punishment
    active           BOOLEAN      DEFAULT TRUE,
    created_at       TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_active_punishments
    ON temporal_punishments(expires_at) WHERE active = TRUE;


-- ╔══════════════════════════════════════════════════════════════╗
-- ║  TABLE 5: audit_logs                                         ║
-- ║  Append-only tamper-proof event log with SHA-256 hash chain. ║
-- ║  ⚠️ Do NOT grant UPDATE or DELETE on this table.             ║
-- ╚══════════════════════════════════════════════════════════════╝

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT       NOT NULL,
    actor_id        BIGINT,                  -- Who triggered the action
    target_id       BIGINT,                  -- Who was affected
    action_type     TEXT         NOT NULL,    -- 'BAN' | 'MUTE' | 'LOCKDOWN' | etc.
    details         JSONB,                   -- Flexible metadata
    severity        VARCHAR(10)  DEFAULT 'INFO',  -- INFO | WARN | CRITICAL
    created_at      TIMESTAMP    DEFAULT NOW(),
    hash_signature  TEXT         NOT NULL     -- SHA-256 chain hash
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_guild   ON audit_logs(guild_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor   ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);


-- ══════════════════════════════════════════════════════════════════
--  ✅ Done! All Phase 1 tables are now ready.
--  You can verify by running: SELECT tablename FROM pg_tables WHERE schemaname = 'public';
-- ══════════════════════════════════════════════════════════════════
