-- ══════════════════════════════════════════════════════════════
--  001_initial_schema.sql — Core Tables
--  Run this migration first on your Supabase PostgreSQL instance.
-- ══════════════════════════════════════════════════════════════

-- Server-specific configuration (one row per guild)
CREATE TABLE IF NOT EXISTS server_configs (
    guild_id              BIGINT PRIMARY KEY,
    prefix                VARCHAR(10)   DEFAULT '!',
    raid_limit_count      INT           DEFAULT 10,
    raid_limit_seconds    INT           DEFAULT 3,
    log_channel_id        BIGINT,
    quarantine_role_id    BIGINT,
    min_account_age_hours INT           DEFAULT 24,
    captcha_enabled       BOOLEAN       DEFAULT TRUE,
    proxycheck_enabled    BOOLEAN       DEFAULT FALSE,
    antinuke_enabled      BOOLEAN       DEFAULT TRUE,
    antispam_enabled      BOOLEAN       DEFAULT TRUE,
    max_mentions          INT           DEFAULT 5,
    spam_msg_limit        INT           DEFAULT 5,
    spam_msg_seconds      INT           DEFAULT 2,
    created_at            TIMESTAMP     DEFAULT NOW()
);

-- Whitelisted entities (roles, channels, users exempt from filters)
CREATE TABLE IF NOT EXISTS whitelists (
    id           SERIAL PRIMARY KEY,
    guild_id     BIGINT       NOT NULL,
    entity_id    BIGINT       NOT NULL,
    entity_type  VARCHAR(20)  NOT NULL,  -- 'role' | 'channel' | 'user'
    added_by     BIGINT,
    added_at     TIMESTAMP    DEFAULT NOW(),
    UNIQUE(guild_id, entity_id, entity_type)
);

-- Known malicious domains
CREATE TABLE IF NOT EXISTS malicious_links (
    id           SERIAL PRIMARY KEY,
    domain       TEXT         UNIQUE NOT NULL,
    threat_level INT          DEFAULT 1,    -- 1=low, 2=medium, 3=critical
    source       TEXT,                      -- 'manual' | 'auto' | 'community' | 'seed'
    created_at   TIMESTAMP    DEFAULT NOW(),
    updated_at   TIMESTAMP    DEFAULT NOW()
);

-- Temporary punishments (auto-lifted by APScheduler)
CREATE TABLE IF NOT EXISTS temporal_punishments (
    id               BIGSERIAL PRIMARY KEY,
    guild_id         BIGINT       NOT NULL,
    user_id          BIGINT       NOT NULL,
    punishment_type  VARCHAR(20)  NOT NULL,  -- 'ban' | 'mute' | 'quarantine'
    expires_at       TIMESTAMP    NOT NULL,
    reason           TEXT,
    issued_by        BIGINT,
    active           BOOLEAN      DEFAULT TRUE,
    created_at       TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_active_punishments
    ON temporal_punishments(expires_at) WHERE active = TRUE;
