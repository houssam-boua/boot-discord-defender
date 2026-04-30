-- ══════════════════════════════════════════════════════════════
--  003_risk_scoring.sql — Risk Score & Server Snapshots (Phase 3)
-- ══════════════════════════════════════════════════════════════

-- Per-user composite risk score
CREATE TABLE IF NOT EXISTS risk_scores (
    guild_id            BIGINT    NOT NULL,
    user_id             BIGINT    NOT NULL,
    account_age_score   INT       DEFAULT 0,
    vpn_flag            BOOLEAN   DEFAULT FALSE,
    spam_velocity_score INT       DEFAULT 0,
    link_abuse_score    INT       DEFAULT 0,
    mention_abuse_score INT       DEFAULT 0,
    total_score         INT       DEFAULT 0,
    last_updated        TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (guild_id, user_id)
);

-- Server state snapshots for restore commands
CREATE TABLE IF NOT EXISTS server_snapshots (
    id            BIGSERIAL PRIMARY KEY,
    guild_id      BIGINT    NOT NULL,
    snapshot_type TEXT      NOT NULL,  -- 'channels' | 'roles' | 'permissions'
    data          JSONB     NOT NULL,
    created_at    TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_snapshots_guild ON server_snapshots(guild_id);
