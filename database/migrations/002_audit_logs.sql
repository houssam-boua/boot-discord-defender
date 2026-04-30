-- ══════════════════════════════════════════════════════════════
--  002_audit_logs.sql — Tamper-Proof Audit Log Table
-- ══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        BIGINT       NOT NULL,
    actor_id        BIGINT,                 -- Who triggered the action
    target_id       BIGINT,                 -- Who was affected
    action_type     TEXT         NOT NULL,   -- 'BAN' | 'MUTE' | 'LOCKDOWN' | etc.
    details         JSONB,                  -- Flexible metadata
    severity        VARCHAR(10)  DEFAULT 'INFO',  -- INFO | WARN | CRITICAL
    created_at      TIMESTAMP    DEFAULT NOW(),
    hash_signature  TEXT         NOT NULL    -- SHA-256 chain hash
);

-- Append-only: no UPDATE or DELETE permissions should be granted on this table
-- Index for fast lookups by guild
CREATE INDEX IF NOT EXISTS idx_audit_logs_guild ON audit_logs(guild_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
