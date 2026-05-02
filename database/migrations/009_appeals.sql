-- ── Appeals table ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS appeals (
    id                BIGSERIAL   PRIMARY KEY,
    guild_id          BIGINT      NOT NULL,
    user_id           BIGINT      NOT NULL,
    punishment_type   TEXT        NOT NULL,
    punishment_reason TEXT        NOT NULL,
    appeal_text       TEXT        NOT NULL,
    status            TEXT        NOT NULL DEFAULT 'pending',
    reviewed_by       BIGINT,
    reviewed_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '48 hours')
);

CREATE INDEX IF NOT EXISTS idx_appeals_guild_user
    ON appeals (guild_id, user_id);

CREATE INDEX IF NOT EXISTS idx_appeals_status
    ON appeals (status)
    WHERE status = 'pending';
