-- ══════════════════════════════════════════════════════════════════
--  Migration 005: Missing Tables — antinuke_whitelist & captcha_challenges
--  Fix H-2 & L-2: These tables were referenced in the blueprint
--  but not included in the original schema.
-- ══════════════════════════════════════════════════════════════════

-- ── Anti-Nuke Whitelist ──────────────────────────────────────────
-- Admins added to this table bypass anti-nuke detection.
-- Prevents trusted senior staff from triggering false positives.
CREATE TABLE IF NOT EXISTS antinuke_whitelist (
    id            SERIAL PRIMARY KEY,
    guild_id      BIGINT NOT NULL,
    user_id       BIGINT NOT NULL,
    added_by      BIGINT,
    reason        TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE (guild_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_antinuke_wl_guild
    ON antinuke_whitelist (guild_id);


-- ── CAPTCHA Challenges ───────────────────────────────────────────
-- Tracks pending CAPTCHA challenges for the verification flow.
-- Prevents replay attacks and allows timeout enforcement.
CREATE TABLE IF NOT EXISTS captcha_challenges (
    id            SERIAL PRIMARY KEY,
    guild_id      BIGINT NOT NULL,
    user_id       BIGINT NOT NULL,
    answer        TEXT NOT NULL,
    attempts      INTEGER DEFAULT 0,
    created_at    TIMESTAMPTZ DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    completed     BOOLEAN DEFAULT FALSE,

    UNIQUE (guild_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_captcha_guild_user
    ON captcha_challenges (guild_id, user_id);
