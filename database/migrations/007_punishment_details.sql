-- ══════════════════════════════════════════════════════════════════
--  Migration 007: Add details JSONB column to temporal_punishments
--  Stores structured metadata (e.g. saved role IDs during quarantine)
--  separately from the human-readable reason text.
-- ══════════════════════════════════════════════════════════════════

ALTER TABLE temporal_punishments
    ADD COLUMN IF NOT EXISTS details JSONB DEFAULT '{}';
