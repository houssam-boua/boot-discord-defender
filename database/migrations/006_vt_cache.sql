-- ══════════════════════════════════════════════════════════════════
--  Migration 006: VirusTotal Scan Cache
--  Caches ALL VT scan results (both malicious AND clean) so we
--  never repeat an API call for the same domain.
--
--  malicious_links stores flagged domains for Layer 1 cache.
--  vt_scan_cache stores ALL results (including clean) to prevent
--  burning the 4-per-minute API quota on repeated clean lookups.
-- ══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS vt_scan_cache (
    domain       VARCHAR(255) PRIMARY KEY,
    is_malicious BOOLEAN      NOT NULL DEFAULT FALSE,
    positives    INTEGER      DEFAULT 0,
    scanned_at   TIMESTAMPTZ  DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vt_cache_scanned
    ON vt_scan_cache (scanned_at);
