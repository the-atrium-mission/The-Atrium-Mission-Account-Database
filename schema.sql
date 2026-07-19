-- =========================================================================
-- The Atrium Mission — Phase 0.5 pre-alpha signup schema
-- Target: Cloudflare D1 (SQLite)
-- Spec ref: atrium-infrastructure-user-db.md §4.1
--
-- Apply:  wrangler d1 execute atrium-prealpha --file=./schema.sql --remote
-- =========================================================================

CREATE TABLE IF NOT EXISTS pre_alpha_signups (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  email_hash        TEXT    NOT NULL UNIQUE,   -- hex HMAC-SHA256(normalized_email, EMAIL_HMAC_PEPPER)
  email_enc         BLOB    NOT NULL,          -- AES-256-GCM: [12-byte IV][ciphertext+tag]
  handle_reserved   TEXT    NOT NULL UNIQUE,   -- normalized lowercase, uniqueness key
  handle_display    TEXT    NOT NULL,          -- as typed, preserves capitalization
  founding_circle   INTEGER NOT NULL DEFAULT 0,
  mycelium_host     INTEGER NOT NULL DEFAULT 0,
  age_confirmed     INTEGER NOT NULL,          -- must be 1
  notes_enc         BLOB,                      -- AES-256-GCM, nullable
  created_week      INTEGER NOT NULL,          -- YYYYWW (ISO-8601 week). NOT a timestamp.
  migrated_week     INTEGER                    -- set when this row activates a real account
);

CREATE INDEX IF NOT EXISTS idx_pre_alpha_handle  ON pre_alpha_signups(handle_reserved);
CREATE INDEX IF NOT EXISTS idx_pre_alpha_created ON pre_alpha_signups(created_week);

-- Handle tombstones are NOT implemented in Phase 0.5.
-- Phase 0.5 reservations are immutable: no handle changes, no deletions via API.
-- Deletion requests are handled manually by a founder until Phase 1.
