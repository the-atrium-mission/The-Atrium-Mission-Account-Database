-- =========================================================================
-- Migration 002 — invite codes (closed alpha gate)
--
-- Apply:  wrangler d1 execute atrium-prealpha --file=./migrations/002_invites.sql --remote
-- =========================================================================

CREATE TABLE IF NOT EXISTS invite_codes (
  code_hash    TEXT PRIMARY KEY,        -- HMAC-SHA256("invite:" || code, EMAIL_HMAC_PEPPER)
                                        -- The plaintext code is NEVER stored.
  issued_week  INTEGER NOT NULL,        -- YYYYWW
  used_week    INTEGER,                 -- NULL = unused. Set atomically on claim.
  used_by      INTEGER REFERENCES pre_alpha_signups(id),
  note         TEXT                     -- cohort label only, e.g. "spirit2.0-batch1".
                                        -- NEVER a person's name, handle, or email.
);

-- Partial index: the hot path is "is this code unused?", not a full scan.
CREATE INDEX IF NOT EXISTS idx_invites_unused
  ON invite_codes(code_hash) WHERE used_week IS NULL;

-- Ops view. Counts only — never exposes a code or links to an identity.
CREATE VIEW IF NOT EXISTS invite_stats AS
SELECT
  note,
  COUNT(*)                                        AS issued,
  SUM(CASE WHEN used_week IS NULL THEN 0 ELSE 1 END) AS redeemed
FROM invite_codes
GROUP BY note;
