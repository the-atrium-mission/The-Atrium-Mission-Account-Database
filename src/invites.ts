/**
 * Invite codes — the closed-alpha gate.
 *
 * WHY THIS EXISTS
 * Without a gate, an open signup endpoint lets anyone reserve any handle
 * using an address they do not own. Email confirmation is the usual fix.
 * An invite gate solves the same problem more strongly: no code, no row.
 * That is why confirmation email can safely wait until we open up.
 *
 * STORAGE RULE
 * We store HMAC(code), never the code. A stolen D1 snapshot therefore
 * contains no usable invites.
 *
 * SEPARATE PEPPER — deliberate.
 * Codes are hashed with INVITE_HMAC_PEPPER, not EMAIL_HMAC_PEPPER. The
 * generator runs on a founder workstation and needs its pepper locally.
 * Sharing the email pepper would mean every code-generation run puts the
 * secret protecting every stored email hash onto a laptop. Separating them
 * caps the blast radius of a workstation compromise at "can mint invites."
 */

/**
 * Crockford base32 alphabet — no I, L, O, or U.
 *
 * I/L/1 and O/0 are the classic transcription failures when someone reads a
 * code off a screen and types it somewhere else. Excluding them from the
 * alphabet means those characters can only ever be a typo, so we can safely
 * auto-correct them in normalizeCode() instead of rejecting the user.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** 12 chars of base32 = 60 bits of entropy. Format: XXXX-XXXX-XXXX */
const CODE_CHARS = 12;
const GROUP = 4;

/** Longest input we will even look at. Guards the regex passes below. */
export const MAX_CODE_INPUT = 64;

/**
 * Generate one invite code. Uses the CSPRNG with rejection sampling so the
 * distribution over the 32-char alphabet is uniform.
 *
 * (256 % 32 === 0, so modulo is already unbiased here — but the explicit
 * guard means this stays correct if the alphabet ever changes length.)
 */
export function generateCode(): string {
  const out: string[] = [];
  const max = Math.floor(256 / ALPHABET.length) * ALPHABET.length;

  while (out.length < CODE_CHARS) {
    const buf = crypto.getRandomValues(new Uint8Array(CODE_CHARS));
    for (const b of buf) {
      if (b >= max) continue; // reject, preserve uniformity
      out.push(ALPHABET[b % ALPHABET.length]);
      if (out.length === CODE_CHARS) break;
    }
  }

  const groups: string[] = [];
  for (let i = 0; i < CODE_CHARS; i += GROUP) {
    groups.push(out.slice(i, i + GROUP).join(''));
  }
  return groups.join('-');
}

/**
 * Normalize user input into the canonical form used for hashing.
 *
 * Forgiving on purpose: people retype these from an email into a form.
 * - case is irrelevant
 * - hyphens, spaces, underscores are cosmetic
 * - I/L -> 1 and O -> 0, since those glyphs are not in the alphabet and can
 *   only ever be a misread
 *
 * Returns the bare 12-char string, or null if it cannot be a valid code.
 * Oversized input is rejected before any regex work is done.
 */
export function normalizeCode(raw: string): string | null {
  if (raw.length > MAX_CODE_INPUT) return null;

  const cleaned = raw
    .toUpperCase()
    .replace(/[\s\-_]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');

  if (cleaned.length !== CODE_CHARS) return null;
  for (const ch of cleaned) {
    if (!ALPHABET.includes(ch)) return null;
  }
  return cleaned;
}
