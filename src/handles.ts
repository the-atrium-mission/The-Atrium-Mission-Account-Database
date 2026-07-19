/**
 * Handle validation + reserved-handle enforcement.
 * Spec ref: atrium-infrastructure-user-db.md §16.
 *
 * This list is openly published — it is not a secret, and treating it as one
 * would be pointless since anyone can probe it via the availability endpoint.
 *
 * Phase 1 note: this file is the TypeScript twin of internal/handles/reserved.go.
 * When the Go backend lands, these two lists MUST stay in sync or a handle
 * reserved in pre-alpha could be claimed for real at activation.
 */

const RESERVED_EXACT = new Set<string>([
  // System / roles
  'admin', 'administrator', 'root', 'system', 'mod', 'moderator', 'staff',
  'official', 'help', 'helpdesk', 'info', 'contact', 'abuse', 'dmca', 'legal',
  'support', 'security', 'team', 'privacy', 'compliance', 'gdpr', 'ccpa',
  'transparency', 'audit', 'auditor',

  // Product names
  'atrium', 'theatriummission', 'mission', 'sentinel', 'mycelium', 'atriummission',

  // Email locals used by automated systems
  'noreply', 'no-reply', 'postmaster', 'webmaster', 'hostmaster', 'mail',
  'mailer', 'mailer-daemon', 'daemon', 'bounces',

  // Impersonation risks
  'anonymous', 'anon', 'guest', 'user', 'me', 'you', 'null', 'undefined',
  'deleted', 'unknown', 'banned', 'suspended', 'removed', 'blocked',
]);

/** Reserved prefixes — the whole namespace under each is unavailable. */
const RESERVED_PREFIXES = ['atrium-', 'mission-', 'official-', 'verified-'];

/** 3–20 chars, alphanumeric + underscore, must start and end alphanumeric. */
const HANDLE_RE = /^[a-z0-9](?:[a-z0-9_]{1,18})[a-z0-9]$/;

/**
 * Digit-for-letter substitutions used to evade a reserved-word list.
 * `adm1n`, `m0derat0r`, `5upport` and friends.
 *
 * Note the alphabet is ASCII-only by construction (HANDLE_RE), which already
 * makes Unicode homoglyph impersonation impossible. This closes the remaining
 * ASCII case.
 */
const DELEET: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a',
  '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
};

/**
 * Collapse a handle toward its "impersonation shape": strip separators and
 * undo digit substitutions. Used ONLY for reserved-word comparison, never for
 * uniqueness — two users may legitimately hold handles that collapse to the
 * same shape.
 */
function confusableForm(normalized: string): string {
  let out = '';
  for (const ch of normalized.replace(/_/g, '')) {
    out += DELEET[ch] ?? ch;
  }
  return out;
}

export type HandleCheck =
  | { ok: true; normalized: string; display: string }
  | { ok: false; reason: string };

/**
 * Normalize for uniqueness. Lowercase only.
 *
 * We deliberately do NOT collapse underscores or strip characters. Doing so
 * would make visually distinct handles collide, which is confusing rather than
 * protective.
 */
export function normalizeHandle(h: string): string {
  return h.trim().toLowerCase();
}

export function validateHandle(raw: string): HandleCheck {
  const display = raw.trim();
  const normalized = normalizeHandle(display);

  if (normalized.length < 3) return { ok: false, reason: 'Handle must be at least 3 characters.' };
  if (normalized.length > 20) return { ok: false, reason: 'Handle must be 20 characters or fewer.' };

  if (!HANDLE_RE.test(normalized)) {
    return {
      ok: false,
      reason: 'Handles can use letters, numbers, and underscores, and must start and end with a letter or number.',
    };
  }

  if (RESERVED_EXACT.has(normalized)) {
    return { ok: false, reason: 'That handle is reserved.' };
  }

  // Also block digit-substituted lookalikes: adm1n, m0derat0r, 5upport.
  const confusable = confusableForm(normalized);
  if (RESERVED_EXACT.has(confusable)) {
    return { ok: false, reason: 'That handle is too close to a reserved name.' };
  }

  for (const p of RESERVED_PREFIXES) {
    const bare = p.slice(0, -1); // "atrium-" -> "atrium"
    if (normalized.startsWith(p) || confusable.startsWith(bare)) {
      return { ok: false, reason: `Handles starting with "${bare}" are reserved.` };
    }
  }

  return { ok: true, normalized, display };
}
