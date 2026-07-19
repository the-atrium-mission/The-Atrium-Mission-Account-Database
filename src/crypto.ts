/**
 * Crypto primitives for Phase 0.5.
 *
 * Runtime: Cloudflare Workers. Web Crypto API only — no Node builtins.
 *
 * Two distinct operations, do not confuse them:
 *   emailHash()  -> irreversible lookup key. Uniqueness + dedup. Never reversed.
 *   encrypt()    -> reversible ciphertext. Only so we can email the user later.
 *
 * Phase 0.5 keys live in Workers Secrets and are DESTROYED after the
 * D1 -> Postgres migration completes. They never become the Phase 1 KEK.
 * Spec ref: atrium-infrastructure-user-db.md §14.
 */

const IV_BYTES = 12; // AES-GCM standard nonce length

/** Decode a base64 secret from Workers Secrets into raw bytes. */
export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Domain-separated HMAC-SHA256, hex output.
 *
 * EVERY caller must pass a domain. Two different kinds of value hashed under
 * the same pepper must never be able to produce the same digest — otherwise a
 * value from one namespace could be replayed into another. All current uses
 * route through here so the separation cannot be forgotten at a call site.
 */
export async function hmacHex(domain: string, value: string, pepperB64: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    b64ToBytes(pepperB64),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${domain}:${value}`));
  return bytesToHex(new Uint8Array(sig));
}

/**
 * Normalize an email before hashing so the same address always produces the
 * same lookup key.
 *
 * Deliberately conservative: trim + lowercase only.
 * We do NOT strip Gmail dots or +tags. Those are provider-specific rules,
 * they are not universally true, and applying them would silently merge
 * addresses the user considers distinct.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * HMAC-SHA256("email:" || normalized_email, pepper) -> hex.
 *
 * The pepper is server-side only. A stolen D1 snapshot alone cannot reverse
 * these hashes, and cannot confirm whether a guessed address is present.
 */
export async function emailHash(email: string, pepperB64: string): Promise<string> {
  return hmacHex('email', normalizeEmail(email), pepperB64);
}

/** Import the AES-256-GCM data key from Workers Secrets. */
async function importAesKey(keyB64: string): Promise<CryptoKey> {
  const raw = b64ToBytes(keyB64);
  if (raw.length !== 32) {
    throw new Error('EMAIL_AES_KEY must be exactly 32 bytes (256-bit) when base64-decoded');
  }
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * AES-256-GCM encrypt. Output layout: [12-byte IV][ciphertext || 16-byte tag].
 * A fresh random IV per call — never reused, never derived, never sequential.
 */
export async function encrypt(plaintext: string, keyB64: string): Promise<Uint8Array> {
  const key = await importAesKey(keyB64);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  const out = new Uint8Array(IV_BYTES + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), IV_BYTES);
  return out;
}

/**
 * AES-256-GCM decrypt. Used by the migration script, not by the signup path.
 * Throws on tag mismatch — tampered ciphertext fails loudly rather than
 * returning garbage.
 */
export async function decrypt(blob: Uint8Array, keyB64: string): Promise<string> {
  const key = await importAesKey(keyB64);
  const iv = blob.slice(0, IV_BYTES);
  const ct = blob.slice(IV_BYTES);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

/**
 * ISO-8601 week number as YYYYWW (e.g. 202629).
 *
 * This is the ONLY temporal data we store. Not a timestamp. Week granularity
 * means we can answer "how did signups trend" without ever holding a record
 * precise enough to correlate a user against external logs.
 */
export function isoWeek(d: Date = new Date()): number {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  // ISO weeks run Mon-Sun; shift to the Thursday of this week, which always
  // falls in the ISO week-numbering year.
  const day = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((t.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return t.getUTCFullYear() * 100 + week;
}
