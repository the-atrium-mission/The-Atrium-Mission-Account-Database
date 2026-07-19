/**
 * The Atrium Mission — Phase 0.5 pre-alpha signup Worker.
 *
 * Scope, deliberately small:
 *   POST /api/signup        reserve a handle + register interest
 *   GET  /api/check-handle  live availability while typing
 *
 * What this endpoint CANNOT do, by design: set a password, hold a Sentinel
 * key, create a session, log anyone in. Phase 0.5 exists to reserve handles
 * and nothing else, which keeps the warrant-return surface near zero during
 * the window where our data sits on Cloudflare rather than our own hardware.
 * Spec ref: atrium-infrastructure-user-db.md §2 (item 2), §3.
 */

import { emailHash, encrypt, hmacHex, isoWeek } from './crypto';
import { validateHandle } from './handles';
import { MAX_CODE_INPUT, normalizeCode } from './invites';
import { IpRateLimiter, ipBucketId } from './ratelimit';

export { IpRateLimiter };

export interface Env {
  DB: D1Database;
  RATE_LIMITER: DurableObjectNamespace;
  EMAIL_HMAC_PEPPER: string;   // base64, 32 bytes. NEVER leaves Cloudflare.
  EMAIL_AES_KEY: string;       // base64, exactly 32 bytes
  INVITE_HMAC_PEPPER: string;  // base64, 32 bytes. Also held on the founder workstation.
  TURNSTILE_SECRET: string;
  ALLOWED_ORIGIN: string;      // e.g. https://theatriummission.com
}

/* ------------------------------------------------------------------ */
/* Limits                                                              */
/* ------------------------------------------------------------------ */

const SIGNUP_LIMIT = 5;          // per IP
const SIGNUP_WINDOW = 900;       // 15 minutes
const TURNSTILE_AFTER = 2;       // challenge from the 3rd attempt onward

// Lowered from 60. During closed alpha the set of reserved handles IS the
// membership list, so this endpoint is a cohort-enumeration surface. 20/min
// is still far above what a human typing into a form will ever need.
const CHECK_LIMIT = 20;
const CHECK_WINDOW = 60;

const MAX_EMAIL_LEN = 254;       // RFC 5321
const MAX_NOTES_LEN = 1000;
const MAX_HANDLE_INPUT = 64;

/**
 * Hard cap on request body size. Every field limit above sums to well under
 * 2 KB; 8 KB leaves room for encoding overhead and nothing else. Enforced
 * BEFORE JSON parsing so an oversized body is never materialised or walked.
 */
const MAX_BODY_BYTES = 8192;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      // No API response may be stored by any intermediary. Availability
      // answers and signup outcomes are not cacheable data.
      'cache-control': 'no-store',
      ...extra,
    },
  });
}

function corsHeaders(env: Env): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };
}

/**
 * Shape check only. We do not verify deliverability here — probing mail
 * servers at signup would leak our interest in an address to third parties.
 */
function looksLikeEmail(e: string): boolean {
  if (e.length > MAX_EMAIL_LEN || e.length < 5) return false;
  return /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(e);
}

/** Reject anything that is not a plain JSON object. */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Read and parse a size-capped JSON body.
 * Returns null on anything malformed, oversized, or not an object.
 */
async function readJsonBody(request: Request): Promise<Record<string, unknown> | null> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;

  // content-length can be absent (chunked). Re-check the materialised body.
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) return null;

  try {
    const parsed = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

/** Coerce an untrusted field to a bounded string. Non-strings become ''. */
function str(v: unknown, maxLen: number): string {
  return typeof v === 'string' ? v.slice(0, maxLen).trim() : '';
}

async function checkRate(
  env: Env,
  ip: string,
  bucket: string,
  limit: number,
  windowSec: number,
) {
  const id = await ipBucketId(`${bucket}:${ip}`, env.EMAIL_HMAC_PEPPER);
  const stub = env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(id));
  const res = await stub.fetch(`https://rl.internal/?limit=${limit}&window=${windowSec}`);
  return (await res.json()) as {
    allowed: boolean;
    remaining: number;
    retryAfterSeconds: number;
    used: number;
  };
}

async function verifyTurnstile(token: string, secret: string, ip: string): Promise<boolean> {
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  form.append('remoteip', ip);

  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: form,
  });
  if (!res.ok) return false;
  const data = (await res.json()) as { success: boolean };
  return data.success === true;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

async function handleCheck(request: Request, env: Env, ip: string): Promise<Response> {
  const rate = await checkRate(env, ip, 'check', CHECK_LIMIT, CHECK_WINDOW);
  if (!rate.allowed) {
    return json({ error: 'Too many requests.' }, 429, {
      'Retry-After': String(rate.retryAfterSeconds),
    });
  }

  const raw = (new URL(request.url).searchParams.get('h') ?? '').slice(0, MAX_HANDLE_INPUT);
  const check = validateHandle(raw);
  if (!check.ok) return json({ available: false, reason: check.reason });

  const row = await env.DB.prepare(
    'SELECT 1 FROM pre_alpha_signups WHERE handle_reserved = ?',
  )
    .bind(check.normalized)
    .first();

  return row
    ? json({ available: false, reason: 'That handle is already reserved.' })
    : json({ available: true });
}

/**
 * The single response returned whenever a signup request is well-formed and
 * carried a valid, unused invite — regardless of whether a row was actually
 * created.
 *
 * This is the anti-enumeration primitive. See the email-collision branch.
 */
const SIGNUP_ACCEPTED = { ok: true, message: 'Reservation received.' };

async function handleSignup(request: Request, env: Env, ip: string): Promise<Response> {
  const rate = await checkRate(env, ip, 'signup', SIGNUP_LIMIT, SIGNUP_WINDOW);
  if (!rate.allowed) {
    return json(
      { error: 'Too many signup attempts. Try again shortly.' },
      429,
      { 'Retry-After': String(rate.retryAfterSeconds) },
    );
  }

  const body = await readJsonBody(request);
  if (!body) return json({ error: 'Malformed request.' }, 400);

  const email = str(body.email, MAX_EMAIL_LEN + 1);
  const handleRaw = str(body.handle, MAX_HANDLE_INPUT);
  const notes = str(body.notes, MAX_NOTES_LEN + 1);
  const turnstileToken = str(body.turnstile_token, 4096);
  const inviteRaw = str(body.invite_code, MAX_CODE_INPUT);
  const ageConfirmed = body.age_confirmed === true;
  const foundingCircle = body.founding_circle === true;
  const myceliumHost = body.mycelium_host === true;

  // Progressive challenge: first two attempts pass clean, then we require it.
  if (rate.used > TURNSTILE_AFTER) {
    if (!turnstileToken || !(await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET, ip))) {
      return json({ error: 'Verification required.', needs_turnstile: true }, 403);
    }
  }

  if (!ageConfirmed) {
    return json({ error: 'You must confirm you are 13 or older.' }, 400);
  }
  if (!looksLikeEmail(email)) {
    return json({ error: 'Enter a valid email address.' }, 400);
  }
  if (notes.length > MAX_NOTES_LEN) {
    return json({ error: `Note must be ${MAX_NOTES_LEN} characters or fewer.` }, 400);
  }

  const check = validateHandle(handleRaw);
  if (!check.ok) return json({ error: check.reason }, 400);

  // --- Invite gate ------------------------------------------------------
  //
  // Closed alpha: no code, no row. This is what lets us defer email
  // confirmation safely — an attacker cannot burn a handle they were never
  // invited to claim.
  //
  // Every rejection returns the SAME message. Distinguishing "no such code"
  // from "already redeemed" would let someone brute-force the code space and
  // learn which guesses were real.
  const normalizedCode = normalizeCode(inviteRaw);
  if (!normalizedCode) {
    return json({ error: 'That invite code is not valid.' }, 403);
  }
  const codeHash = await hmacHex('invite', normalizedCode, env.INVITE_HMAC_PEPPER);

  // Atomic claim. The `used_week IS NULL` predicate is what makes this
  // race-safe: two simultaneous requests with the same code both run this
  // UPDATE, and SQLite guarantees exactly one reports changes === 1.
  // Claiming BEFORE any lookup means the code is spent by the time we touch
  // anything that could reveal state — which is what kills the email oracle.
  const claim = await env.DB.prepare(
    'UPDATE invite_codes SET used_week = ? WHERE code_hash = ? AND used_week IS NULL',
  )
    .bind(isoWeek(), codeHash)
    .run();

  if (claim.meta.changes !== 1) {
    return json({ error: 'That invite code is not valid.' }, 403);
  }

  /** Undo the claim so a failed signup does not silently consume an invite. */
  const releaseCode = async () => {
    try {
      await env.DB.prepare(
        'UPDATE invite_codes SET used_week = NULL WHERE code_hash = ? AND used_by IS NULL',
      )
        .bind(codeHash)
        .run();
    } catch {
      console.error('invite release failed');
    }
  };

  // Handle collisions are safe to disclose — handles are public by definition,
  // and /api/check-handle answers the same question for free. Release the code
  // so the user can retry with a different handle.
  const handleTaken = await env.DB.prepare(
    'SELECT 1 FROM pre_alpha_signups WHERE handle_reserved = ?',
  )
    .bind(check.normalized)
    .first();

  if (handleTaken) {
    await releaseCode();
    return json({ error: 'That handle is already reserved.' }, 409);
  }

  const hash = await emailHash(email, env.EMAIL_HMAC_PEPPER);

  // Email collisions are NOT safe to disclose. Membership in the closed alpha
  // is exactly the kind of thing we promise not to reveal.
  //
  // Two properties make this non-enumerable:
  //   1. The response is byte-identical to a successful signup.
  //   2. The invite code stays SPENT. Probing an address costs a code, so one
  //      code buys one guess, not unlimited guesses.
  // Both are required. Dropping either one reopens the oracle.
  const emailTaken = await env.DB.prepare(
    'SELECT 1 FROM pre_alpha_signups WHERE email_hash = ?',
  )
    .bind(hash)
    .first();

  if (emailTaken) {
    return json(SIGNUP_ACCEPTED, 201);
  }

  const emailEnc = await encrypt(email, env.EMAIL_AES_KEY);
  const notesEnc = notes.length > 0 ? await encrypt(notes, env.EMAIL_AES_KEY) : null;

  let signupId: number | null = null;

  try {
    const inserted = await env.DB.prepare(
      `INSERT INTO pre_alpha_signups
         (email_hash, email_enc, handle_reserved, handle_display,
          founding_circle, mycelium_host, age_confirmed, notes_enc, created_week)
       VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
    )
      .bind(
        hash,
        emailEnc,
        check.normalized,
        check.display,
        foundingCircle ? 1 : 0,
        myceliumHost ? 1 : 0,
        notesEnc,
        isoWeek(),
      )
      .run();

    signupId = inserted.meta.last_row_id ?? null;
  } catch {
    // The pre-checks above handle the common cases; reaching here means either
    // a genuine fault or a race that the UNIQUE constraints caught. We do NOT
    // inspect the error text — matching on D1's wording is brittle, and a
    // wording change would silently turn the email branch into a 500, which is
    // itself an oracle. One opaque response covers every case.
    await releaseCode();
    console.error('signup insert failed');
    return json({ error: 'Something went wrong. Try again.' }, 500);
  }

  // Link the redeemed invite to the row it created. Best-effort: the code is
  // already correctly marked used; this is founder-side accounting only.
  if (signupId !== null) {
    try {
      await env.DB.prepare('UPDATE invite_codes SET used_by = ? WHERE code_hash = ?')
        .bind(signupId, codeHash)
        .run();
    } catch {
      console.error('invite link failed');
    }
  }

  // TODO(email): send confirmation via Postmark before opening beyond invites.
  // Safe to defer while the invite gate is the only way in. Once it ships, the
  // email becomes the channel that tells the user the real outcome — which is
  // why the HTTP response above is deliberately non-committal.

  return json(SIGNUP_ACCEPTED, 201);
}

/* ------------------------------------------------------------------ */
/* Entry                                                               */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const cors = corsHeaders(env);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    // Set by Cloudflare at the edge and not client-spoofable. If it is absent
    // we are not receiving normal edge traffic, so we fail CLOSED. Falling
    // back to a placeholder would drop every such request into one shared
    // rate-limit bucket — either a bypass or a self-inflicted DoS.
    const ip = request.headers.get('CF-Connecting-IP');
    if (!ip) {
      return json({ error: 'Bad request.' }, 400, cors);
    }

    let res: Response;
    try {
      if (url.pathname === '/api/check-handle' && request.method === 'GET') {
        res = await handleCheck(request, env, ip);
      } else if (url.pathname === '/api/signup' && request.method === 'POST') {
        res = await handleSignup(request, env, ip);
      } else {
        res = json({ error: 'Not found.' }, 404);
      }
    } catch {
      // Never surface internal error text — it leaks schema and stack shape.
      console.error('unhandled worker error');
      res = json({ error: 'Something went wrong.' }, 500);
    }

    const out = new Response(res.body, res);
    for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
    out.headers.set('X-Content-Type-Options', 'nosniff');
    out.headers.set('Referrer-Policy', 'no-referrer');
    out.headers.set('X-Frame-Options', 'DENY');
    return out;
  },
};
