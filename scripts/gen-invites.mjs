#!/usr/bin/env node
/**
 * Invite code generator — RUN LOCALLY ONLY.
 *
 *   node scripts/gen-invites.mjs <count> <note>
 *   node scripts/gen-invites.mjs 50 spirit2.0-batch1
 *
 * Requires INVITE_HMAC_PEPPER in the environment. This is a SEPARATE secret
 * from EMAIL_HMAC_PEPPER by design — the email pepper must never leave
 * Cloudflare, so it must never be needed by a script that runs on a laptop.
 *
 * Do NOT hardcode it, do NOT paste it into a shell that records history:
 *
 *   read -rs INVITE_HMAC_PEPPER && export INVITE_HMAC_PEPPER
 *   node scripts/gen-invites.mjs 50 spirit2.0-batch1
 *
 * Produces two things:
 *   1. stdout  — the plaintext codes. This is the ONLY time they exist.
 *                Distribute them, then close the terminal.
 *   2. out/invites-<note>.sql — hashes only, safe to run against D1.
 *
 * The plaintext codes are never written to disk by this script. If you pipe
 * stdout to a file, that file is now a credential — treat it accordingly and
 * shred it once distributed.
 *
 * out/ is gitignored. Verify with: git check-ignore -v out/
 */

import { webcrypto as crypto } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CODE_CHARS = 12;
const GROUP = 4;

function isoWeek(d = new Date()) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = t.getUTCDay() || 7;
  t.setUTCDate(t.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1));
  const week = Math.ceil(((t.getTime() - yearStart.getTime()) / 86400000 + 1) / 7);
  return t.getUTCFullYear() * 100 + week;
}

function generateCode() {
  const out = [];
  const max = Math.floor(256 / ALPHABET.length) * ALPHABET.length;
  while (out.length < CODE_CHARS) {
    const buf = crypto.getRandomValues(new Uint8Array(CODE_CHARS));
    for (const b of buf) {
      if (b >= max) continue;
      out.push(ALPHABET[b % ALPHABET.length]);
      if (out.length === CODE_CHARS) break;
    }
  }
  const groups = [];
  for (let i = 0; i < CODE_CHARS; i += GROUP) groups.push(out.slice(i, i + GROUP).join(''));
  return groups.join('-');
}

function normalizeCode(raw) {
  return raw.toUpperCase().replace(/[\s\-_]/g, '').replace(/[IL]/g, '1').replace(/O/g, '0');
}

async function hashCode(normalized, pepperB64) {
  const pepper = Buffer.from(pepperB64, 'base64');
  const key = await crypto.subtle.importKey(
    'raw',
    pepper,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`invite:${normalized}`));
  return Buffer.from(sig).toString('hex');
}

/* --------------------------------------------------------------------- */

const count = Number(process.argv[2]);
const note = process.argv[3];
const pepper = process.env.INVITE_HMAC_PEPPER;

if (!Number.isInteger(count) || count < 1 || count > 1000) {
  console.error('Usage: node scripts/gen-invites.mjs <count 1-1000> <note>');
  process.exit(1);
}
if (!note || !/^[a-z0-9._-]{1,40}$/i.test(note)) {
  console.error('Note must be a short cohort label: [a-z0-9._-], max 40 chars.');
  console.error('Use a COHORT name, never a person\'s name or handle.');
  process.exit(1);
}
if (!pepper) {
  console.error('INVITE_HMAC_PEPPER is not set. See the header of this file.');
  process.exit(1);
}
if (Buffer.from(pepper, 'base64').length !== 32) {
  console.error('INVITE_HMAC_PEPPER must decode to exactly 32 bytes.');
  process.exit(1);
}

const week = isoWeek();
const codes = new Set();
while (codes.size < count) codes.add(generateCode());

const values = [];
for (const code of codes) {
  const hash = await hashCode(normalizeCode(code), pepper);
  values.push(`  ('${hash}', ${week}, '${note}')`);
}

const sql = `-- ${count} invite codes, cohort "${note}", week ${week}
-- Hashes only. Plaintext codes were printed to the terminal and are not recoverable from this file.
INSERT INTO invite_codes (code_hash, issued_week, note) VALUES
${values.join(',\n')};
`;

mkdirSync('out', { recursive: true });
const path = `out/invites-${note}-${week}.sql`;
writeFileSync(path, sql, { mode: 0o600 });

console.log(`\n=== ${count} invite codes — cohort "${note}" ===`);
console.log('These are shown ONCE. They are not stored anywhere.\n');
for (const code of codes) console.log(`  ${code}`);
console.log(`\nHashes written to: ${path}`);
console.log(`Apply with:\n  wrangler d1 execute atrium-prealpha --file=./${path} --remote\n`);
console.log('Then distribute the codes above and clear your terminal.\n');
