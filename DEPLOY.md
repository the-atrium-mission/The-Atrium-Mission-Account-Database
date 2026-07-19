# Phase 0.5 — Deployment Runbook

Pre-alpha handle reservation. Cloudflare Workers + D1.

Follow in order. Each step has a verification line — do not skip them; several
failures here are silent.

## 0. Prerequisites

```bash
node --version     # v22+
npx wrangler --version
npx wrangler login # opens a browser
npx wrangler whoami
```

`whoami` must show the account that owns `theatriummission.com`.

## 1. Create the D1 database

```bash
npx wrangler d1 create atrium-prealpha
```

Copy the returned `database_id` into `wrangler.toml`, replacing
`PASTE_DATABASE_ID_HERE`.

The id is an identifier, not a credential. It is safe to commit.

```bash
grep database_id wrangler.toml    # must NOT still say PASTE_
```

## 2. Apply the schema

Order matters - `invite_codes.used_by` references `pre_alpha_signups(id)`.

```bash
npx wrangler d1 execute atrium-prealpha --file=./schema.sql --remote
npx wrangler d1 execute atrium-prealpha --file=./migrations/002_invites.sql --remote
```

Verify both tables exist:

```bash
npx wrangler d1 execute atrium-prealpha --remote \
  --command "SELECT name FROM sqlite_master WHERE type='table'"
```

Expect `pre_alpha_signups` and `invite_codes`.

## 3. Generate and set secrets

Generate three 32-byte values. **Keep the invite pepper** — you need it locally
to mint codes. The other two should be set and forgotten; they live only in
Cloudflare.

```bash
openssl rand -base64 32   # -> EMAIL_HMAC_PEPPER
openssl rand -base64 32   # -> EMAIL_AES_KEY
openssl rand -base64 32   # -> INVITE_HMAC_PEPPER  (save this one)
```

```bash
npx wrangler secret put EMAIL_HMAC_PEPPER
npx wrangler secret put EMAIL_AES_KEY
npx wrangler secret put INVITE_HMAC_PEPPER
npx wrangler secret put TURNSTILE_SECRET     # from step 4
```

```bash
npx wrangler secret list   # 4 entries, values never shown
```

### Storing INVITE_HMAC_PEPPER

It is needed on the workstation that generates invites, so it needs a home.
A password manager entry is fine. What is not fine: a shell history file, a
note in the repo, or a chat message.

```bash
read -rs INVITE_HMAC_PEPPER && export INVITE_HMAC_PEPPER
```

`read -rs` keeps it off the terminal and out of history.

### Rotation impact — read before ever rotating

| Secret | Effect of rotating |
|---|---|
| `TURNSTILE_SECRET` | None. Rotate freely. |
| `INVITE_HMAC_PEPPER` | All unredeemed codes become invalid. Reissue them. |
| `EMAIL_AES_KEY` | Must decrypt every `email_enc` with the old key and re-encrypt. Keep the old key until verified. |
| `EMAIL_HMAC_PEPPER` | Invalidates every `email_hash`. Requires the AES key to recompute. This is a migration, not a config change. |

Never rotate `EMAIL_HMAC_PEPPER` and `EMAIL_AES_KEY` together — the AES key is
what recovers the plaintext needed to rebuild the hashes.

## 4. Turnstile

Cloudflare dashboard → Turnstile → Add widget.

- Domain: `accounts.theatriummission.com`
- Mode: **Managed**

Two keys come out:

- **Site key** → `wrangler.toml` under `[vars]`, replacing
  `PASTE_TURNSTILE_SITE_KEY_HERE`. Public by design — it is rendered into the
  page HTML. Safe to commit.
- **Secret key** → `wrangler secret put TURNSTILE_SECRET`. Never in the repo.

## 4b. Cloudflare Access — gate the admin panel

`/admin` can mint invite codes and read every reserved handle. It must not be
reachable by anyone but the two of you.

Cloudflare dashboard → **Zero Trust** → Access → Applications → Add an
application → **Self-hosted**.

| Field | Value |
|---|---|
| Application name | `Atrium Admin` |
| Session duration | 8 hours or less |
| Subdomain | `accounts` |
| Domain | `theatriummission.com` |
| Path | `admin` |

Add a policy:

| Field | Value |
|---|---|
| Policy name | `Founders` |
| Action | Allow |
| Include | **Emails** → both founder addresses, listed individually |

Use `Emails`, not `Emails ending in`. A domain-wide rule grants access to every
current and future address on that domain, including any that gets created
later without your involvement.

Then copy two values into `wrangler.toml` under `[vars]`:

- **Team domain** — Zero Trust → Settings → Custom Pages, shown as
  `<team>.cloudflareaccess.com` → `ACCESS_TEAM_DOMAIN`
- **Application Audience (AUD) tag** — on the application's Overview tab →
  `ACCESS_AUD`

Neither is a secret. The AUD tag is only meaningful alongside a valid
Cloudflare-signed JWT, and the Worker verifies that signature on every request.
Safe to commit.

**Why both layers.** Access blocks unauthenticated requests at the edge. The
Worker independently verifies the JWT signature, audience, issuer, and expiry.
That second check is what makes a forged `Cf-Access-Jwt-Assertion` header
worthless if a request ever reaches the Worker without passing through Access.

## 5. Deploy

```bash
npm run typecheck
npx wrangler deploy
```

### DNS record required first

This Worker lives on its own hostname, which must exist before the route can
attach.

Dashboard → DNS → Add record:

| Field | Value |
|---|---|
| Type | `AAAA` |
| Name | `accounts` |
| IPv4/IPv6 | `100::` (discard prefix) |
| Proxy status | **Proxied** (orange cloud) — required |

The `100::` target is the standard placeholder for a hostname served entirely
by a Worker. Nothing routes to it; the orange cloud means Cloudflare intercepts
the request at the edge and hands it to the Worker before any origin lookup.

Grey cloud (DNS-only) will not work — the Worker never runs.

Then confirm the route attached: Dashboard → Workers & Pages → this Worker →
Settings → Domains & Routes. `accounts.theatriummission.com/*` must be listed.

## 6. Verify the deployment

```bash
# page loads on the auth origin
curl -sI https://accounts.theatriummission.com/ | head -1       # 200

# old path still resolves for anyone with a stale link
curl -sI https://accounts.theatriummission.com/accounts | head -1  # 301

# workers.dev is OFF
curl -sI https://atrium-accounts.<subdomain>.workers.dev/ | head -1  # 404/error

# handle check works
curl -s "https://accounts.theatriummission.com/api/check-handle?h=testhandle"   # {"available":true}

# reserved handles are blocked
curl -s "https://accounts.theatriummission.com/api/check-handle?h=admin"        # available:false
curl -s "https://accounts.theatriummission.com/api/check-handle?h=adm1n"        # available:false

# admin is gated — no Access session means no entry
curl -sI https://accounts.theatriummission.com/admin | head -1     # 302 to Access login

# signup rejects a bad invite
curl -s -X POST https://accounts.theatriummission.com/api/signup \
  -H 'content-type: application/json' \
  -d '{"invite_code":"AAAA-AAAA-AAAA","handle":"nobody","email":"a@b.co","age_confirmed":true}'
# {"error":"That invite code is not valid."}
```

If the workers.dev check returns 200, `workers_dev = false` did not take
effect. Fix before announcing the URL — that hostname bypasses every WAF and
firewall rule on the zone.

## 7. Mint the first invite batch

Open `https://accounts.theatriummission.com/admin`, authenticate through
Access, set a count and cohort label, and generate.

Codes are displayed **once** and are not stored anywhere. Only their hashes
reach the database. Copy them before leaving the page.

Prefer this over the CLI script: minting through the panel means
`INVITE_HMAC_PEPPER` stays inside Cloudflare and never touches a workstation.

### CLI fallback

Still available if the panel is unreachable. Requires the pepper locally, which
is the reason it is the fallback rather than the default.

```bash
read -rs INVITE_HMAC_PEPPER && export INVITE_HMAC_PEPPER
node scripts/gen-invites.mjs 50 spirit2.0-batch1
npx wrangler d1 execute atrium-prealpha \
  --file=./out/invites-spirit2.0-batch1-<week>.sql --remote
shred -u out/*.sql && rmdir out
```

## 8. End-to-end test

Use one real code on `https://accounts.theatriummission.com`. Reserve a handle
you intend to keep (a founder handle is a good choice).

Confirm afterwards:

```bash
npx wrangler d1 execute atrium-prealpha --remote \
  --command "SELECT handle_display, founding_circle, mycelium_host, created_week FROM pre_alpha_signups"

npx wrangler d1 execute atrium-prealpha --remote \
  --command "SELECT COUNT(*) AS redeemed FROM invite_codes WHERE used_week IS NOT NULL"
```

`email_hash` and `email_enc` are deliberately excluded from that query. There
is no operational reason to select them, and getting into the habit of
selecting `*` on this table is how plaintext ends up in a terminal scrollback.

## 9. Confirm no IP logging

Two separate settings, both must be off:

1. `wrangler.toml` → `[observability] enabled = false` — already set.
2. Dashboard → Workers & Pages → this Worker → Settings → **Logpush must be
   off**. This is not controlled by the config file.

The public claim is that IP addresses are not collected. Cloudflare's request
logs include client IP. Leaving either on makes the claim false via the vendor
regardless of what the Worker code stores.

## Ongoing operations

**Mint more invites / check uptake**

`https://accounts.theatriummission.com/admin`

**Redeploy after a code change**

```bash
npm run typecheck && npx wrangler deploy
```

**Back out a bad deploy**

Dashboard → Workers & Pages → this Worker → Deployments → Rollback.

## Known gaps at this stage

- **No confirmation email.** Acceptable only while the invite gate is the sole
  way in. Becomes mandatory before signup opens without a code — otherwise
  anyone can burn a handle with an address they do not own.
- **No self-service deletion.** Handle deletion requests are manual until
  Phase 1.
- **The admin panel cannot read email addresses.** There is no code path that
  decrypts `email_enc`, and none should be added. An admin UI that can dump the
  user list makes the envelope encryption decorative — one stolen session and
  the attacker has everything. Bulk contact, if ever needed, is a deliberate
  batch job with its own key access, not a screen.
- **Phase 0.5 data lives on Cloudflare.** Both the data and its keys sit in one
  vendor's account, so a warrant served on Cloudflare would reach both. This is
  the documented trade for the pre-alpha window and is why Phase 0.5 collects
  no passwords and no key material. Spec §2, item 2.
