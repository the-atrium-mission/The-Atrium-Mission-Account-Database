/**
 * Cloudflare Access JWT verification.
 *
 * Access sits in front of /admin and rejects unauthenticated requests at the
 * edge, before this Worker runs. It then injects a signed JWT identifying who
 * got through.
 *
 * We verify that JWT rather than trusting the header's presence. Presence
 * alone is not evidence: if the route were ever misconfigured, or the Worker
 * reachable by some path Access does not cover, an attacker could simply set
 * the header themselves. A signature check makes that worthless.
 *
 * Checked: RS256 signature against Cloudflare's published keys, audience,
 * issuer, and expiry. All four must pass.
 */

interface Jwk {
  kid: string;
  kty: string;
  alg: string;
  n: string;
  e: string;
}

/** JWKS cached per isolate. Cheap, and Access rotates keys slowly. */
let jwksCache: { keys: Jwk[]; fetchedAt: number } | null = null;
const JWKS_TTL_MS = 60 * 60 * 1000; // 1 hour

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson(s: string): any {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

async function getJwks(teamDomain: string): Promise<Jwk[]> {
  const now = Date.now();
  if (jwksCache && now - jwksCache.fetchedAt < JWKS_TTL_MS) return jwksCache.keys;

  const res = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error('access jwks fetch failed');
  const data = (await res.json()) as { keys: Jwk[] };
  jwksCache = { keys: data.keys, fetchedAt: now };
  return data.keys;
}

export interface AccessIdentity {
  email: string;
  sub: string;
}

/**
 * Returns the verified identity, or null if the request is not a valid
 * Access-authenticated request. Callers must treat null as a hard reject.
 */
export async function verifyAccess(
  request: Request,
  teamDomain: string,
  expectedAud: string,
): Promise<AccessIdentity | null> {
  const token =
    request.headers.get('Cf-Access-Jwt-Assertion') ??
    (request.headers.get('cookie') ?? '').match(/CF_Authorization=([^;]+)/)?.[1];

  if (!token) return null;

  const parts = token.split('.');
  if (parts.length !== 3) return null;

  let header: any, payload: any;
  try {
    header = b64urlToJson(parts[0]);
    payload = b64urlToJson(parts[1]);
  } catch {
    return null;
  }

  if (header.alg !== 'RS256') return null;

  // Audience must match this specific Access application. Without this check a
  // valid token for ANY app in the same Access account would be accepted here.
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(expectedAud)) return null;

  if (payload.iss !== `https://${teamDomain}`) return null;

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
  if (typeof payload.nbf === 'number' && payload.nbf > now) return null;

  const keys = await getJwks(teamDomain);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );

  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    b64urlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
  );
  if (!ok) return null;

  return { email: String(payload.email ?? ''), sub: String(payload.sub ?? '') };
}
