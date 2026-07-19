/**
 * Per-IP rate limiting via Durable Objects.
 *
 * MISSION CONSTRAINT — read this before changing anything here.
 *
 * We publicly claim we do not collect IP addresses. That claim must stay true.
 * So this limiter never stores a raw IP anywhere:
 *
 *   1. The caller HMACs the IP with the server pepper before we ever see it.
 *      The Durable Object ID is derived from that hash, so even the DO's own
 *      name is not an address.
 *   2. We store only a counter and a window expiry. No address, no user agent,
 *      no path, no correlation key.
 *   3. State self-expires. Nothing accumulates into a history.
 *
 * The result: an attacker with full access to our Durable Object storage
 * learns "some hashed identifier made N requests in the last 15 minutes" and
 * cannot reverse it to an address without the pepper.
 *
 * Cloudflare still sees the real client IP at the edge — that is unavoidable
 * for anyone using a CDN, and the spec is honest about it (§2, Cloudflare
 * warrant surface). What we control is what WE persist, and we persist none.
 */

import { hmacHex } from './crypto';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
  /** Attempts used in the current window — drives progressive Turnstile. */
  used: number;
}

interface Bucket {
  count: number;
  resetAt: number; // epoch ms
}

export class IpRateLimiter implements DurableObject {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const limit = Number(url.searchParams.get('limit') ?? '5');
    const windowSec = Number(url.searchParams.get('window') ?? '900'); // 15 min

    const now = Date.now();
    let bucket = await this.state.storage.get<Bucket>('b');

    // A fresh window means a fresh alarm; an ongoing window already has one.
    const isNewWindow = !bucket || bucket.resetAt <= now;
    if (isNewWindow) {
      bucket = { count: 0, resetAt: now + windowSec * 1000 };
    }

    bucket!.count += 1;

    const allowed = bucket!.count <= limit;
    const retryAfterSeconds = allowed ? 0 : Math.ceil((bucket!.resetAt - now) / 1000);

    await this.state.storage.put('b', bucket);
    if (isNewWindow) {
      // Hard guarantee that state disappears. Nothing outlives its window.
      await this.state.storage.setAlarm(bucket!.resetAt);
    }

    const result: RateLimitResult = {
      allowed,
      remaining: Math.max(0, limit - bucket!.count),
      retryAfterSeconds,
      used: bucket!.count,
    };

    return new Response(JSON.stringify(result), {
      headers: { 'content-type': 'application/json' },
    });
  }

  /** Window elapsed — erase everything. */
  async alarm(): Promise<void> {
    await this.state.storage.deleteAll();
  }
}

/**
 * Derive a Durable Object name from an IP without ever persisting the IP.
 * Same HMAC construction as the email lookup hash, different pepper input
 * domain so the two can never be cross-correlated.
 */
export async function ipBucketId(ip: string, pepperB64: string): Promise<string> {
  // Domain-separated so an IP hash can never equal an email or invite hash.
  return hmacHex('ip', ip, pepperB64);
}
