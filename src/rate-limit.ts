/**
 * In-memory rate limiting for the /api surface (R97-04 partial).
 *
 * Zero dependencies: a sliding-window limiter over per-(rule, IP)
 * timestamp arrays, plus an H11-style client-IP resolver.
 *
 * IP resolution (same posture as SubNation's cloudflareClientIp
 * middleware / the dashboard's clientIp, hardened for Render):
 *
 *   1. Render's edge APPENDS the true connecting peer as the RIGHTMOST
 *      X-Forwarded-For entry — that entry is never client-controlled,
 *      so it is the default client identity (matches dashboard.ts).
 *   2. `CF-Connecting-IP` is honoured ONLY when the rightmost XFF peer
 *      is a published Cloudflare range (the request genuinely traversed
 *      CF). A forged CF header sent directly to the *.onrender.com
 *      origin is ignored — otherwise every IP-keyed bucket would be
 *      attacker-chosen data (H11).
 *   3. No XFF at all (local/test traffic) → socket address.
 *
 * Bounded memory: expired windows are swept every 60s (timer unref'd,
 * armed only when the middleware factory is invoked by index.ts — the
 * module itself stays side-effect-free for tests).
 *
 * تحديد المعدل لواجهة /api — نافذة منزلقة بلا تبعيات + استخراج IP
 * بمنطق H11 (الوثوق بـ CF-Connecting-IP فقط حين يكون النظير الأيمن
 * في XFF ضمن نطاقات Cloudflare).
 */
import type { NextFunction, Request, Response } from "express";

// ── Cloudflare published ranges (cloudflare.com/ips-v4 & ips-v6) ─────────────
// Same tables as SubNation's backend/src/middlewares/cloudflareClientIp.ts —
// stable for years; keep in sync when CF announces changes.

const CF_IPV4_RANGES: ReadonlyArray<readonly [number, number]> = [
  cidr4("173.245.48.0/20"),
  cidr4("103.21.244.0/22"),
  cidr4("103.22.200.0/22"),
  cidr4("103.31.4.0/22"),
  cidr4("141.101.64.0/18"),
  cidr4("108.162.192.0/18"),
  cidr4("190.93.240.0/20"),
  cidr4("188.114.96.0/20"),
  cidr4("197.234.240.0/22"),
  cidr4("198.41.128.0/17"),
  cidr4("162.158.0.0/15"),
  cidr4("104.16.0.0/13"),
  cidr4("104.24.0.0/14"),
  cidr4("172.64.0.0/13"),
  cidr4("131.0.72.0/22"),
];

// [BigInt network, BigInt mask]
const CF_IPV6_RANGES: ReadonlyArray<readonly [bigint, bigint]> = [
  cidr6("2400:cb00::/32"),
  cidr6("2606:4700::/32"),
  cidr6("2803:f800::/32"),
  cidr6("2405:b500::/32"),
  cidr6("2405:8100::/32"),
  cidr6("2a06:98c0::/29"),
  cidr6("2c0f:f248::/29"),
];

function cidr4(cidr: string): readonly [number, number] {
  const [ip, bitsStr] = cidr.split("/");
  const bits = Number(bitsStr);
  const mask = bits === 0 ? 0 : (-1 << (32 - bits)) >>> 0;
  const parts = ip.split(".").map(Number);
  const addr = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  return [(addr & mask) >>> 0, mask] as const;
}

function cidr6(cidr: string): readonly [bigint, bigint] {
  const [ip, bitsStr] = cidr.split("/");
  const bits = BigInt(bitsStr);
  const expanded = expandIpv6(ip);
  // High-bits mask (leftmost `bits` positions) — mirrors the V1-M4 fix.
  const mask =
    bits === 0n
      ? 0n
      : ((1n << bits) - 1n) << (128n - bits);
  return [expanded & mask, mask] as const;
}

function expandIpv6(ip: string): bigint {
  // Handle "::" compression and IPv4-mapped tails.
  let full = ip;
  if (full.includes(".")) {
    const v4 = full.split(":").pop() ?? "";
    const segs = v4.split(".").map(Number);
    const v4hi = (segs[0] << 8) | segs[1];
    const v4lo = (segs[2] << 8) | segs[3];
    full = full.slice(0, full.lastIndexOf(":") + 1) + v4hi.toString(16) + ":" + v4lo.toString(16);
  }
  const doubleColonCount = (full.match(/::/g) ?? []).length;
  let head: string[], tail: string[];
  if (doubleColonCount > 0) {
    const idx = full.indexOf("::");
    head = full.slice(0, idx).split(":").filter(Boolean);
    tail = full.slice(idx + 2).split(":").filter(Boolean);
    const missing = 8 - head.length - tail.length;
    full = [...head, ...Array(missing).fill("0"), ...tail].join(":");
  } else {
    head = full.split(":").filter(Boolean);
  }
  const groups = full.split(":");
  let value = 0n;
  for (const g of groups) {
    value = (value << 16n) | BigInt(parseInt(g || "0", 16));
  }
  return value;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let addr = 0;
  for (const p of parts) {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    addr = ((addr << 8) | n) >>> 0;
  }
  return addr >>> 0;
}

export function isCloudflareIp(ip: string): boolean {
  const trimmed = ip.trim();
  if (trimmed.includes(":")) {
    try {
      const value = expandIpv6(trimmed);
      for (const [network, mask] of CF_IPV6_RANGES) {
        if ((value & mask) === network) return true;
      }
      return false;
    } catch {
      return false;
    }
  }
  const addr = ipv4ToInt(trimmed);
  if (addr === null) return false;
  for (const [network, mask] of CF_IPV4_RANGES) {
    if ((addr & mask) === (network & mask)) return true;
  }
  return false;
}

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]{2,45}$/;

/** Structural request shape so tests can pass plain objects. */
export interface IpRequestLike {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string | null };
}

function headerValue(req: IpRequestLike, name: string): string {
  const raw = req.headers[name];
  if (Array.isArray(raw)) return raw.join(",");
  return typeof raw === "string" ? raw : "";
}

/** The peer that actually connected to Render = RIGHTMOST XFF entry
 * (appended by the trusted Render hop — never client-controlled). */
export function renderFacingPeer(req: IpRequestLike): string | null {
  const xff = headerValue(req, "x-forwarded-for");
  if (xff.length === 0) return null;
  const entries = xff.split(",").map((e) => e.trim()).filter(Boolean);
  return entries.length > 0 ? entries[entries.length - 1] : null;
}

/**
 * Resolve the client IP for rate-limit keys:
 * CF-Connecting-IP (only via a verified Cloudflare hop) → rightmost XFF
 * (Render's appended peer) → socket address → "unknown".
 */
export function resolveClientIp(req: IpRequestLike): string {
  const peer = renderFacingPeer(req);
  const cfIp = headerValue(req, "cf-connecting-ip").trim();
  const cfWellFormed = cfIp.length > 0 && cfIp.length < 64 && (IPV4_RE.test(cfIp) || IPV6_RE.test(cfIp));
  if (cfWellFormed && peer != null && isCloudflareIp(peer)) {
    return cfIp;
  }
  if (peer) return peer;
  return req.socket?.remoteAddress ?? "unknown";
}

// ── Sliding-window limiter ───────────────────────────────────────────────────

export interface RateLimitRule {
  name: string;
  limit: number;
  windowMs: number;
}

export interface RateLimitVerdict {
  allowed: boolean;
  /** Bucket size (echoed in X-RateLimit-Limit). */
  limit: number;
  /** Requests still allowed inside the current window. */
  remaining: number;
  /** 0 when allowed; whole seconds until the oldest hit expires otherwise. */
  retryAfterSec: number;
}

/**
 * Sliding window: each (rule, key) keeps the timestamps of every request
 * inside the last `windowMs`. A request is allowed while fewer than
 * `limit` timestamps remain in-window; the retry hint is the time until
 * the OLDEST in-window hit slides out. `now` is injectable for tests.
 */
export class SlidingWindowLimiter {
  private readonly rules = new Map<string, RateLimitRule>();
  private readonly windows = new Map<string, Map<string, number[]>>();
  private readonly nowFn: () => number;

  constructor(rules: RateLimitRule[], opts: { now?: () => number } = {}) {
    for (const r of rules) this.rules.set(r.name, { ...r });
    this.nowFn = opts.now ?? Date.now;
  }

  /** Record a hit and decide. يسجّل المحاولة ويقرر السماح. */
  check(ruleName: string, key: string): RateLimitVerdict {
    const rule = this.rules.get(ruleName);
    if (!rule) throw new Error(`unknown rate-limit rule: ${ruleName}`);
    const now = this.nowFn();
    const cutoff = now - rule.windowMs;
    let bucket = this.windows.get(ruleName);
    if (!bucket) {
      bucket = new Map();
      this.windows.set(ruleName, bucket);
    }
    const hits = (bucket.get(key) ?? []).filter((t) => t > cutoff);
    if (hits.length >= rule.limit) {
      const retryAfterMs = hits[0] + rule.windowMs - now;
      return {
        allowed: false,
        limit: rule.limit,
        remaining: 0,
        retryAfterSec: Math.max(1, Math.ceil(retryAfterMs / 1000)),
      };
    }
    hits.push(now);
    bucket.set(key, hits);
    return { allowed: true, limit: rule.limit, remaining: rule.limit - hits.length, retryAfterSec: 0 };
  }

  /** Drop every (rule, key) whose window is fully expired. Returns the
   * number of keys removed. مسح النوافذ المنتهية (ذاكرة محدودة). */
  sweep(): number {
    const now = this.nowFn();
    let removed = 0;
    for (const [ruleName, rule] of this.rules) {
      const cutoff = now - rule.windowMs;
      const bucket = this.windows.get(ruleName);
      if (!bucket) continue;
      for (const [key, hits] of bucket) {
        if (!hits.some((t) => t > cutoff)) {
          bucket.delete(key);
          removed++;
        }
      }
      if (bucket.size === 0) this.windows.delete(ruleName);
    }
    return removed;
  }

  /** Total tracked (rule, key) pairs — for tests/diagnostics. */
  size(): number {
    let n = 0;
    for (const bucket of this.windows.values()) n += bucket.size;
    return n;
  }
}

// ── /api surface rules ───────────────────────────────────────────────────────

/**
 * Budgets (R97-04 partial). The SubNation backend's server-to-server
 * usage sits far below every bucket: the readiness probe is a GET pair
 * cached 30s (~4 req/min) and OTP sends are user-throttled upstream
 * (cooldown 60s/number, 5/hour/number, 20/15min/IP) — 60 sends/min and
 * 240 general/min leave an order of magnitude of headroom while capping
 * a leaked-key relay and unauthenticated key guessing per IP.
 */
export const API_RATE_RULES = {
  /** POST /api/sessions/:id/pair-code — pairing-code issuance is the
   * WhatsApp-abuse-sensitive endpoint: 5/hour/IP. */
  pairCode: { name: "pair-code", limit: 5, windowMs: 60 * 60 * 1000 },
  /** POST .../messages/send-text + .../messages/test — 60/min/IP. */
  sends: { name: "sends", limit: 60, windowMs: 60 * 1000 },
  /** Every other /api request (GET included) — 240/min/IP. */
  general: { name: "general", limit: 240, windowMs: 60 * 1000 },
} as const satisfies Record<string, RateLimitRule>;

/** Mutually exclusive bucket classification for a request path relative
 * to the /api mount point. Returns the RULE NAME (the limiter's key).
 * تصنيف الطلب إلى دلو المعدل المناسب. */
export function classifyApiPath(path: string): "pair-code" | "sends" | "general" {
  if (/\/pair-code$/.test(path)) return API_RATE_RULES.pairCode.name;
  if (/\/messages\/(send-text|test)$/.test(path)) return API_RATE_RULES.sends.name;
  return API_RATE_RULES.general.name;
}

export interface RateLimitResponseLike {
  status(code: number): unknown;
  json(body: unknown): unknown;
  setHeader(name: string, value: string | number): unknown;
}

const SWEEP_INTERVAL_MS = 60 * 1000;

/**
 * Express middleware factory for the /api surface. Sweeps expired
 * windows every 60s (timer unref'd — never holds the process open).
 * Mount BEFORE the X-API-Key gate so unauthenticated key guessing is
 * bounded per IP as well; /healthz lives outside /api and stays exempt
 * (keep-alive self-ping + backend probes must never throttle).
 */
export function createApiRateLimiter(
  opts: { now?: () => number; sweepIntervalMs?: number } = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const limiter = new SlidingWindowLimiter(Object.values(API_RATE_RULES), { now: opts.now });
  const sweepIntervalMs = opts.sweepIntervalMs ?? SWEEP_INTERVAL_MS;
  if (sweepIntervalMs > 0) {
    const timer = setInterval(() => limiter.sweep(), sweepIntervalMs);
    timer.unref?.();
  }
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = resolveClientIp(req);
    const rule = classifyApiPath(req.path);
    const verdict = limiter.check(rule, ip);
    res.setHeader("X-RateLimit-Limit", String(verdict.limit));
    res.setHeader("X-RateLimit-Remaining", String(verdict.remaining));
    if (!verdict.allowed) {
      res.setHeader("Retry-After", String(verdict.retryAfterSec));
      res.status(429).json({ error: "rate_limited", retry_after_sec: verdict.retryAfterSec });
      return;
    }
    next();
  };
}
