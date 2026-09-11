/**
 * Unit tests for the /api rate limiter (R97-04 partial) — window math,
 * sweep, per-IP isolation, path classification, H11-style IP resolution
 * and the 429 middleware contract.
 *
 * اختبارات محدد المعدل — حسابات النافذة والمسح وعزل IP وتصنيف المسارات.
 *
 * Run: node --test tests/rate-limit.test.mjs   (after `npm run build`)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SlidingWindowLimiter,
  classifyApiPath,
  resolveClientIp,
  renderFacingPeer,
  isCloudflareIp,
  createApiRateLimiter,
  API_RATE_RULES,
} from "../dist/rate-limit.js";

// ── SlidingWindowLimiter: window math ────────────────────────────────────────

test("window math: allows exactly `limit` requests inside the window", () => {
  let t = 0;
  const lim = new SlidingWindowLimiter([{ name: "general", limit: 3, windowMs: 60_000 }], {
    now: () => t,
  });
  assert.equal(lim.check("general", "ip-a").allowed, true);
  assert.equal(lim.check("general", "ip-a").allowed, true);
  const third = lim.check("general", "ip-a");
  assert.equal(third.allowed, true);
  assert.equal(third.remaining, 0);
  assert.equal(lim.check("general", "ip-a").allowed, false); // 4th → denied
});

test("window math: retry_after_sec = time until the OLDEST hit slides out", () => {
  let t = 0;
  const lim = new SlidingWindowLimiter([{ name: "general", limit: 2, windowMs: 60_000 }], {
    now: () => t,
  });
  lim.check("general", "ip-a"); // t=0
  t = 10_000;
  lim.check("general", "ip-a"); // t=10s
  t = 25_000;
  const denied = lim.check("general", "ip-a"); // oldest hit expires at t=60s
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterSec, 35); // 60s - 25s
  assert.equal(denied.remaining, 0);
  assert.equal(denied.limit, 2);
});

test("window math: the window SLIDES — expired hits stop counting", () => {
  let t = 0;
  const lim = new SlidingWindowLimiter([{ name: "general", limit: 2, windowMs: 60_000 }], {
    now: () => t,
  });
  lim.check("general", "ip-a"); // t=0
  t = 10_000;
  lim.check("general", "ip-a"); // t=10s
  t = 61_000; // the t=0 hit slid out (0 <= 61s - 60s)
  const verdict = lim.check("general", "ip-a");
  assert.equal(verdict.allowed, true);
  assert.equal(verdict.remaining, 0); // t=10s hit still inside
});

test("window math: a denied request is never negative / never zero retry", () => {
  let t = 1_000_000;
  const lim = new SlidingWindowLimiter([{ name: "pair-code", limit: 1, windowMs: 3_600_000 }], {
    now: () => t,
  });
  lim.check("pair-code", "ip-a");
  t += 5; // 5ms later — retry is ~3599.995s → ceil → 3600
  const denied = lim.check("pair-code", "ip-a");
  assert.equal(denied.allowed, false);
  assert.equal(denied.retryAfterSec, 3600);
  assert.ok(denied.retryAfterSec >= 1);
});

// ── Per-IP + per-rule isolation ──────────────────────────────────────────────

test("per-IP isolation: one IP's exhaustion never affects another", () => {
  let t = 0;
  const lim = new SlidingWindowLimiter([{ name: "general", limit: 2, windowMs: 60_000 }], {
    now: () => t,
  });
  lim.check("general", "ip-a");
  lim.check("general", "ip-a");
  assert.equal(lim.check("general", "ip-a").allowed, false);
  const other = lim.check("general", "ip-b"); // single verdict — check() records a hit
  assert.equal(other.allowed, true);
  assert.equal(other.remaining, 1);
  // IPv6 keys coexist with IPv4 keys untouched:
  const v6 = lim.check("general", "::1");
  assert.equal(v6.allowed, true);
  assert.equal(v6.remaining, 1);
});

test("per-rule isolation: buckets are independent (pair-code vs general)", () => {
  let t = 0;
  const lim = new SlidingWindowLimiter(
    [API_RATE_RULES.pairCode, API_RATE_RULES.general],
    { now: () => t },
  );
  for (let i = 0; i < 5; i++) lim.check("pair-code", "ip-a");
  assert.equal(lim.check("pair-code", "ip-a").allowed, false); // 5/h exhausted
  assert.equal(lim.check("general", "ip-a").allowed, true); // untouched
});

test("unknown rule name throws (programming error, not a 429)", () => {
  const lim = new SlidingWindowLimiter([{ name: "general", limit: 5, windowMs: 60_000 }]);
  assert.throws(() => lim.check("nope", "ip-a"), /unknown rate-limit rule/);
});

// ── Sweep (bounded memory) ───────────────────────────────────────────────────

test("sweep: removes fully-expired keys and keeps live ones", () => {
  let t = 0;
  const lim = new SlidingWindowLimiter([{ name: "general", limit: 100, windowMs: 60_000 }], {
    now: () => t,
  });
  lim.check("general", "ip-a"); // t=0
  t = 30_000;
  lim.check("general", "ip-b"); // t=30s
  assert.equal(lim.size(), 2);
  t = 61_000; // ip-a fully expired; ip-b still live (30s > 1s)
  const removed = lim.sweep();
  assert.equal(removed, 1);
  assert.equal(lim.size(), 1);
  // The surviving key still works with its history:
  const v = lim.check("general", "ip-b");
  assert.equal(v.allowed, true);
});

test("sweep: repeated sweeps are idempotent and safe on empty state", () => {
  const lim = new SlidingWindowLimiter([API_RATE_RULES.general]);
  assert.equal(lim.sweep(), 0);
  assert.equal(lim.size(), 0);
});

// ── Path classification ──────────────────────────────────────────────────────

test("classifyApiPath: pair-code, send-text and test get their own buckets", () => {
  assert.equal(classifyApiPath("/sessions/sess_x/pair-code"), "pair-code");
  assert.equal(classifyApiPath("/sessions/sess_x/messages/send-text"), "sends");
  assert.equal(classifyApiPath("/sessions/sess_x/messages/test"), "sends");
});

test("classifyApiPath: everything else is the general bucket (GET included)", () => {
  assert.equal(classifyApiPath("/sessions"), "general");
  assert.equal(classifyApiPath("/sessions/sess_x"), "general");
  assert.equal(classifyApiPath("/sessions/sess_x/delivery-log"), "general");
  assert.equal(classifyApiPath("/sessions/sess_x/contacts/check/218914460503"), "general");
  assert.equal(classifyApiPath("/sessions/sess_x/qr"), "general");
  assert.equal(classifyApiPath("/docs"), "general");
  assert.equal(classifyApiPath("/"), "general");
});

test("API_RATE_RULES: the contracted budgets", () => {
  assert.equal(API_RATE_RULES.pairCode.limit, 5);
  assert.equal(API_RATE_RULES.pairCode.windowMs, 60 * 60 * 1000);
  assert.equal(API_RATE_RULES.sends.limit, 60);
  assert.equal(API_RATE_RULES.sends.windowMs, 60 * 1000);
  assert.equal(API_RATE_RULES.general.limit, 240);
  assert.equal(API_RATE_RULES.general.windowMs, 60 * 1000);
});

// ── H11-style client-IP resolution ───────────────────────────────────────────

test("resolveClientIp: no XFF at all → socket address", () => {
  const ip = resolveClientIp({ headers: {}, socket: { remoteAddress: "10.0.0.7" } });
  assert.equal(ip, "10.0.0.7");
});

test("resolveClientIp: rightmost XFF entry wins (Render appends the true peer)", () => {
  const ip = resolveClientIp({
    headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(ip, "5.6.7.8");
});

test("resolveClientIp: a forged first XFF entry is ignored (proven-live bypass)", () => {
  const ip = resolveClientIp({
    headers: { "x-forwarded-for": "6.6.6.6, 6.6.6.5, 5.6.7.8" },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(ip, "5.6.7.8");
});

test("resolveClientIp: CF-Connecting-IP honoured ONLY when the peer is a Cloudflare range", () => {
  // Genuine CF traversal: rightmost XFF is a CF edge → trust the header.
  const via = resolveClientIp({
    headers: {
      "cf-connecting-ip": "41.208.172.99",
      "x-forwarded-for": "41.208.172.99, 104.16.1.1",
    },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(via, "41.208.172.99");
});

test("resolveClientIp: forged CF-Connecting-IP on a direct-to-Render request is IGNORED (H11)", () => {
  const ip = resolveClientIp({
    headers: {
      "cf-connecting-ip": "1.1.1.1", // attacker-chosen
      "x-forwarded-for": "1.1.1.1, 203.0.113.9", // Render-appended real peer ∉ CF
    },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(ip, "203.0.113.9");
});

test("resolveClientIp: malformed CF-Connecting-IP is never trusted", () => {
  const ip = resolveClientIp({
    headers: {
      "cf-connecting-ip": "not-an-ip",
      "x-forwarded-for": "203.0.113.9, 104.16.1.1",
    },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(ip, "104.16.1.1"); // falls back to the Render-facing peer
});

test("resolveClientIp: IPv6 Cloudflare edges verify correctly", () => {
  const ip = resolveClientIp({
    headers: {
      "cf-connecting-ip": "2a01:4f8:1c17::99",
      "x-forwarded-for": "2a01:4f8:1c17::99, 2606:4700:10::1",
    },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(ip, "2a01:4f8:1c17::99");
});

test("resolveClientIp: duplicate headers (array form) are handled", () => {
  const ip = resolveClientIp({
    headers: {
      "x-forwarded-for": ["1.2.3.4", "5.6.7.8"],
    },
    socket: { remoteAddress: "10.0.0.7" },
  });
  assert.equal(ip, "5.6.7.8");
});

test("resolveClientIp: unknown socket + no headers → 'unknown' (never crashes)", () => {
  assert.equal(resolveClientIp({ headers: {} }), "unknown");
});

test("isCloudflareIp / renderFacingPeer: range-table sanity", () => {
  assert.equal(isCloudflareIp("104.16.1.1"), true);
  assert.equal(isCloudflareIp("172.64.0.9"), true);
  assert.equal(isCloudflareIp("2606:4700::1"), true);
  assert.equal(isCloudflareIp("203.0.113.9"), false);
  assert.equal(isCloudflareIp("not-an-ip"), false);
  assert.equal(renderFacingPeer({ headers: {} }), null);
  assert.equal(renderFacingPeer({ headers: { "x-forwarded-for": "1.2.3.4" } }), "1.2.3.4");
});

// ── Middleware contract ──────────────────────────────────────────────────────

function fakeRes() {
  const headers = {};
  const state = { statusCode: 200, body: null, nextCalled: false };
  const res = {
    setHeader(name, value) {
      headers[String(name).toLowerCase()] = String(value);
      return res;
    },
    status(code) {
      state.statusCode = code;
      return res;
    },
    json(body) {
      state.body = body;
      return res;
    },
  };
  return {
    res,
    headers,
    state,
    next: () => {
      state.nextCalled = true;
    },
  };
}

function fakeReq(path, headers = {}, remoteAddress = "9.9.9.9") {
  return { method: "GET", path, headers, socket: { remoteAddress } };
}

test("middleware: allowed requests pass through with rate-limit headers", () => {
  const mw = createApiRateLimiter({ now: () => 0, sweepIntervalMs: 0 });
  const { res, headers, state, next } = fakeRes();
  mw(fakeReq("/sessions", { "x-forwarded-for": "5.6.7.8" }), res, next);
  assert.equal(state.nextCalled, true);
  assert.equal(state.statusCode, 200);
  assert.equal(headers["x-ratelimit-limit"], "240");
  assert.equal(headers["x-ratelimit-remaining"], "239");
});

test("middleware: 6th pair-code within the hour → 429 + Retry-After + JSON body", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const req = fakeReq("/sessions/sess_x/pair-code", { "x-forwarded-for": "5.6.7.8" });
  for (let i = 0; i < 5; i++) {
    const { res, state, next } = fakeRes();
    mw(req, res, next);
    assert.equal(state.nextCalled, true);
  }
  t = 120_000; // 2 minutes in — still inside the 1h window
  const { res, headers, state, next } = fakeRes();
  mw(req, res, next);
  assert.equal(state.nextCalled, false);
  assert.equal(state.statusCode, 429);
  assert.equal(headers["retry-after"], "3480"); // 3600 - 120
  assert.equal(headers["x-ratelimit-limit"], "5");
  assert.equal(headers["x-ratelimit-remaining"], "0");
  assert.deepEqual(state.body, { error: "rate_limited", retry_after_sec: 3480 });
});

test("middleware: send-text exhausts the sends bucket (60/min) while general stays open", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const xff = { "x-forwarded-for": "5.6.7.8" };
  const sendReq = fakeReq("/sessions/sess_x/messages/send-text", xff);
  let last = null;
  for (let i = 0; i < 61; i++) {
    const ctx = fakeRes();
    mw(sendReq, ctx.res, ctx.next);
    last = ctx;
  }
  assert.equal(last.state.statusCode, 429);
  assert.equal(last.state.body.error, "rate_limited");
  // A GET /api/sessions from the same IP is still allowed — different bucket:
  const get = fakeRes();
  mw(fakeReq("/sessions", xff), get.res, get.next);
  assert.equal(get.state.nextCalled, true);
  // And an /api/messages/test POST is ALSO blocked by the same sends bucket:
  const testMsg = fakeRes();
  mw(fakeReq("/sessions/sess_x/messages/test", xff), testMsg.res, testMsg.next);
  assert.equal(testMsg.state.statusCode, 429);
});

test("middleware: the general bucket caps at 240/min for a non-send path", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const xff = { "x-forwarded-for": "5.6.7.8" };
  const req = fakeReq("/sessions", xff);
  let deniedAt = -1;
  for (let i = 1; i <= 245; i++) {
    const ctx = fakeRes();
    mw(req, ctx.res, ctx.next);
    if (ctx.state.statusCode === 429 && deniedAt < 0) deniedAt = i;
  }
  assert.equal(deniedAt, 241); // 240 allowed, the 241st denied
});

test("middleware: per-IP isolation at the HTTP layer (server-side caller unaffected)", () => {
  const mw = createApiRateLimiter({ now: () => 0, sweepIntervalMs: 0 });
  const xffA = { "x-forwarded-for": "10.20.0.1" }; // the SubNation backend
  const xffB = { "x-forwarded-for": "10.20.0.2" }; // an attacker
  const pairReqB = fakeReq("/sessions/sess_x/pair-code", xffB);
  for (let i = 0; i < 5; i++) {
    const ctx = fakeRes();
    mw(pairReqB, ctx.res, ctx.next);
    assert.equal(ctx.state.nextCalled, true);
  }
  const blocked = fakeRes();
  mw(pairReqB, blocked.res, blocked.next);
  assert.equal(blocked.state.statusCode, 429);
  // Different IP: still fully allowed.
  const other = fakeRes();
  mw(fakeReq("/sessions/sess_x/pair-code", xffA), other.res, other.next);
  assert.equal(other.state.nextCalled, true);
  assert.equal(other.headers["x-ratelimit-remaining"], "4");
});

test("middleware: sliding expiry restores access (retry_after honors the clock)", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const xff = { "x-forwarded-for": "5.6.7.8" };
  const req = fakeReq("/sessions/sess_x/messages/send-text", xff);
  for (let i = 0; i < 60; i++) {
    const ctx = fakeRes();
    mw(req, ctx.res, ctx.next);
  }
  const denied = fakeRes();
  mw(req, denied.res, denied.next);
  assert.equal(denied.state.statusCode, 429);
  assert.equal(denied.state.body.retry_after_sec, 60);
  t = 60_001; // the whole window slid away
  const allowed = fakeRes();
  mw(req, allowed.res, allowed.next);
  assert.equal(allowed.state.nextCalled, true);
  assert.equal(allowed.headers["x-ratelimit-remaining"], "59");
});
