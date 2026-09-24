/**
 * R111 fix-fleet regression tests (agent R111-FIX-O) — the fixes landed
 * this round, pinned at the mechanism level:
 *
 *   O1-H1  rate-limit bucket evasion via path shape: classifyApiPath
 *          NORMALIZES the path (lowercase, collapse duplicate slashes,
 *          strip trailing slashes) BEFORE the strict regexes — `/pair-code/`
 *          and `/PAIR-CODE` still reach the real handler (Express routing
 *          is lenient) and must land in the pair-code 5/hour bucket, not
 *          the general 240/min one (a 2,880× amplification of pairing-code
 *          issuance with a leaked key — proven live in R111-O1).
 *   O1-M4  TRUST_PROXY knob: 0/false → forwarded headers (XFF +
 *          CF-Connecting-IP) are NEVER trusted for identity (rate limiter
 *          + dashboard lockout share the same switch, lib.ts).
 *   O2-F1  interim-creds shadow: the restore gate prefers the DB blob
 *          whenever local creds are absent OR not fully registered
 *          (shouldPreferDbBlobOverLocal — the old gate tested existence
 *          only and a persistent-volume qr_ready loop resulted).
 *   O2-F5  SIGTERM flush: flushNow's OWN upsert runs on a dedicated client
 *          inside a transaction with a 3s SET LOCAL statement_timeout;
 *          background debounced saves keep the plain pool.query path.
 *   O2-F6  >256kb body → 413 not 500: httpErrorStatus honors the parser's
 *          statusCode/status (sane 4xx/5xx only), else generic 500.
 *
 * Imports compiled dist modules exactly the way the engine does; the
 * persist.ts cases use the __setPoolForTest + module-reload idiom from
 * persist-hardening.test.mjs. Run:
 *   node --test tests/r111-hardening.test.mjs   (after `npm run build`)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import {
  classifyApiPath,
  createApiRateLimiter,
  resolveClientIp,
} from "../dist/rate-limit.js";
import {
  httpErrorStatus,
  shouldPreferDbBlobOverLocal,
} from "../dist/lib.js";
import { clientIp } from "../dist/dashboard.js";

// ── O1-H1: normalized variants must hit the RIGHT bucket ───────────────────

test("classifyApiPath: trailing-slash / case / duplicate-slash variants of pair-code hit the 5/hour bucket", () => {
  assert.equal(classifyApiPath("/sessions/sess_x/pair-code"), "pair-code"); // canonical
  assert.equal(classifyApiPath("/sessions/sess_x/pair-code/"), "pair-code"); // trailing slash
  assert.equal(classifyApiPath("/sessions/sess_x/PAIR-CODE"), "pair-code"); // case
  assert.equal(classifyApiPath("/sessions/sess_x/Pair-Code/"), "pair-code"); // mixed
  assert.equal(classifyApiPath("/sessions//sess_x//pair-code//"), "pair-code"); // duplicated separators
});

test("classifyApiPath: send-text/test variants hit the sends bucket", () => {
  assert.equal(classifyApiPath("/sessions/sess_x/messages/send-text/"), "sends");
  assert.equal(classifyApiPath("/sessions/sess_x/messages/SEND-TEXT"), "sends");
  assert.equal(classifyApiPath("/sessions/sess_x/messages/test/"), "sends");
  assert.equal(classifyApiPath("/sessions/sess_x/messages/Test"), "sends");
});

test("classifyApiPath: no false positives — near-miss shapes stay general", () => {
  // The strict regexes must still anchor at the (normalized) END — a
  // session literally named "pair-code" was ALREADY pair-code-classified
  // pre-fix; only genuinely new near-misses are pinned here.
  assert.equal(classifyApiPath("/sessions/sess_x/pair-codes"), "general"); // plural
  assert.equal(classifyApiPath("/sessions/sess_x/pair-code/foo"), "general"); // deeper path
  assert.equal(classifyApiPath("/sessions/sess_x/messages/send-text2"), "general");
  assert.equal(classifyApiPath("/sessions/sess_x/delivery-log/"), "general");
  assert.equal(classifyApiPath("/"), "general");
});

// ── O1-H1 at the middleware layer: variants share the STRICT bucket ────────

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
  return { method: "POST", path, headers, socket: { remoteAddress } };
}

test("middleware: the 6th /pair-code/ (trailing slash) within the hour → 429 with the 5/hour limit", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const xff = { "x-forwarded-for": "5.6.7.8" };
  let last = null;
  for (let i = 0; i < 6; i++) {
    const ctx = fakeRes();
    mw(fakeReq("/sessions/sess_x/pair-code/", xff), ctx.res, ctx.next);
    last = ctx;
  }
  assert.equal(last.state.nextCalled, false);
  assert.equal(last.state.statusCode, 429);
  assert.equal(last.headers["x-ratelimit-limit"], "5", "the variant must share the pair-code bucket");
  assert.equal(last.state.body.error, "rate_limited");
});

test("middleware: case-evasion (/PAIR-CODE) shares ONE bucket with the canonical shape", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const xff = { "x-forwarded-for": "5.6.7.8" };
  // 5 canonical + 1 case-variant from the same IP — the 6th must be denied
  // (pre-fix the variant fell into the 240/min general bucket and passed).
  for (let i = 0; i < 5; i++) {
    const ctx = fakeRes();
    mw(fakeReq("/sessions/sess_x/pair-code", xff), ctx.res, ctx.next);
    assert.equal(ctx.state.nextCalled, true);
  }
  const evader = fakeRes();
  mw(fakeReq("/sessions/sess_x/PAIR-CODE/", xff), evader.res, evader.next);
  assert.equal(evader.state.statusCode, 429);
  assert.equal(evader.headers["x-ratelimit-limit"], "5");
});

test("middleware: send-text trailing-slash variant counts against the 60/min sends bucket", () => {
  let t = 0;
  const mw = createApiRateLimiter({ now: () => t, sweepIntervalMs: 0 });
  const xff = { "x-forwarded-for": "5.6.7.8" };
  let last = null;
  for (let i = 0; i < 61; i++) {
    const ctx = fakeRes();
    mw(fakeReq("/sessions/sess_x/messages/send-text/", xff), ctx.res, ctx.next);
    last = ctx;
  }
  assert.equal(last.state.statusCode, 429);
  assert.equal(last.headers["x-ratelimit-limit"], "60", "the variant must share the sends bucket");
});

// ── O1-M4: TRUST_PROXY knob ─────────────────────────────────────────────────

test("resolveClientIp: TRUST_PROXY=0 → forged XFF and CF-Connecting-IP are IGNORED (socket address wins)", () => {
  process.env.TRUST_PROXY = "0";
  try {
    const ip = resolveClientIp({
      headers: {
        "x-forwarded-for": "1.2.3.4, 5.6.7.8",
        "cf-connecting-ip": "41.208.172.99",
      },
      socket: { remoteAddress: "203.0.113.9" },
    });
    assert.equal(ip, "203.0.113.9", "direct-publish identity must be the TCP peer");
    assert.equal(resolveClientIp({ headers: {}, socket: { remoteAddress: "10.0.0.7" } }), "10.0.0.7");
    assert.equal(resolveClientIp({ headers: {} }), "unknown");
  } finally {
    delete process.env.TRUST_PROXY;
  }
});

test("resolveClientIp: TRUST_PROXY=false is the same as 0; 1/true keep the default rightmost-XFF posture", () => {
  process.env.TRUST_PROXY = "false";
  try {
    assert.equal(
      resolveClientIp({
        headers: { "x-forwarded-for": "6.6.6.6" },
        socket: { remoteAddress: "203.0.113.9" },
      }),
      "203.0.113.9",
    );
  } finally {
    process.env.TRUST_PROXY = "1";
  }
  try {
    assert.equal(
      resolveClientIp({
        headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" },
        socket: { remoteAddress: "10.0.0.7" },
      }),
      "5.6.7.8",
    );
  } finally {
    delete process.env.TRUST_PROXY;
  }
});

test("resolveClientIp: unset (default) keeps the current Render posture (rightmost XFF trusted)", () => {
  delete process.env.TRUST_PROXY;
  assert.equal(
    resolveClientIp({
      headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" },
      socket: { remoteAddress: "10.0.0.7" },
    }),
    "5.6.7.8",
  );
});

test("dashboard clientIp: TRUST_PROXY=0 → the socket address IS the lockout identity", () => {
  const req = (headers) => ({
    header: (name) => headers[name.toLowerCase()] ?? "",
    socket: { remoteAddress: "203.0.113.9" },
  });
  process.env.TRUST_PROXY = "0";
  try {
    assert.equal(clientIp(req({ "x-forwarded-for": "6.6.6.6, 1.2.3.4" })), "203.0.113.9");
  } finally {
    delete process.env.TRUST_PROXY;
  }
  // Default: rightmost XFF still trusted (existing deployments unchanged).
  assert.equal(clientIp(req({ "x-forwarded-for": "6.6.6.6, 1.2.3.4" })), "1.2.3.4");
  assert.equal(clientIp(req({})), "203.0.113.9");
});

// ── O2-F1: restore-gate decision ────────────────────────────────────────────

test("shouldPreferDbBlobOverLocal: interim local creds no longer shadow the DB blob", () => {
  // No local creds at all → restore (the old behavior, unchanged):
  assert.equal(shouldPreferDbBlobOverLocal(false, false), true);
  // LOCAL creds exist but are INTERIM (registered !== true) → prefer the DB
  // blob — the exact R111-O2-F1 permanent-qr_ready-loop vector:
  assert.equal(shouldPreferDbBlobOverLocal(true, false), true);
  // Fully registered local creds → local wins (nothing to restore over it):
  assert.equal(shouldPreferDbBlobOverLocal(true, true), false);
});

// ── O2-F6: terminal error status ────────────────────────────────────────────

test("httpErrorStatus: body-parser's 413 is honored (oversized payload ≠ server fault)", () => {
  // body-parser attaches BOTH status and statusCode (http-errors shape):
  assert.equal(httpErrorStatus({ status: 413, statusCode: 413, type: "entity.too.large" }), 413);
  assert.equal(httpErrorStatus({ statusCode: 429 }), 429);
  assert.equal(httpErrorStatus({ status: 502 }), 502);
  // statusCode wins over status when both are sane (body-parser convention):
  assert.equal(httpErrorStatus({ statusCode: 413, status: 500 }), 413);
});

test("httpErrorStatus: junk stays a generic 500", () => {
  assert.equal(httpErrorStatus(new Error("engine exploded")), 500);
  assert.equal(httpErrorStatus(null), 500);
  assert.equal(httpErrorStatus(undefined), 500);
  assert.equal(httpErrorStatus({ statusCode: "413" }), 500); // string, not number
  assert.equal(httpErrorStatus({ statusCode: 999 }), 500); // out of range
  assert.equal(httpErrorStatus({ statusCode: 302 }), 500); // 3xx is not an error code
  assert.equal(httpErrorStatus({ statusCode: 413.5 }), 500); // non-integer
});

test("O2-F6 integration: a >256kb JSON body answers 413 payload_too_large through the real body-parser", async () => {
  // The exact index.ts wiring (express.json limit 256kb + a terminal error
  // middleware shaped identically + httpErrorStatus) over real HTTP — the
  // pre-fix shape answered a blanket 500 here.
  const express = (await import("express")).default;
  const app = express();
  app.use(express.json({ limit: "256kb" }));
  app.post("/api/sessions/:id/messages/send-text", (req, res) => {
    res.json({ ok: true });
  });
  app.use((err, _req, res, next) => {
    const status = httpErrorStatus(err);
    if (res.headersSent) {
      next(err);
      return;
    }
    res.status(status).json({ error: status === 413 ? "payload_too_large" : "internal" });
  });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const small = await fetch(`${base}/api/sessions/x/messages/send-text`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "hi" }),
    });
    assert.equal(small.status, 200, "an in-limit body passes untouched");
    const big = await fetch(`${base}/api/sessions/x/messages/send-text`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "x".repeat(300 * 1024) }),
    });
    assert.equal(big.status, 413, "an oversized body is a client fault, not a server fault");
    assert.deepEqual(await big.json(), { error: "payload_too_large" });
  } finally {
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
  }
});

// ── O2-F5: bounded flush path (persist.ts) ──────────────────────────────────

const DIST = "file://" + resolve("dist/persist.js");

async function loadPersist(env) {
  const prev = { ...env };
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
  try {
    // Unique query string = fresh module instance = fresh module-level env
    // snapshot (persist.ts reads env at import time).
    const mod = await import(`${DIST}?case=${Math.random().toString(36).slice(2)}`);
    return mod;
  } finally {
    for (const k of Object.keys(prev)) delete process.env[k];
  }
}

const API_KEY = "test-api-key-0123456789abcdef";
const FAKE_URL = "postgresql://fake:test@localhost:5432/fakedb";
const BLOB = { "creds.json": '{"registered":true}', "pre-key-42.json": '{"key":1}' };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, ms = 2000) {
  const deadline = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > deadline) throw new Error("waitFor timeout");
    await sleep(5);
  }
}

/** Minimal fake pool distinguishing the CLIENT (flush) path from pool.query. */
function makeBoundedFakePool() {
  const clientQueries = [];
  const poolQueries = [];
  const rows = new Map();
  const client = {
    async query(sql, params) {
      const text = String(sql).trim();
      clientQueries.push(text);
      if (
        text.startsWith("BEGIN") ||
        text.startsWith("SET LOCAL") ||
        text.startsWith("COMMIT") ||
        text.startsWith("ROLLBACK")
      ) {
        return { rowCount: 0 };
      }
      if (text.startsWith("INSERT INTO openwa_sessions")) {
        rows.set(params[0], params[1]);
        return { rowCount: 1 };
      }
      return { rowCount: 0 };
    },
    release() {},
  };
  const pool = {
    async connect() {
      return client;
    },
    async query(sql, params) {
      const text = String(sql).trim();
      poolQueries.push(text);
      if (text.startsWith("INSERT INTO openwa_sessions")) {
        rows.set(params[0], params[1]);
        return { rowCount: 1 };
      }
      return { rowCount: 0 };
    },
  };
  return { pool, client, clientQueries, poolQueries, rows };
}

test("flushNow: the flush upsert runs on a dedicated client with SET LOCAL statement_timeout = 3000", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API_KEY, PERSISTENCE_URL: FAKE_URL });
  const fake = makeBoundedFakePool();
  persist.__setPoolForTest(fake.pool);

  await persist.flushNow("s1", async () => JSON.stringify(BLOB));

  // The bounded sequence, exactly once, in order — a stuck upsert inside
  // this transaction fails fast at 3s instead of hanging the SIGTERM
  // budget against the pool-level 10s statement_timeout (O2-F5).
  assert.equal(fake.poolQueries.length, 0, "the flush must NOT use the shared pool.query path");
  assert.equal(fake.clientQueries.length, 4, "BEGIN + SET LOCAL + upsert + COMMIT, nothing else");
  assert.equal(fake.clientQueries[0], "BEGIN");
  assert.equal(fake.clientQueries[1], "SET LOCAL statement_timeout = 3000");
  assert.ok(
    fake.clientQueries[2].startsWith("INSERT INTO openwa_sessions"),
    "the third client statement is the credentials upsert",
  );
  assert.equal(fake.clientQueries[3], "COMMIT");
  assert.equal(fake.rows.has("s1"), true, "the row must still land");
  assert.ok(persist.persistAge("s1") != null, "bookkeeping still records the save");
});

test("scheduleSave (background path): unchanged — plain pool upsert, no client, no SET LOCAL", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API_KEY, PERSISTENCE_URL: FAKE_URL });
  const fake = makeBoundedFakePool();
  persist.__setPoolForTest(fake.pool);

  persist.scheduleSave("s2", async () => JSON.stringify(BLOB), 10);
  await waitFor(() => fake.poolQueries.some((q) => q.startsWith("INSERT INTO openwa_sessions")));

  assert.equal(fake.clientQueries.length, 0, "background saves must keep the pool.query path");
  assert.equal(fake.rows.has("s2"), true);
});
