/**
 * r98/98-F6 hardening tests — the fixes landed this round:
 *
 *   P2-1  asyncHandler (lib.ts) converts an async route-handler rejection
 *         into next(err); the terminal error middleware mounted in
 *         index.ts answers a generic 500 JSON instead of hanging forever
 *         (Express 4 does NOT route async rejections itself).
 *   P2-2  beginSessionStart (lib.ts) memoizes the in-flight startSession
 *         promise on the session record — concurrent starts share ONE
 *         engine start instead of building two Baileys sockets on one
 *         auth folder (the loggedOut → credential-wipe chain).
 *   P3-3  maskDigits/maskJid (lib.ts) redact phone digits in stdout logs.
 *   P3-6  dashboard pair-code issuance guard: one request in flight + a
 *         per-session cooldown (bounded map) — verified through the real
 *         mountDashboard router over HTTP with a cookie login.
 *
 * Mechanism-level: imports the compiled modules (dist/lib.js,
 * dist/dashboard-routes.js) exactly the way the engine does. Run:
 *   node --test tests/gateway-hardening.test.mjs   (after `npm run build`)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { asyncHandler, beginSessionStart, maskDigits, maskJid } from "../dist/lib.js";

// ── helpers ────────────────────────────────────────────────────────────────

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Boot an express app on an ephemeral port; tear it down afterwards. */
async function withServer(app, fn) {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    return await fn(base);
  } finally {
    await new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections?.();
    });
  }
}

/** The exact terminal-error-middleware shape index.ts mounts last. */
function terminalErrorMiddleware() {
  return (err, _req, res, next) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    res.status(500).json({ error: "internal" });
  };
}

// ── P2-1: async rejections must answer 500 JSON, never hang ────────────────

test("asyncHandler: a normal async response passes through untouched", async () => {
  const app = express();
  app.get("/ok", asyncHandler(async (_req, res) => {
    await sleep(5);
    res.json({ ok: true });
  }));
  app.use(terminalErrorMiddleware());
  await withServer(app, async (base) => {
    const res = await fetch(`${base}/ok`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true });
  });
});

test("asyncHandler: a rejecting handler answers 500 {error:internal} via the terminal error middleware", async () => {
  const app = express();
  app.get("/boom", asyncHandler(async () => {
    throw new Error("engine exploded");
  }));
  app.use(terminalErrorMiddleware());
  await withServer(app, async (base) => {
    const res = await fetch(`${base}/boom`);
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { error: "internal" });
  });
});

test("regression demo: WITHOUT the wrapper the request hangs (Express 4 never routes the rejection)", async () => {
  const app = express();
  // The pre-fix shape: the handler's rejection is observed (silenced here so
  // the test process stays clean) but NOBODY answers the request.
  app.get("/hang", async (_req, _res) => {
    await Promise.reject(new Error("pre-fix")).catch(() => {});
  });
  app.use(terminalErrorMiddleware());
  await withServer(app, async (base) => {
    await assert.rejects(
      fetch(`${base}/hang`, { signal: AbortSignal.timeout(400) }),
      "an unwrapped async rejection must never produce a response",
    );
  });
});

// ── P2-2: concurrent starts share one engine start ─────────────────────────

test("beginSessionStart: concurrent callers invoke the engine ONCE (single socket)", async () => {
  let calls = 0;
  const gate = deferred();
  const rs = {};
  const start = () => {
    calls++; // the makeWASocket stand-in: must run exactly once
    return gate.promise;
  };
  const first = beginSessionStart(rs, start);
  const second = beginSessionStart(rs, start);
  assert.equal(calls, 1, "the second concurrent start must not start a second socket");
  gate.resolve();
  await first;
  await second;
  assert.equal(rs.starting, undefined, "the memo is cleared once settled");
});

test("beginSessionStart: a failed start clears the memo so the next start retries", async () => {
  let calls = 0;
  const rs = {};
  const fail = () => {
    calls++;
    return Promise.reject(new Error("start failed"));
  };
  await assert.rejects(beginSessionStart(rs, fail));
  await assert.rejects(beginSessionStart(rs, fail));
  assert.equal(calls, 2, "a FAILED start must be retryable (memo not sticky)");
  assert.equal(rs.starting, undefined);
});

// ── P3-3: stdout PII masking ────────────────────────────────────────────────

test("maskDigits: only the last 4 digits survive (any input shape)", () => {
  assert.equal(maskDigits("218910089975"), "…9975");
  assert.equal(maskDigits("+218 910 089 975"), "…9975");
  assert.equal(maskDigits("218910089975@s.whatsapp.net"), "…9975"); // domain has no digits
  assert.equal(maskDigits("1234567"), "…4567");
  assert.equal(maskDigits("1234"), "…1234");
  assert.equal(maskDigits(""), "");
  assert.equal(maskDigits("no-digits-here"), "");
});

test("maskJid: user part masked, domain suffix preserved (LID vs PN stays diagnosable)", () => {
  assert.equal(maskJid("218910089975@s.whatsapp.net"), "…9975@s.whatsapp.net");
  assert.equal(maskJid("192616985542878@lid"), "…2878@lid");
  assert.equal(maskJid("218910089975"), "…9975"); // bare digits
  assert.equal(maskJid(""), "");
});

// ── P3-6: dashboard pair-code guard (real router over HTTP) ────────────────

// Dashboard env must be set BEFORE the router module loads (dashboard.ts
// snapshots it at import time) — hence the dynamic import.
process.env.DASHBOARD_USERNAME = "admin";
process.env.DASHBOARD_PASSWORD = "op-admin-pass";
process.env.DASHBOARD_SESSION_SECRET = "unit-test-dashboard-session-secret-0123456789";
const { mountDashboard, __pairCodeGuardForTest } = await import("../dist/dashboard-routes.js");
const guard = __pairCodeGuardForTest();

function dashView(overrides = {}) {
  return {
    id: "sess_dash1",
    name: "dash-test",
    status: "ready",
    createdAt: new Date().toISOString(),
    start: async () => {},
    requestPairCode: async () => "ABCD-EFGH",
    qrString: () => null,
    delete: async () => {},
    ...overrides,
  };
}

function dashApp(view) {
  const app = express();
  app.use(express.json());
  mountDashboard(app, {
    sessions: () => [view],
    info: () => ({ uptimeSec: 1, persist: false, version: "test" }),
    createSession: async (name) => ({
      id: "sess_new1",
      name,
      status: "created",
      createdAt: new Date().toISOString(),
    }),
  });
  return app;
}

async function login(base) {
  const res = await fetch(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "username=admin&password=op-admin-pass",
    redirect: "manual",
  });
  assert.equal(res.status, 302, "login must succeed and redirect");
  const jar = res.headers.getSetCookie?.() ?? [];
  const dash = jar.map((c) => c.split(";")[0]).find((c) => c.startsWith("openwa_dash="));
  assert.ok(dash, "login must set the openwa_dash cookie");
  return dash;
}

function pairCodePost(base, cookie) {
  return fetch(`${base}/dash/api/sessions/sess_dash1/pair-code`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie },
    body: JSON.stringify({ phone: "218910089975" }),
  });
}

test("dash pair-code: first issue 200, immediate retry 429, allowed again after the cooldown", async () => {
  guard.reset();
  let fakeNow = Date.now();
  guard.setClock(() => fakeNow);
  let issued = 0;
  const app = dashApp(dashView({
    requestPairCode: async () => {
      issued++;
      return "ABCD-EFGH";
    },
  }));
  await withServer(app, async (base) => {
    const cookie = await login(base);
    const first = await pairCodePost(base, cookie);
    assert.equal(first.status, 200);
    assert.equal((await first.json()).code, "ABCD-EFGH");
    // immediate duplicate — cooldown active:
    const second = await pairCodePost(base, cookie);
    assert.equal(second.status, 429);
    assert.ok((await second.json()).error.includes("انتظر"));
    // cooldown expired (60s window, clock is ours):
    fakeNow += 61_000;
    const third = await pairCodePost(base, cookie);
    assert.equal(third.status, 200);
    assert.equal(issued, 2, "only the first and third attempts reach WhatsApp");
  });
});

test("dash pair-code: a concurrent duplicate is 429 while the first is still in flight", async () => {
  guard.reset();
  let fakeNow = Date.now();
  guard.setClock(() => fakeNow);
  const gate = deferred();
  let calls = 0;
  const app = dashApp(dashView({
    requestPairCode: async () => {
      calls++;
      return gate.promise;
    },
  }));
  await withServer(app, async (base) => {
    const cookie = await login(base);
    const first = pairCodePost(base, cookie);
    await sleep(30); // let the first reach the engine
    const second = await pairCodePost(base, cookie);
    assert.equal(second.status, 429, "the in-flight duplicate must be rejected");
    gate.resolve("WXYZ-KLMN");
    const firstRes = await first;
    assert.equal(firstRes.status, 200);
    assert.equal((await firstRes.json()).code, "WXYZ-KLMN");
    assert.equal(calls, 1, "the duplicate never reaches requestPairingCode");
  });
});

test("dash router: an async rejection reaches the terminal error middleware (requireAuth forwards next)", async () => {
  guard.reset();
  const app = express();
  app.use(express.json());
  mountDashboard(app, {
    sessions: () => [],
    info: () => ({ uptimeSec: 1, persist: false, version: "test" }),
    createSession: async () => {
      throw new Error("engine exploded");
    },
  });
  app.use(terminalErrorMiddleware());
  await withServer(app, async (base) => {
    const cookie = await login(base);
    const res = await fetch(`${base}/dash/api/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie },
      body: JSON.stringify({ name: "hardening" }),
    });
    // 500 via asyncHandler → next(err) → terminal error mw. A dropped `next`
    // in requireAuth would fall through to Express's 404 instead — this
    // assertion pins the forwarding.
    assert.equal(res.status, 500);
    assert.deepEqual(await res.json(), { error: "internal" });
  });
});
