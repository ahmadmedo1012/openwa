/**
 * 110-K persistence hardening tests — the fixes landed this round:
 *
 *   109-h P3  doSave guard2→upsert window: a save that had already passed
 *             the in-memory tombstone guards could still land its upsert
 *             AFTER a wipe's DELETE completed (the await between guard2
 *             and the upsert is the window — a cold-Neon upsert can hang
 *             for seconds) and RESURRECT the wiped row. Fix: per-name FIFO
 *             write serialization (orderedWrites) — the wipe's DELETE
 *             queues behind any in-flight upsert and lands last. The wipe
 *             always wins; a save REQUESTED after the wipe call is still a
 *             legitimate re-pair and must keep working.
 *   109-h P3  restore-path blob filenames: isSafeBlobFilename (persist.ts)
 *             accepts every filename the Baileys multi-file auth store can
 *             produce (source-verified charset: @ for JIDs, +/= for base64
 *             app-state keys) and rejects traversal/absolute/separator/
 *             control-char/oversized names.
 *
 * Pool mocking: persist.ts exposes the @internal __setPoolForTest hook —
 * with PERSISTENCE_URL set to a dummy string, ensurePool() returns the
 * injected fake without ever touching a real database (the creation branch,
 * including the boot DDL, is skipped when a pool is already set). Module
 * cache-busting reloads dist/persist.js per test, exactly like
 * persist-key-separation.test.mjs. Run:
 *   node --test tests/persist-hardening.test.mjs   (after `npm run build`)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";

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

const API = "test-api-key-0123456789abcdef";
const CRED = "dedicated-credentials-key-0123456789abcdef";
// Non-empty dummy URL: persistenceEnabled() must be true for the pool path
// to run; the fake pool below intercepts every query.
const FAKE_URL = "postgresql://fake:test@localhost:5432/fakedb";

const BLOB = { "creds.json": '{"registered":true}', "pre-key-42.json": '{"key":1}' };
const serialize = async () => JSON.stringify(BLOB);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll until fn() is truthy (deterministic "query reached the pool"). */
async function waitFor(fn, ms = 2000) {
  const deadline = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > deadline) throw new Error("waitFor timeout");
    await sleep(5);
  }
}

/**
 * Fake pg Pool over an in-memory table. Faithful SQL semantics:
 *   INSERT … ON CONFLICT → upsert (ALWAYS writes — the resurrect vector)
 *   UPDATE … WHERE name=$1 → writes ONLY when the row exists (can't resurrect)
 *   DELETE … WHERE name=$1 → removes when present
 * `entered` records queries on arrival, `landed` on completion — the gap
 * between them is where the pre-fix race lived. parkInserts()/parkUpdates()
 * park the matching query on a gate, simulating a slow cold-Neon write.
 */
function makeFakePool() {
  const entered = [];
  const landed = [];
  const rows = new Map();
  let insertGate = null;
  let updateGate = null;
  let insertGateRelease = null;
  let updateGateRelease = null;
  const pool = {
    async query(sql, params) {
      const text = String(sql).trim();
      if (text.startsWith("INSERT INTO openwa_sessions")) {
        entered.push("insert");
        if (insertGate) await insertGate;
        rows.set(params[0], params[1]);
        landed.push("insert");
        return { rowCount: 1 };
      }
      if (text.startsWith("UPDATE openwa_sessions")) {
        entered.push("update");
        if (updateGate) await updateGate;
        landed.push("update");
        if (rows.has(params[0])) {
          rows.set(params[0], params[1]);
          return { rowCount: 1 };
        }
        return { rowCount: 0 }; // UPDATE on a deleted row = no-op
      }
      if (text.startsWith("DELETE FROM openwa_sessions")) {
        entered.push("delete");
        landed.push("delete");
        return { rowCount: rows.delete(params[0]) ? 1 : 0 };
      }
      if (text.startsWith("SELECT creds FROM openwa_sessions")) {
        entered.push("select");
        landed.push("select");
        const creds = rows.get(params[0]);
        return creds ? { rowCount: 1, rows: [{ creds }] } : { rowCount: 0, rows: [] };
      }
      entered.push("other");
      landed.push("other");
      return { rowCount: 0, rows: [] };
    },
  };
  // O2-F5 (R111): flushNow's upsert now runs on a DEDICATED client inside a
  // transaction (BEGIN / SET LOCAL statement_timeout / INSERT / COMMIT).
  // The fake client swallows the transaction plumbing (recorded separately
  // in clientQueries) and delegates the INSERT itself to the shared pool
  // path, so the parking-gate semantics the race tests below rely on stay
  // intact — `entered`/`landed` keep seeing exactly the insert/delete/etc.
  // ops they always did.
  const clientQueries = [];
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
      return pool.query(sql, params);
    },
    release() {},
  };
  pool.connect = async () => client;
  return {
    pool,
    rows,
    entered,
    landed,
    clientQueries,
    parkInserts() {
      insertGate = new Promise((r) => {
        insertGateRelease = r;
      });
    },
    releaseParkedInsert() {
      insertGateRelease?.();
      insertGateRelease = null;
    },
    parkUpdates() {
      updateGate = new Promise((r) => {
        updateGateRelease = r;
      });
    },
    releaseParkedUpdate() {
      updateGateRelease?.();
      updateGateRelease = null;
    },
  };
}

// ── isSafeBlobFilename: lossless for the engine, hostile to traversal ──────

test("isSafeBlobFilename: accepts EVERY filename the Baileys auth store produces", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  const ok = (f) => assert.equal(persist.isSafeBlobFilename(f), true, `must accept ${f}`);
  // Source-verified shapes (use-multi-file-auth-state + libsignal):
  ok("creds.json");
  ok("pre-key-42.json");
  ok("session-218910089975.1.json"); // ProtocolAddress `${user}.${device}`
  // SenderKeyName `${groupJid}::${user}.${device}` — ':' → '--' on disk:
  ok("sender-key-123456789-1234567890@g.us--218910089975.1.json");
  ok("sender-key-192616985542878@lid--218910089975.0.json");
  ok("sender-key-memory-218910089975@c.us.json");
  // app-state-sync-key ids are base64 ('/' → '__', keeps '+' and '='):
  ok("app-state-sync-key-AbC+12dE__9f=.json");
  ok("app-state-sync-version-critical_block.json");
  ok("a".repeat(255)); // Linux NAME_MAX boundary is still a valid name
});

test("isSafeBlobFilename: rejects traversal, absolute paths, separators, control chars", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  const bad = (f) => assert.equal(persist.isSafeBlobFilename(f), false, `must reject ${JSON.stringify(f)}`);
  bad("../creds.json"); // parent traversal
  bad("..\\..\\creds.json"); // windows-style traversal
  bad("/etc/passwd"); // absolute posix path
  bad("C:\\Windows\\temp\\creds.json"); // windows absolute + separators + ':'
  bad("creds.json/../../etc/passwd"); // separator mid-name
  bad("creds.json\\evil"); // backslash separator
  bad("creds.json\0.txt"); // NUL byte
  bad("creds.json\n"); // newline (log/poisoning hygiene)
  bad("creds .json"); // space (not engine-produced)
});

test("isSafeBlobFilename: rejects dot-names, empty and >255-char names", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  // '.' and '..' PASS the charset (dots are allowed) — rejected explicitly:
  assert.equal(persist.isSafeBlobFilename("."), false);
  assert.equal(persist.isSafeBlobFilename(".."), false);
  assert.equal(persist.isSafeBlobFilename(""), false);
  assert.equal(persist.isSafeBlobFilename("a".repeat(256)), false); // > NAME_MAX
});

// ── WA-02: the wipe must always win over an in-flight stale save ────────────

test("race: a wipe issued while an upsert is mid-flight lands LAST — no resurrection", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: FAKE_URL });
  const fake = makeFakePool();
  persist.__setPoolForTest(fake.pool);

  // The save passes BOTH tombstone guards, then its upsert parks in the
  // pool (a cold just-woken Neon can take seconds — the real-world window).
  fake.parkInserts();
  const saveP = persist.flushNow("s1", serialize);
  await waitFor(() => fake.entered.includes("insert"));

  // The wipe is requested (and its caller waits) while the upsert is
  // still mid-flight. Chain order is fixed synchronously at call time.
  const wipeP = persist.deletePersisted("s1");

  // The DELETE must NOT land while the in-flight save holds the per-name
  // write chain — pre-fix the DELETE executed immediately and the late
  // upsert then resurrected the row.
  await sleep(25);
  assert.equal(
    fake.landed.includes("delete"),
    false,
    "the wipe must queue behind the in-flight save",
  );

  fake.releaseParkedInsert(); // the upsert finally lands
  await Promise.all([saveP, wipeP]);

  // THE invariant: the DELETE lands AFTER the parked upsert, so the row
  // ends up gone (the wipe wins).
  assert.deepEqual(fake.landed, ["insert", "delete"]);
  assert.equal(fake.rows.has("s1"), false, "the wipe must win — no resurrected row");
});

test("guards + chain: a save REQUESTED before the wipe but running after it is killed (no query)", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: FAKE_URL });
  const fake = makeFakePool();
  persist.__setPoolForTest(fake.pool);

  // save1 parks holding the write chain; save2 is requested BEFORE the
  // wipe (so its startedAt < the tombstone) but only RUNS after it.
  fake.parkInserts();
  const save1 = persist.flushNow("s2", serialize);
  await waitFor(() => fake.entered.includes("insert"));
  const save2 = persist.flushNow("s2", serialize);
  const wipe = persist.deletePersisted("s2");
  await sleep(25);
  assert.equal(
    fake.landed.includes("delete"),
    false,
    "the wipe must queue behind the parked save",
  );

  fake.releaseParkedInsert();
  await Promise.all([save1, save2, wipe]);

  // save2 must be guard-killed (tombstone >= its request time → it never
  // reaches the pool); save1's upsert lands, then the DELETE removes it.
  assert.deepEqual(fake.landed, ["insert", "delete"]);
  assert.equal(fake.rows.has("s2"), false);
});

test("a save requested AFTER a completed wipe still writes (legit re-pair unaffected)", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: FAKE_URL });
  const fake = makeFakePool();
  persist.__setPoolForTest(fake.pool);

  await persist.deletePersisted("s3"); // tombstone + DELETE complete
  assert.equal(fake.rows.has("s3"), false);
  // A real re-pair takes seconds (QR scan); the tombstone guard uses
  // `wipe >= startedAt`, so step past the wipe's millisecond to model it.
  await sleep(2);
  await persist.flushNow("s3", serialize); // FRESH pairing saves normally
  assert.equal(fake.rows.has("s3"), true, "a post-wipe re-pair save must persist");
});

test("rekey: an UPDATE landing after a wipe DELETE is a no-op (UPDATE can never resurrect)", async () => {
  // The legacy re-key path is safe by SQL semantics (plain UPDATE with a
  // WHERE, no ON CONFLICT) — this test pins that property so a future
  // refactor to an upsert can't silently reopen the resurrection vector.
  const legacy = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  const blob = legacy.__cryptoForTest().encryptCurrent(JSON.stringify(BLOB));
  const persist = await loadPersist({
    OPENWA_API_KEY: API,
    OPENWA_CREDENTIALS_KEY: CRED,
    PERSISTENCE_URL: FAKE_URL,
  });
  const fake = makeFakePool();
  persist.__setPoolForTest(fake.pool);
  fake.rows.set("s4", blob); // legacy-keyed blob triggers the re-key path

  fake.parkUpdates();
  const loadP = persist.loadCreds("s4"); // SELECT → legacy decrypt → re-key UPDATE parks
  await waitFor(() => fake.entered.includes("update"));
  await persist.deletePersisted("s4"); // DELETE completes while the UPDATE is parked
  assert.equal(fake.rows.has("s4"), false);
  fake.releaseParkedUpdate();

  const plaintext = await loadP;
  assert.equal(plaintext, JSON.stringify(BLOB)); // the boot restore still gets its creds…
  assert.equal(fake.rows.has("s4"), false); // …but the UPDATE no-oped on the deleted row
});
