// Key-separation audit tests (2026-09-20) — OPENWA_CREDENTIALS_KEY vs
// OPENWA_API_KEY. Proves backward compatibility (byte-identical derivation
// when unset), separation (new derivation when set), the legacy-fallback
// decrypt path, and the wrong-key failure mode. Uses query-string module
// cache-busting to reload dist/persist.js under different env combos.
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

test("unset OPENWA_CREDENTIALS_KEY keeps the legacy derivation (backward compat)", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  const c = persist.__cryptoForTest();
  assert.equal(c.legacyKeyAvailable(), false);
  const blob = c.encryptCurrent('{"creds":"legacy-shape"}');
  assert.equal(c.decryptCurrent(blob), '{"creds":"legacy-shape"}');
  assert.equal(c.decryptLegacy(blob), '{"creds":"legacy-shape"}');
  // AND: byte-identical to the pre-split derivation (scrypt(API_KEY, salt))
  const { scryptSync, createCipheriv, randomBytes } = await import("node:crypto");
  const oldKey = scryptSync(API, "openwa-gateway-creds-v1", 32);
  // same IV/tag layout → decrypt manually with the pre-split derivation
  const decipher = createCipheriv === undefined ? undefined : null; // (typing shim)
  const { createDecipheriv } = await import("node:crypto");
  const d = createDecipheriv("aes-256-gcm", oldKey, blob.subarray(0, 12));
  d.setAuthTag(blob.subarray(12, 28));
  const plain = Buffer.concat([d.update(blob.subarray(28)), d.final()]).toString("utf8");
  assert.equal(plain, '{"creds":"legacy-shape"}');
});

test("set OPENWA_CREDENTIALS_KEY separates the derivations", async () => {
  const persist = await loadPersist({
    OPENWA_API_KEY: API,
    OPENWA_CREDENTIALS_KEY: CRED,
    PERSISTENCE_URL: "",
  });
  const c = persist.__cryptoForTest();
  assert.equal(c.legacyKeyAvailable(), true);
  const blob = c.encryptCurrent('{"creds":"new-shape"}');
  assert.equal(c.decryptCurrent(blob), '{"creds":"new-shape"}');
  // current-key blob is NOT readable with the legacy derivation
  assert.throws(() => c.decryptLegacy(blob));
});

test("legacy blob (API-key encrypted) decrypts via the legacy path", async () => {
  const legacy = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  const blob = legacy.__cryptoForTest().encryptCurrent('{"creds":"pre-split"}');
  const modern = await loadPersist({
    OPENWA_API_KEY: API,
    OPENWA_CREDENTIALS_KEY: CRED,
    PERSISTENCE_URL: "",
  });
  const c = modern.__cryptoForTest();
  assert.equal(c.decryptLegacy(blob), '{"creds":"pre-split"}');
  assert.throws(() => c.decryptCurrent(blob));
});

test("wrong credentials key fails BOTH paths (honest unreadable)", async () => {
  const original = await loadPersist({
    OPENWA_API_KEY: API,
    OPENWA_CREDENTIALS_KEY: CRED,
    PERSISTENCE_URL: "",
  });
  const blob = original.__cryptoForTest().encryptCurrent('{"creds":"real"}');
  const wrong = await loadPersist({
    OPENWA_API_KEY: API,
    OPENWA_CREDENTIALS_KEY: "a-completely-different-key-0123456789",
    PERSISTENCE_URL: "",
  });
  const c = wrong.__cryptoForTest();
  // The blob was CRED-encrypted: the wrong current key fails AND the
  // API-key legacy path fails too (it was never API-encrypted) — honest
  // unreadable. Recovery: unset the wrong key / restore the right one;
  // the blob on disk is untouched (loadCreds never overwrites it here).
  assert.throws(() => c.decryptCurrent(blob));
  assert.throws(() => c.decryptLegacy(blob));
});

test("memoized derivation is stable across calls", async () => {
  const persist = await loadPersist({ OPENWA_API_KEY: API, PERSISTENCE_URL: "" });
  const c = persist.__cryptoForTest();
  const b1 = c.encryptCurrent("same");
  const b2 = c.encryptCurrent("same");
  // IVs differ (random per encryption) but both decrypt with the same key
  assert.equal(c.decryptCurrent(b1), "same");
  assert.equal(c.decryptCurrent(b2), "same");
});
