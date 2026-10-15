/**
 * R149 acceptance tests — the WhatsApp retry contract ("Waiting for this
 * message" fix). Baileys 6.7.24 calls getMessage(key) exactly when a
 * recipient device requests a re-send (retry receipt → sendMessagesAgain,
 * lib/Socket/messages-recv.js:468); a miss is silently dropped and the
 * recipient's placeholder is permanent (WhiskeySockets/Baileys#1767).
 *
 * These pin the STORE primitive (createBoundedTtlMap in lib.ts) that
 * engineSend now feeds and getMessage now serves, plus the WA-02
 * pairing-death clearing wired into resetSessionIdentity:
 *
 *   - a recorded send is retrievable by its message id (exact content)
 *   - an absent or expired entry returns undefined — the safe explicit miss
 *   - FIFO cap bounds storage; re-set updates in place
 *   - clear() drops every entry (pairing death / sensitive-data deletion)
 *   - the store instance survives a "reconnect" (it lives on the session
 *     record, not the socket) — pre-reconnect sends stay retry-servable
 *   - resetSessionIdentity wipes retryMessages with the dead pairing
 *   - the msgRetryCounterCache shape satisfies Baileys' CacheStore contract
 *     (get/set/del/flushAll) with number values
 *
 * Mechanism-level like the repo's other suites: imports the compiled
 * dist/lib.js exactly the way the engine does. Run:
 *   node --test tests/retry-store.test.mjs   (after `npm run build`)
 *
 * اختبارات عقد إعادة الإرسال — جذر مشكلة «بانتظار هذه الرسالة».
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createBoundedTtlMap,
  resetSessionIdentity,
  RETRY_STORE_CAP,
  RETRY_STORE_TTL_MS,
  MSG_RETRY_CACHE_CAP,
  MSG_RETRY_CACHE_TTL_MS,
} from "../dist/lib.js";

/** Injectable clock: start at a fixed epoch, advance on demand. */
function fakeClock(startMs = 1_000_000) {
  let now = startMs;
  return { now: () => now, advance: (ms) => (now += ms) };
}

/** The message CONTENT shape Baileys' getMessage must return (proto.IMessage
 * — the `message` field of the sent WAMessage, NOT the full WebMessageInfo). */
const otpMessage = (code) => ({ conversation: `رمز التحقق الخاص بك: ${code}` });

// ── successful send + retry request obtains the correct original payload ────

test("retry store: a recorded send is retrievable by message id with the exact content", () => {
  const store = createBoundedTtlMap(10, 60_000);
  const msg = otpMessage("123456");
  store.set("3EB0F5C7A9", msg);
  assert.equal(store.get("3EB0F5C7A9"), msg); // same reference — zero-copy serve
  assert.deepEqual(store.get("3EB0F5C7A9"), { conversation: "رمز التحقق الخاص بك: 123456" });
});

test("retry store: ids are independent — one send never serves another's content", () => {
  const store = createBoundedTtlMap(10, 60_000);
  store.set("msg-A", otpMessage("111111"));
  store.set("msg-B", otpMessage("222222"));
  assert.deepEqual(store.get("msg-A"), { conversation: "رمز التحقق الخاص بك: 111111" });
  assert.deepEqual(store.get("msg-B"), { conversation: "رمز التحقق الخاص بك: 222222" });
});

// ── absent / expired → the safe explicit miss (undefined, never a stub) ─────

test("retry store: an unknown id returns undefined — the safe explicit miss", () => {
  const store = createBoundedTtlMap(10, 60_000);
  assert.equal(store.get("never-sent"), undefined);
});

test("retry store: an expired entry returns undefined AND is evicted", () => {
  const clock = fakeClock();
  const store = createBoundedTtlMap(10, RETRY_STORE_TTL_MS, clock.now);
  store.set("old", otpMessage("999999"));
  clock.advance(RETRY_STORE_TTL_MS + 1); // past the TTL
  assert.equal(store.get("old"), undefined); // miss, not stale plaintext
  assert.equal(store.size(), 0); // the read evicted the expired entry
});

test("retry store: an entry just inside the TTL is still served", () => {
  const clock = fakeClock();
  const store = createBoundedTtlMap(10, RETRY_STORE_TTL_MS, clock.now);
  const msg = otpMessage("123456");
  store.set("fresh", msg);
  clock.advance(RETRY_STORE_TTL_MS - 1); // 1 ms before expiry
  assert.equal(store.get("fresh"), msg);
});

// ── bounded storage: FIFO cap + re-set semantics ────────────────────────────

test("retry store: FIFO cap evicts the OLDEST entries past the cap", () => {
  const store = createBoundedTtlMap(3, 60_000);
  store.set("m1", otpMessage("1"));
  store.set("m2", otpMessage("2"));
  store.set("m3", otpMessage("3"));
  store.set("m4", otpMessage("4")); // evicts m1
  store.set("m5", otpMessage("5")); // evicts m2
  assert.equal(store.size(), 3);
  assert.equal(store.get("m1"), undefined);
  assert.equal(store.get("m2"), undefined);
  assert.deepEqual(store.get("m3"), otpMessage("3"));
  assert.deepEqual(store.get("m4"), otpMessage("4"));
  assert.deepEqual(store.get("m5"), otpMessage("5"));
});

test("retry store: re-setting an existing id updates the content in place", () => {
  const store = createBoundedTtlMap(10, 60_000);
  store.set("same-id", otpMessage("first"));
  store.set("same-id", otpMessage("second"));
  assert.deepEqual(store.get("same-id"), otpMessage("second"));
  assert.equal(store.size(), 1);
});

test("retry store bounds match the R149 decision of record", () => {
  // 30 min = 6× the 5-min SubNation OTP validity; cap = DELIVERY_LOG_CAP discipline.
  assert.equal(RETRY_STORE_TTL_MS, 30 * 60_000);
  assert.equal(RETRY_STORE_CAP, 500);
  // Counter cache TTL matches Baileys' DEFAULT_CACHE_TTLS.MSG_RETRY (1 h).
  assert.equal(MSG_RETRY_CACHE_TTL_MS, 3_600_000);
  assert.equal(MSG_RETRY_CACHE_CAP, 1_000);
});

// ── sensitive-data deletion + pairing death (WA-02) ─────────────────────────

test("retry store: delete() removes a single entry; clear() drops every entry", () => {
  const store = createBoundedTtlMap(10, 60_000);
  store.set("a", otpMessage("1"));
  store.set("b", otpMessage("2"));
  assert.equal(store.delete("a"), true);
  assert.equal(store.get("a"), undefined);
  assert.equal(store.delete("a"), false); // already gone
  store.clear();
  assert.equal(store.size(), 0);
  assert.equal(store.get("b"), undefined);
});

test("resetSessionIdentity wipes the retry store with the dead pairing (WA-02)", () => {
  const store = createBoundedTtlMap(10, 60_000);
  store.set("dead-pairing-msg", otpMessage("123456"));
  const rs = {
    status: "ready",
    lastReadyAt: "2026-10-15T00:00:00.000Z",
    accountDigits: "218910000000",
    deliveryLog: [],
    retryMessages: store,
  };
  resetSessionIdentity(rs);
  assert.equal(rs.retryMessages, store); // same instance…
  assert.equal(store.size(), 0); // …emptied — no old-pairing OTP survives a re-pair
  assert.equal(store.get("dead-pairing-msg"), undefined);
});

// ── the store survives a reconnect (lives on the session record) ────────────

test("retry store: entries recorded before a 'reconnect' stay retry-servable after it", () => {
  // The engine holds the store on the SESSION record (rs.retryMessages ??= …),
  // so a new socket (startSession re-run) reuses the SAME instance — pin that
  // contract through the exact lazy-init idiom index.ts uses.
  const rs = {};
  const first = (rs.retryMessages ??= createBoundedTtlMap(10, 60_000));
  first.set("pre-reconnect", otpMessage("123456"));
  // …socket disconnects, startSession runs again with a fresh socket…
  const second = (rs.retryMessages ??= createBoundedTtlMap(10, 60_000));
  assert.equal(second, first); // lazy-init kept the existing store
  assert.deepEqual(second.get("pre-reconnect"), otpMessage("123456")); // still servable
});

// ── msgRetryCounterCache satisfies Baileys' CacheStore contract ─────────────

test("counter cache: the BoundedTtlMap number store satisfies the CacheStore usage pattern", () => {
  // messages-recv.js: msgRetryCache.get(key) || 0 … set(key, get(key)+1);
  // del on flush paths; flushAll on pairing reset. Pin the exact usage
  // (the engine's adapter renames delete→del for the CacheStore interface).
  const cache = createBoundedTtlMap(10, 60_000);
  const key = "3EB0F5C7A9:218913456789:9@s.whatsapp.net";
  assert.equal(cache.get(key) || 0, 0); // absent → Baileys' own || 0 default
  cache.set(key, (cache.get(key) || 0) + 1);
  cache.set(key, (cache.get(key) || 0) + 1);
  assert.equal(cache.get(key), 2);
  cache.delete(key);
  assert.equal(cache.get(key), undefined);
  cache.set(key, 1);
  cache.clear(); // the engine's adapter maps flushAll → clear
  assert.equal(cache.get(key), undefined);
});

test("counter cache: counters expire on the Baileys TTL (1 h) — no unbounded retention", () => {
  const clock = fakeClock();
  const cache = createBoundedTtlMap(10, MSG_RETRY_CACHE_TTL_MS, clock.now);
  cache.set("id:participant", 4);
  clock.advance(MSG_RETRY_CACHE_TTL_MS + 1);
  assert.equal(cache.get("id:participant"), undefined);
});
