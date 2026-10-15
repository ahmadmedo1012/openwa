/**
 * R150 acceptance tests — restart persistence of the WhatsApp retry
 * contract + the PII-masked Baileys log adapter.
 *
 * R149 established the retry contract (getMessage + bounded stores) but
 * kept the stores in-memory: a container restart inside a message's retry
 * window orphaned it — the recipient's retry receipt would miss forever
 * ("Waiting for this message" made PERMANENT by a redeploy). R150 closes
 * that: snapshot()/initial make the store serialize/rehydrate with its
 * ORIGINAL write timestamps, and the state file rides the existing
 * encrypted persistence snapshot (same unit as the credentials).
 *
 * This suite pins:
 *
 *   - snapshot() = the serialization surface (insertion order, timestamps)
 *   - rehydration restores entries with their ORIGINAL TTL anchor — an
 *     entry written 10 min before a restart (TTL 30 min) survives it and
 *     expires 20 min later, NOT 30 min later (no TTL reset on restore)
 *   - expired entries never resurrect across a restart
 *   - the FIFO cap keeps only the NEWEST entries on rehydration
 *   - the exact index.ts chain: snapshot → JSON.stringify → JSON.parse →
 *     createBoundedTtlMap(initial) round-trips content losslessly
 *   - malformed initial entries (non-string id / non-number at) are dropped
 *   - RETRY_STATE_FNAME is a legal, collision-free auth-folder filename
 *     (passes the restore-path guard in persist.ts; never matches a
 *     Baileys auth-file prefix)
 *   - maskLogValue masks JIDs and bare phone digits EVERYWHERE in a log
 *     object (nested objects/arrays) while leaving message ids, numbers,
 *     and plain words untouched; buffer-ish values never reach the surface
 *   - shouldForwardBaileysInfo passes exactly the retry-relevant Baileys
 *     info lines ('recv retry for not fromMe message' = the misclassified
 *     receipt signature; 'will not send message again, as sent too many
 *     times' = exhausted budget) and drops the rest
 *   - createBaileysLogAdapter: warn/error always forwarded masked;
 *     info forwarded only when retry-relevant; child() composes bindings;
 *     the single-string pino call form works
 *
 * Mechanism-level like the repo's other suites: imports the compiled
 * dist/lib.js + dist/persist.js exactly the way the engine does. Run:
 *   node --test tests/retry-persistence.test.mjs   (after `npm run build`)
 *
 * اختبارات بقاء عقد إعادة الإرسال عبر إعادة التشغيل — وقناع سجل Baileys.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  createBoundedTtlMap,
  maskLogValue,
  shouldForwardBaileysInfo,
  createBaileysLogAdapter,
  RETRY_STATE_FNAME,
  RETRY_STORE_CAP,
  RETRY_STORE_TTL_MS,
} from "../dist/lib.js";
import { isSafeBlobFilename } from "../dist/persist.js";

/** Injectable clock: start at a fixed epoch, advance on demand. */
function fakeClock(startMs = 1_000_000) {
  let now = startMs;
  return { now: () => now, advance: (ms) => (now += ms) };
}

const otpMessage = (code) => ({ conversation: `رمز التحقق: ${code}` });

/** Capture logger — records every forwarded line. */
function recordingLogger() {
  const lines = [];
  return {
    lines,
    info: (obj, msg) => lines.push({ level: "info", obj, msg }),
    warn: (obj, msg) => lines.push({ level: "warn", obj, msg }),
    error: (obj, msg) => lines.push({ level: "error", obj, msg }),
  };
}

// ── snapshot(): the serialization surface ───────────────────────────────────

test("snapshot: returns entries in insertion order with their write timestamps", () => {
  const clock = fakeClock();
  const store = createBoundedTtlMap(10, 60_000, clock.now);
  store.set("msg-A", otpMessage("111111"));
  clock.advance(1_000);
  store.set("msg-B", otpMessage("222222"));
  const snap = store.snapshot();
  assert.equal(snap.length, 2);
  assert.deepEqual(snap[0], { id: "msg-A", value: otpMessage("111111"), at: 1_000_000 });
  assert.deepEqual(snap[1], { id: "msg-B", value: otpMessage("222222"), at: 1_001_000 });
});

test("snapshot: reflects updates (re-set overwrites the value, refreshes the timestamp)", () => {
  const clock = fakeClock();
  const store = createBoundedTtlMap(10, 60_000, clock.now);
  store.set("msg-A", otpMessage("old"));
  clock.advance(5_000);
  store.set("msg-A", otpMessage("new"));
  const snap = store.snapshot();
  assert.equal(snap.length, 1);
  assert.deepEqual(snap[0].value, otpMessage("new"));
  assert.equal(snap[0].at, 1_005_000);
});

test("snapshot: an empty store serializes to an empty array (never undefined)", () => {
  const store = createBoundedTtlMap(10, 60_000);
  assert.deepEqual(store.snapshot(), []);
});

// ── rehydration: the restart-persistence contract ──────────────────────────

test("rehydrate: entries written before a restart are served after it (the R150 fix)", () => {
  const clock = fakeClock();
  const live = createBoundedTtlMap(10, RETRY_STORE_TTL_MS, clock.now);
  live.set("msg-A", otpMessage("123456"));
  // "process restart": the exact index.ts chain — JSON round-trip + initial
  const revived = createBoundedTtlMap(
    10,
    RETRY_STORE_TTL_MS,
    clock.now,
    JSON.parse(JSON.stringify(live.snapshot())),
  );
  assert.deepEqual(revived.get("msg-A"), otpMessage("123456"));
});

test("rehydrate: the TTL stays anchored to the ORIGINAL send time — a restart never resets it", () => {
  const clock = fakeClock();
  const live = createBoundedTtlMap(10, RETRY_STORE_TTL_MS, clock.now);
  live.set("msg-A", otpMessage("123456"));
  clock.advance(10 * 60_000); // 10 min pass, then the process restarts
  const revived = createBoundedTtlMap(
    10,
    RETRY_STORE_TTL_MS,
    clock.now,
    JSON.parse(JSON.stringify(live.snapshot())),
  );
  assert.ok(revived.get("msg-A"), "20 min of TTL headroom remain right after the restart");
  clock.advance(20 * 60_000 + 1); // the remaining 20 min elapse — 30 min TOTAL
  assert.equal(revived.get("msg-A"), undefined, "expired 30 min after the ORIGINAL send, not after the restart");
});

test("rehydrate: an entry that already expired before the restart NEVER resurrects", () => {
  const clock = fakeClock();
  const live = createBoundedTtlMap(10, RETRY_STORE_TTL_MS, clock.now);
  live.set("msg-old", otpMessage("999999"));
  clock.advance(RETRY_STORE_TTL_MS + 1); // past the TTL, then the restart
  const revived = createBoundedTtlMap(
    10,
    RETRY_STORE_TTL_MS,
    clock.now,
    JSON.parse(JSON.stringify(live.snapshot())),
  );
  assert.equal(revived.get("msg-old"), undefined);
  assert.equal(revived.size(), 0); // filtered at hydrate — no stale plaintext loaded at all
});

test("rehydrate: the FIFO cap keeps only the NEWEST entries", () => {
  const clock = fakeClock();
  const live = createBoundedTtlMap(3, RETRY_STORE_TTL_MS, clock.now);
  live.set("m1", otpMessage("1"));
  clock.advance(1_000);
  live.set("m2", otpMessage("2"));
  clock.advance(1_000);
  live.set("m3", otpMessage("3"));
  clock.advance(1_000);
  live.set("m4", otpMessage("4")); // evicts m1 in the live map
  const revived = createBoundedTtlMap(
    3,
    RETRY_STORE_TTL_MS,
    clock.now,
    JSON.parse(JSON.stringify(live.snapshot())),
  );
  assert.equal(revived.size(), 3);
  assert.equal(revived.get("m1"), undefined); // oldest stayed evicted
  assert.deepEqual(revived.get("m4"), otpMessage("4"));
});

test("rehydrate: a snapshot LARGER than the cap trims to the newest cap entries", () => {
  const clock = fakeClock();
  const big = Array.from({ length: 10 }, (_, i) => ({
    id: `m${i}`,
    value: otpMessage(String(i)),
    at: 1_000_000 + i * 1_000,
  }));
  const revived = createBoundedTtlMap(4, RETRY_STORE_TTL_MS, clock.now, big);
  assert.equal(revived.size(), 4);
  assert.equal(revived.get("m0"), undefined);
  assert.equal(revived.get("m5"), undefined);
  assert.deepEqual(revived.get("m9"), otpMessage("9"));
});

test("rehydrate: malformed entries (non-string id / non-number at) are dropped individually", () => {
  const clock = fakeClock();
  const poisoned = [
    { id: "good", value: otpMessage("123456"), at: 1_000_000 },
    { id: 42, value: otpMessage("bad"), at: 1_000_000 }, // numeric id
    { id: "no-at", value: otpMessage("bad") }, // missing timestamp
    null, // junk row
    "not-an-entry",
  ];
  const revived = createBoundedTtlMap(10, RETRY_STORE_TTL_MS, clock.now, poisoned);
  assert.equal(revived.size(), 1);
  assert.deepEqual(revived.get("good"), otpMessage("123456"));
});

test("rehydrate: counters round-trip too — the 5-resend bound stays total across restarts", () => {
  const clock = fakeClock();
  const counters = createBoundedTtlMap(100, 3_600_000, clock.now);
  counters.set("3EB0F5C7A9:218913456789:0", 4); // Baileys' `${id}:${participant}` key shape
  const revived = createBoundedTtlMap(
    100,
    3_600_000,
    clock.now,
    JSON.parse(JSON.stringify(counters.snapshot())),
  );
  assert.equal(revived.get("3EB0F5C7A9:218913456789:0"), 4); // 4 of 5 budget used BEFORE the restart
  revived.set("3EB0F5C7A9:218913456789:0", 5); // the last retry after it
  assert.equal(revived.get("3EB0F5C7A9:218913456789:0"), 5); // budget exhausted — stays exhausted
});

test("rehydrate: an undefined initial stays an empty store (fresh boot, no state file)", () => {
  const store = createBoundedTtlMap(10, 60_000, Date.now, undefined);
  assert.equal(store.size(), 0);
  assert.deepEqual(store.snapshot(), []);
});

// ── the state-file name is a legal, collision-free auth-folder citizen ─────

test("state file: RETRY_STATE_FNAME passes the restore-path filename guard", () => {
  assert.ok(isSafeBlobFilename(RETRY_STATE_FNAME), "must survive the persist.ts blob-restore validation");
});

test("state file: never collides with a Baileys auth-file name", () => {
  const baileysPrefixes = ["creds.json", "pre-key-", "session-", "sender-key-", "sender-key-memory-", "app-state-sync-key-", "app-state-sync-version-"];
  for (const p of baileysPrefixes) {
    assert.ok(!RETRY_STATE_FNAME.startsWith(p), `must not look like ${p}`);
  }
  assert.ok(RETRY_STATE_FNAME.startsWith("__openwa_"), "our private namespace");
});

// ── maskLogValue: the log-surface PII masker ───────────────────────────────

test("maskLogValue: JIDs are masked everywhere in the object graph", () => {
  const masked = maskLogValue({
    attrs: { from: "218913456789@s.whatsapp.net", participant: "218910089975:5@lid" },
    key: { remoteJid: "120363023070206483@g.us", id: "3EB0F5C7A9" },
    list: ["218913456789@s.whatsapp.net", { to: "user@lid" }],
  });
  assert.equal(masked.attrs.from, "…6789@s.whatsapp.net");
  assert.equal(masked.attrs.participant, "…9755@lid"); // maskJid merges the :device digit before slicing (…89975 + :5 → "9755") — R149 primitive behavior
  assert.equal(masked.key.remoteJid, "…6483@g.us");
  assert.equal(masked.key.id, "3EB0F5C7A9", "message ids are not PII — untouched");
  assert.equal(masked.list[0], "…6789@s.whatsapp.net");
  assert.equal(masked.list[1].to, "@lid", "non-digit user part collapses to the bare domain");
});

test("maskLogValue: bare phone-digit strings are masked; ids/words/numbers untouched", () => {
  assert.equal(maskLogValue("218913456789"), "…6789");
  assert.equal(maskLogValue("+218913456789"), "…6789");
  assert.equal(maskLogValue("3EB0F5C7A9B2D1"), "3EB0F5C7A9B2D1", "hex message id — not a phone");
  assert.equal(maskLogValue("hello"), "hello");
  assert.equal(maskLogValue(1719), 1719);
  assert.equal(maskLogValue(null), null);
  assert.deepEqual(maskLogValue({ count: 2, t: 1760000000 }), { count: 2, t: 1760000000 });
});

test("maskLogValue: buffer-ish values never reach the log surface", () => {
  const masked = maskLogValue({ frame: { type: "Buffer", data: [1, 2, 3] } });
  assert.equal(masked.frame, "[buffer]");
});

test("maskLogValue: an Error contributes its message with only the embedded JID masked", () => {
  const err = new Error("boom for 218913456789@s.whatsapp.net");
  assert.equal(maskLogValue(err), "boom for …6789@s.whatsapp.net");
});

test("maskLogValue: a string with MULTIPLE embedded JIDs masks each one", () => {
  const masked = maskLogValue("retry loop between 218913456789@s.whatsapp.net and 192616985542878:9@lid failed");
  // maskJid merges the :device digit before slicing (…542878 + :9 → last-4 "8789").
  assert.equal(masked, "retry loop between …6789@s.whatsapp.net and …8789@lid failed");
});

test("maskLogValue: deep nesting is bounded, never a stack overflow", () => {
  // Within bounds (depth ≤ 8): the leaf JID still gets masked.
  let shallow = { jid: "218913456789@s.whatsapp.net" };
  for (let i = 0; i < 5; i++) shallow = { nested: shallow };
  assert.ok(JSON.stringify(maskLogValue(shallow)).includes("…6789"));
  // Far past the bound: recursion stops safely with [depth], no crash, and
  // the too-deep leaf is simply not reachable.
  let deep = { jid: "218913456789@s.whatsapp.net" };
  for (let i = 0; i < 50; i++) deep = { nested: deep };
  const masked = maskLogValue(deep);
  assert.ok(JSON.stringify(masked).includes("[depth]"));
  assert.equal(JSON.stringify(masked).includes("218913456789"), false, "the too-deep leaf never leaks unmasked");
});

// ── shouldForwardBaileysInfo: which info lines are retry observables ───────

test("forward filter: the retry-relevant Baileys info lines pass", () => {
  assert.ok(shouldForwardBaileysInfo("recv retry for not fromMe message"));
  assert.ok(shouldForwardBaileysInfo("will not send message again, as sent too many times"));
  assert.ok(shouldForwardBaileysInfo("error in sending message again"));
});

test("forward filter: ordinary Baileys info noise is dropped", () => {
  assert.equal(shouldForwardBaileysInfo("opened connection to WA"), false);
  assert.equal(shouldForwardBaileysInfo("connection update"), false);
  assert.equal(shouldForwardBaileysInfo(""), false);
  assert.equal(shouldForwardBaileysInfo(undefined), false);
  assert.equal(shouldForwardBaileysInfo(42), false);
});

// ── createBaileysLogAdapter: the observability + masking boundary ──────────

test("adapter: warn/error always forwarded, JID-masked, [baileys]-prefixed", () => {
  const rec = recordingLogger();
  const adapter = createBaileysLogAdapter(rec);
  adapter.error({ key: { remoteJid: "218913456789@s.whatsapp.net", id: "3EB0" }, ids: ["3EB0"], trace: "st" }, "error in sending message again");
  adapter.warn({ jid: "218913456789@s.whatsapp.net" }, "stream errored out");
  assert.equal(rec.lines.length, 2);
  assert.equal(rec.lines[0].level, "error");
  assert.equal(rec.lines[0].msg, "[baileys] error in sending message again");
  assert.equal(rec.lines[0].obj.key.remoteJid, "…6789@s.whatsapp.net");
  assert.equal(rec.lines[0].obj.key.id, "3EB0");
  assert.equal(rec.lines[1].obj.jid, "…6789@s.whatsapp.net");
});

test("adapter: info forwarded ONLY when retry-relevant (both pino call forms)", () => {
  const rec = recordingLogger();
  const adapter = createBaileysLogAdapter(rec);
  adapter.info({ attrs: { from: "218913456789@s.whatsapp.net" }, key: {} }, "recv retry for not fromMe message");
  adapter.info("opened connection to WA"); // dropped
  adapter.info({ x: 1 }, "unrelated"); // dropped
  assert.equal(rec.lines.length, 1);
  assert.equal(rec.lines[0].msg, "[baileys] recv retry for not fromMe message");
  assert.equal(rec.lines[0].obj.attrs.from, "…6789@s.whatsapp.net");
});

test("adapter: the budget-exhaustion line reaches the operator", () => {
  const rec = recordingLogger();
  const adapter = createBaileysLogAdapter(rec);
  adapter.info({ attrs: {}, key: { id: "3EB0" } }, "will not send message again, as sent too many times");
  assert.equal(rec.lines.length, 1);
  assert.equal(rec.lines[0].msg, "[baileys] will not send message again, as sent too many times");
});

test("adapter: trace/debug are dropped entirely (volume + raw-JID risk)", () => {
  const rec = recordingLogger();
  const adapter = createBaileysLogAdapter(rec);
  adapter.trace({ jid: "218913456789@s.whatsapp.net" }, "trace line");
  adapter.debug({ jid: "218913456789@s.whatsapp.net" }, "recv retry request");
  assert.equal(rec.lines.length, 0);
});

test("adapter: child() returns a working adapter and composes (masked) bindings", () => {
  const rec = recordingLogger();
  const adapter = createBaileysLogAdapter(rec);
  const child = adapter.child({ class: "baileys", host: "218913456789@s.whatsapp.net" });
  child.warn("child warn");
  child.child({ tag: "ws" }).error("grandchild error");
  assert.equal(rec.lines.length, 2);
  assert.equal(rec.lines[0].level, "warn");
  assert.equal(rec.lines[0].msg, "[baileys] child warn");
  assert.equal(rec.lines[0].obj.class, "baileys");
  assert.equal(rec.lines[0].obj.host, "…6789@s.whatsapp.net", "binding values are masked too");
  assert.equal(rec.lines[1].obj.tag, "ws");
  assert.equal(rec.lines[1].msg, "[baileys] grandchild error");
});

test("adapter: a message-like string form with retry relevance forwards with an empty object", () => {
  const rec = recordingLogger();
  const adapter = createBaileysLogAdapter(rec);
  adapter.info("error in sending message again");
  assert.equal(rec.lines.length, 1);
  assert.deepEqual(rec.lines[0].obj, {});
  assert.equal(rec.lines[0].msg, "[baileys] error in sending message again");
});
