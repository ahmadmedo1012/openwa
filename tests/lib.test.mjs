/**
 * Unit tests for the pure helpers in src/lib.ts (compiled → dist/lib.js).
 * Zero-dependency: node:test + node:assert/strict — matches the repo's
 * no-new-devDependencies constraint.
 *
 * اختبارات الدوال النقية — بدون أي تبعيات جديدة.
 *
 * Run: node --test tests/lib.test.mjs   (after `npm run build`)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeChatId,
  extractAccountDigits,
  extractLidDigits,
  resolveSendJid,
  mergeDeliveryTimeline,
  pushDeliveryLog,
  chatDigits,
  DELIVERY_LOG_CAP,
} from "../dist/lib.js";

// ── normalizeChatId ──────────────────────────────────────────────────────────

test("normalizeChatId: accepts @c.us, @s.whatsapp.net, + prefix and bare digits", () => {
  assert.equal(normalizeChatId("218913456789@c.us"), "218913456789@s.whatsapp.net");
  assert.equal(normalizeChatId("218913456789@s.whatsapp.net"), "218913456789@s.whatsapp.net");
  assert.equal(normalizeChatId("+218 913 456 789"), "218913456789@s.whatsapp.net");
  assert.equal(normalizeChatId("218913456789"), "218913456789@s.whatsapp.net");
});

test("normalizeChatId: rejects too-short, too-long and digit-less inputs", () => {
  assert.equal(normalizeChatId("1234567"), null); // 7 digits < 8
  assert.equal(normalizeChatId("1234567890123456"), null); // 16 digits > 15
  assert.equal(normalizeChatId("abc-def-ghi"), null);
  assert.equal(normalizeChatId(""), null);
});

test("chatDigits: strips every non-digit character", () => {
  assert.equal(chatDigits("+218 (91) 008-9975 @c.us"), "218910089975");
  assert.equal(chatDigits(""), "");
});

// ── extractAccountDigits ─────────────────────────────────────────────────────

test("extractAccountDigits: full jid with device suffix", () => {
  assert.equal(extractAccountDigits("218910089975:9@s.whatsapp.net"), "218910089975");
});

test("extractAccountDigits: jid without device suffix and bare digits", () => {
  assert.equal(extractAccountDigits("218910089975@s.whatsapp.net"), "218910089975");
  assert.equal(extractAccountDigits("218910089975"), "218910089975");
});

test("extractAccountDigits: rejects LID jids, garbage and short numbers", () => {
  assert.equal(extractAccountDigits("192616985542878:9@lid"), null);
  assert.equal(extractAccountDigits("not-a-jid"), null);
  assert.equal(extractAccountDigits("1234567"), null);
  assert.equal(extractAccountDigits(""), null);
});

// ── extractLidDigits ─────────────────────────────────────────────────────────

test("extractLidDigits: lid jid with device suffix (the real-world shape)", () => {
  assert.equal(extractLidDigits("192616985542878:9@lid"), "192616985542878");
});

test("extractLidDigits: bare digits accepted, PN jids rejected", () => {
  assert.equal(extractLidDigits("192616985542878"), "192616985542878");
  assert.equal(extractLidDigits("218910089975:9@s.whatsapp.net"), null);
  assert.equal(extractLidDigits(""), null);
});

// ── resolveSendJid ───────────────────────────────────────────────────────────

test("resolveSendJid: self-send with LID digits routes via @lid", () => {
  const r = resolveSendJid("218910089975", "218910089975", "192616985542878", true);
  assert.equal(r.jid, "192616985542878@lid");
  assert.equal(r.pnJid, "218910089975@s.whatsapp.net");
  assert.equal(r.selfSend, true);
  assert.equal(r.viaLid, true);
});

test("resolveSendJid: self-send with LID disabled falls back to the PN jid", () => {
  const r = resolveSendJid("218910089975", "218910089975", "192616985542878", false);
  assert.equal(r.jid, "218910089975@s.whatsapp.net");
  assert.equal(r.selfSend, true);
  assert.equal(r.viaLid, false);
});

test("resolveSendJid: self-send without known LID digits uses the PN jid", () => {
  const r = resolveSendJid("218910089975", "218910089975", null, true);
  assert.equal(r.jid, "218910089975@s.whatsapp.net");
  assert.equal(r.selfSend, true);
  assert.equal(r.viaLid, false);
});

test("resolveSendJid: another recipient is never flagged self-send", () => {
  const r = resolveSendJid("218913456789", "218910089975", "192616985542878", true);
  assert.equal(r.jid, "218913456789@s.whatsapp.net");
  assert.equal(r.pnJid, "218913456789@s.whatsapp.net");
  assert.equal(r.selfSend, false);
  assert.equal(r.viaLid, false);
});

test("resolveSendJid: no linked account identity on file → plain PN route", () => {
  const r = resolveSendJid("218910089975", undefined, undefined, true);
  assert.equal(r.jid, "218910089975@s.whatsapp.net");
  assert.equal(r.selfSend, false);
  assert.equal(r.viaLid, false);
});

// ── mergeDeliveryTimeline ────────────────────────────────────────────────────

test("mergeDeliveryTimeline: appends a new status with its timestamp", () => {
  const out = mergeDeliveryTimeline([], "2", "2026-09-07T01:00:00.000Z");
  assert.deepEqual(out, [{ status: "2", at: "2026-09-07T01:00:00.000Z" }]);
});

test("mergeDeliveryTimeline: consecutive duplicate statuses are collapsed", () => {
  const t0 = [{ status: "2", at: "2026-09-07T01:00:00.000Z" }];
  const out = mergeDeliveryTimeline(t0, "2", "2026-09-07T01:00:01.000Z");
  assert.equal(out.length, 1);
  assert.equal(out, t0); // same reference — nothing appended
});

test("mergeDeliveryTimeline: non-consecutive repeats ARE kept (2 → 3 → 2)", () => {
  let t = mergeDeliveryTimeline([], "2", "a");
  t = mergeDeliveryTimeline(t, "3", "b");
  t = mergeDeliveryTimeline(t, "2", "c");
  assert.deepEqual(t.map((e) => e.status), ["2", "3", "2"]);
});

test("mergeDeliveryTimeline: never mutates the input array", () => {
  const t0 = [{ status: "1", at: "a" }];
  mergeDeliveryTimeline(t0, "2", "b");
  assert.equal(t0.length, 1);
});

// ── pushDeliveryLog ──────────────────────────────────────────────────────────

const entry = (i) => ({
  messageId: `msg-${i}`,
  chatId: "218910089975@s.whatsapp.net",
  sentAt: `2026-09-07T01:00:${String(i).padStart(2, "0")}.000Z`,
  timeline: [],
});

test("pushDeliveryLog: appends and preserves order", () => {
  const out = pushDeliveryLog([entry(1)], entry(2));
  assert.deepEqual(out.map((e) => e.messageId), ["msg-1", "msg-2"]);
});

test("pushDeliveryLog: evicts the OLDEST entries past the cap (ring buffer)", () => {
  let log = [];
  for (let i = 1; i <= 30; i++) log = pushDeliveryLog(log, entry(i));
  assert.equal(log.length, DELIVERY_LOG_CAP);
  assert.equal(log[0].messageId, "msg-6"); // 1..5 evicted
  assert.equal(log[log.length - 1].messageId, "msg-30");
});

test("pushDeliveryLog: honors a custom cap", () => {
  let log = [];
  for (let i = 1; i <= 10; i++) log = pushDeliveryLog(log, entry(i), 3);
  assert.deepEqual(log.map((e) => e.messageId), ["msg-8", "msg-9", "msg-10"]);
});

test("pushDeliveryLog: never mutates the input array (pure)", () => {
  const orig = [entry(1)];
  pushDeliveryLog(orig, entry(2));
  assert.equal(orig.length, 1);
});
