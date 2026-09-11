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
  deliveryStatusRank,
  advanceDeliveryStatus,
  DELIVERY_LOG_CAP,
  DELIVERY_TIMELINE_CAP,
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

// ── delivery status semantics (WA-04) ────────────────────────────────────────

test("deliveryStatusRank: WAProto WebMessageInfo.Status ranks 0–5", () => {
  // ERROR=0, PENDING=1, SERVER_ACK=2, DELIVERY_ACK=3, READ=4, PLAYED=5
  assert.equal(deliveryStatusRank("0"), 0);
  assert.equal(deliveryStatusRank("1"), 1);
  assert.equal(deliveryStatusRank("2"), 2);
  assert.equal(deliveryStatusRank("3"), 3);
  assert.equal(deliveryStatusRank("4"), 4);
  assert.equal(deliveryStatusRank("5"), 5);
});

test("deliveryStatusRank: non-numeric / negative / fractional → -1", () => {
  assert.equal(deliveryStatusRank("abc"), -1);
  assert.equal(deliveryStatusRank(""), -1);
  assert.equal(deliveryStatusRank("-1"), -1);
  assert.equal(deliveryStatusRank("2.5"), -1);
});

test("advanceDeliveryStatus: undefined current adopts the next status", () => {
  assert.equal(advanceDeliveryStatus(undefined, "2"), "2");
});

test("advanceDeliveryStatus: forward progression is adopted", () => {
  assert.equal(advanceDeliveryStatus("2", "3"), "3");
  assert.equal(advanceDeliveryStatus("3", "4"), "4");
});

test("advanceDeliveryStatus: a REGRESSION never lowers the max (the live 3→2 WA-04 incident)", () => {
  assert.equal(advanceDeliveryStatus("3", "2"), "3");
  assert.equal(advanceDeliveryStatus("4", "2"), "4");
  assert.equal(advanceDeliveryStatus("3", "0"), "3");
});

test("advanceDeliveryStatus: unrankable next never displaces a ranked current", () => {
  assert.equal(advanceDeliveryStatus("2", "weird"), "2");
  // first observation of something unrankable still lands when current is absent
  assert.equal(advanceDeliveryStatus(undefined, "weird"), "weird");
  assert.equal(advanceDeliveryStatus("weird", "3"), "3"); // ranked beats unrankable
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

test("mergeDeliveryTimeline (WA-04): caps the timeline at the LAST 10 transitions", () => {
  assert.equal(DELIVERY_TIMELINE_CAP, 10);
  let t = [];
  // alternating statuses dodge the consecutive-duplicate collapse
  for (let i = 1; i <= 12; i++) t = mergeDeliveryTimeline(t, i % 2 === 0 ? "2" : "3", `t${i}`);
  assert.equal(t.length, DELIVERY_TIMELINE_CAP);
  // the first two transitions (t1, t2) were dropped — oldest evicted
  assert.deepEqual(t.map((e) => e.at), ["t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12"]);
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

test("pushDeliveryLog: evicts the OLDEST entries past the cap (ring buffer, WA-04: cap 500)", () => {
  assert.equal(DELIVERY_LOG_CAP, 500);
  let log = [];
  for (let i = 1; i <= DELIVERY_LOG_CAP + 5; i++) log = pushDeliveryLog(log, entry(i));
  assert.equal(log.length, DELIVERY_LOG_CAP);
  assert.equal(log[0].messageId, "msg-6"); // 1..5 evicted
  assert.equal(log[log.length - 1].messageId, `msg-${DELIVERY_LOG_CAP + 5}`);
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
