/**
 * Unit tests for WA-02 — the loggedOut identity reset.
 *
 * applyConnectionClose is the extracted reducer for the Baileys
 * connection.update "close" event: simulating the event with the
 * loggedOut disconnect code must wipe every pairing-scoped identity
 * field, wipe credentials, and NEVER touch the persistence flush
 * (creds are being wiped — a flush would resurrect them).
 *
 * محاكاة حدث الإغلاق برمز loggedOut: تصفير الهوية بلا أي حفظ.
 *
 * Run: node --test tests/logged-out-reset.test.mjs   (after `npm run build`)
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  applyConnectionClose,
  resetSessionIdentity,
  advanceDeliveryStatus,
  mergeDeliveryTimeline,
  pushDeliveryLog,
} from "../dist/lib.js";

/** A session that had a LIVE, ready pairing with delivery history. */
function pairedSession() {
  const timeline = mergeDeliveryTimeline([], "2", "2026-09-09T22:02:02.000Z");
  const log = pushDeliveryLog(
    [],
    {
      messageId: "msg-otp-1",
      chatId: "218910089975@s.whatsapp.net",
      sentAt: "2026-09-09T22:02:00.000Z",
      timeline,
      lastStatus: "3",
      maxStatus: "3",
      lastStatusAt: "2026-09-09T22:02:04.000Z",
    },
  );
  return {
    id: "sess_cjAv55GlDZIA7Exl",
    name: "subnation-otp",
    status: "ready",
    socket: { fake: "wsocket" },
    lastReadyAt: "2026-09-10T17:24:40.000Z",
    connectedAt: "2026-09-10T17:24:40.000Z",
    accountDigits: "218910089975",
    accountName: "Ahmed Radwan",
    accountLidDigits: "192616985542878",
    lastDeliveryStatus: "3",
    deliveryLog: log,
    stopRequested: false,
  };
}

/** Effects recorder — spies on every side effect of the reducer. */
function spyEffects() {
  const calls = { wipeCredentials: 0, markRestartable: 0, flushSnapshot: 0, scheduleReconnect: 0 };
  return {
    calls,
    effects: {
      wipeCredentials: () => {
        calls.wipeCredentials++;
      },
      markRestartable: () => {
        calls.markRestartable++;
      },
      flushSnapshot: () => {
        calls.flushSnapshot++;
      },
      scheduleReconnect: () => {
        calls.scheduleReconnect++;
      },
    },
  };
}

test("loggedOut: every pairing-scoped identity field is reset (WA-02)", () => {
  const rs = pairedSession();
  const { calls, effects } = spyEffects();
  const outcome = applyConnectionClose(rs, { loggedOut: true, stopRequested: false }, effects);
  assert.equal(outcome, "failed");
  assert.equal(rs.status, "failed");
  assert.equal(rs.socket, undefined);
  // The OLD pairing's identity must die with its credentials:
  assert.equal(rs.lastReadyAt, undefined);
  assert.equal(rs.connectedAt, undefined);
  assert.equal(rs.accountDigits, undefined);
  assert.equal(rs.accountName, undefined);
  assert.equal(rs.accountLidDigits, undefined);
  assert.equal(rs.lastDeliveryStatus, undefined);
  assert.deepEqual(rs.deliveryLog, []);
});

test("loggedOut: NO persistence flush — credentials are being wiped (WA-02)", () => {
  const rs = pairedSession();
  const { calls, effects } = spyEffects();
  applyConnectionClose(rs, { loggedOut: true, stopRequested: false }, effects);
  assert.equal(calls.flushSnapshot, 0);
  assert.equal(calls.wipeCredentials, 1);
  assert.equal(calls.markRestartable, 1);
  assert.equal(calls.scheduleReconnect, 0); // dead pairing — no auto-reconnect
});

test("loggedOut: the flush gate is dead even if effects are re-invoked later (reset clears lastReadyAt)", () => {
  const rs = pairedSession();
  const { effects } = spyEffects();
  applyConnectionClose(rs, { loggedOut: true, stopRequested: false }, effects);
  // The disconnect-path guard relies on rs.lastReadyAt — after the reset
  // the "only persist after proven ready" gate stays CLOSED.
  assert.ok(!rs.lastReadyAt);
});

test("stopRequested close: same dead-credentials path (delete flow)", () => {
  const rs = pairedSession();
  const { calls, effects } = spyEffects();
  const outcome = applyConnectionClose(rs, { loggedOut: false, stopRequested: true }, effects);
  assert.equal(outcome, "failed");
  assert.equal(rs.status, "failed");
  assert.equal(rs.accountDigits, undefined);
  assert.equal(rs.lastReadyAt, undefined);
  assert.equal(calls.wipeCredentials, 1);
  assert.equal(calls.flushSnapshot, 0);
});

test("normal disconnect: identity PRESERVED, snapshot flushed, reconnect armed", () => {
  const rs = pairedSession();
  const { calls, effects } = spyEffects();
  const outcome = applyConnectionClose(rs, { loggedOut: false, stopRequested: false }, effects);
  assert.equal(outcome, "disconnected");
  assert.equal(rs.status, "disconnected");
  // Same pairing resumes — identity intact:
  assert.equal(rs.lastReadyAt, "2026-09-10T17:24:40.000Z");
  assert.equal(rs.connectedAt, "2026-09-10T17:24:40.000Z");
  assert.equal(rs.accountDigits, "218910089975");
  assert.equal(rs.accountName, "Ahmed Radwan");
  assert.equal(rs.accountLidDigits, "192616985542878");
  assert.equal(rs.lastDeliveryStatus, "3");
  assert.equal(rs.deliveryLog.length, 1);
  assert.equal(calls.flushSnapshot, 1);
  assert.equal(calls.scheduleReconnect, 1);
  assert.equal(calls.wipeCredentials, 0);
  assert.equal(calls.markRestartable, 0);
});

test("normal disconnect of a NEVER-ready session: no flush (persist gate stays closed)", () => {
  const rs = pairedSession();
  delete rs.lastReadyAt; // never proven ready (e.g. qr_ready flapping)
  const { calls, effects } = spyEffects();
  const outcome = applyConnectionClose(rs, { loggedOut: false, stopRequested: false }, effects);
  assert.equal(outcome, "disconnected");
  assert.equal(calls.flushSnapshot, 0); // interim creds must not reach the DB
  assert.equal(calls.scheduleReconnect, 1);
});

test("resetSessionIdentity: standalone full wipe of a paired state", () => {
  const rs = pairedSession();
  resetSessionIdentity(rs);
  assert.equal(rs.lastReadyAt, undefined);
  assert.equal(rs.connectedAt, undefined);
  assert.equal(rs.accountDigits, undefined);
  assert.equal(rs.accountName, undefined);
  assert.equal(rs.accountLidDigits, undefined);
  assert.equal(rs.lastDeliveryStatus, undefined);
  assert.deepEqual(rs.deliveryLog, []);
});

test("re-pair flow: after loggedOut the epoch token is empty, then a fresh open sets a new one", () => {
  // The SubNation backend (97-F3) derives its pairing-epoch token from
  // lastReadyAt ?? connectedAt — after the reset it must read "" so the
  // next ready observation is recognized as a NEW pairing.
  const rs = pairedSession();
  const { effects } = spyEffects();
  applyConnectionClose(rs, { loggedOut: true, stopRequested: false }, effects);
  assert.equal(rs.lastReadyAt ?? rs.connectedAt ?? "", "");
  // ...operator re-pairs; connection goes open again:
  rs.status = "ready";
  rs.lastReadyAt = "2026-09-11T09:00:00.000Z";
  rs.connectedAt = rs.lastReadyAt;
  rs.accountDigits = "218914460503"; // the NEW account
  assert.equal(rs.lastReadyAt ?? rs.connectedAt ?? "", "2026-09-11T09:00:00.000Z");
});

test("delivery regression across a re-pair: old acks are gone, new max is clean", () => {
  const rs = pairedSession();
  const { effects } = spyEffects();
  applyConnectionClose(rs, { loggedOut: true, stopRequested: false }, effects);
  // New pairing sends an OTP; a 3→2 re-ack burst arrives (the live WA-04
  // incident): the timeline records it but the status stays at the max.
  rs.deliveryLog = pushDeliveryLog(rs.deliveryLog, {
    messageId: "msg-otp-2",
    chatId: "218914460503@s.whatsapp.net",
    sentAt: "2026-09-11T09:01:00.000Z",
    timeline: [],
  });
  const entry = rs.deliveryLog[0];
  const timeline = mergeDeliveryTimeline(entry.timeline, "3", "2026-09-11T09:01:04.000Z");
  const timeline2 = mergeDeliveryTimeline(timeline, "2", "2026-09-11T09:05:00.000Z");
  assert.deepEqual(timeline2.map((e) => e.status), ["3", "2"]); // recorded…
  assert.equal(advanceDeliveryStatus("3", "2"), "3"); // …but max kept
});
