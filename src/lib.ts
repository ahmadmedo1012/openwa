/**
 * Pure helpers extracted from the engine — deterministic, side-effect-free
 * (except timestamps, which are injectable where it matters), and unit
 * testable with zero dependencies (tests/lib.test.mjs imports dist/lib.js).
 *
 * دوال نقية مستخرجة من المحرك — يمكن اختبارها بدون Baileys/Express/Postgres.
 *
 * Shared by index.ts for: chat normalization, account/LID digit extraction,
 * self-send LID routing, and the outbound delivery log.
 */

/**
 * Ring-buffer cap for the per-session delivery log — the LATEST 500
 * engine-sent messages are kept (oldest dropped past the cap). WA-04:
 * enough history for diagnostics, still strictly bounded per session.
 * حد سجل التسليم لكل جلسة — آخر 500 رسالة فقط.
 */
export const DELIVERY_LOG_CAP = 500;

/**
 * Cap for each message's delivery timeline — only the LAST 10 status
 * transitions are kept (older transitions dropped). WA-04.
 * حد خط التسليم لكل رسالة — آخر 10 انتقالات فقط.
 */
export const DELIVERY_TIMELINE_CAP = 10;

// ── Delivery-status semantics (WA-04) ──────────────────────────────────────

/**
 * WhatsApp protocol delivery statuses — WebMessageInfo.Status enum,
 * ground-truthed from the Baileys proto bundled in node_modules
 * (@whiskeysockets/baileys/WAProto/WAProto.proto, `enum Status`):
 *
 *   0 = ERROR         — delivery failed / the message errored out
 *   1 = PENDING       — handed to the engine, not yet acked by the server
 *   2 = SERVER_ACK    — accepted by WhatsApp's server (NOT yet on the phone)
 *   3 = DELIVERY_ACK  — delivered to the recipient's device
 *   4 = READ          — opened/read by the recipient
 *   5 = PLAYED        — media/voice message played by the recipient
 *
 * Real delivery progress is monotonic along that rank. WhatsApp
 * nevertheless re-acks statuses that REGRESS (a live 3→2 burst was
 * observed at the exact second a pairing was revoked — a protocol
 * artifact, not a real un-delivery). Regressions are RECORDED in the
 * timeline for audit but never lower the authoritative status.
 *
 * دلالات حالات التسليم من البروتوكول نفسه — والانحدار أثر بروتوكولي
 * يُسجَّل لكنه لا يخفض الحالة الموثوقة.
 */
export function deliveryStatusRank(status: string): number {
  // NOTE: Number("") === 0 in JS — an empty/blank status is NOT rank 0.
  if (typeof status !== "string" || status.trim().length === 0) return -1;
  const n = Number(status);
  return Number.isInteger(n) && n >= 0 ? n : -1;
}

/**
 * Monotonic status advance: returns whichever of `current`/`next` sits
 * higher on the protocol ladder; an unrankable (unknown/non-numeric)
 * `next` never displaces a ranked current. `undefined` current adopts
 * `next`. الحالة الموثوقة = الأعلى رتبةً — لا الحدث الأخير.
 */
export function advanceDeliveryStatus(
  current: string | undefined,
  next: string,
): string {
  if (current === undefined) return next;
  return deliveryStatusRank(next) > deliveryStatusRank(current) ? next : current;
}

/** Strip everything that is not a digit. إزالة كل ما ليس رقمًا. */
export function chatDigits(raw: string): string {
  return String(raw ?? "").replace(/[^0-9]/g, "");
}

/**
 * `218913456789@c.us` | `218913456789@s.whatsapp.net` | `+218913456789`
 * | bare digits → normalized `@s.whatsapp.net` JID, or null when the digit
 * count is outside E.164-ish bounds (8–15).
 */
export function normalizeChatId(raw: string): string | null {
  const digits = chatDigits(raw);
  return digits.length >= 8 && digits.length <= 15 ? `${digits}@s.whatsapp.net` : null;
}

/**
 * `creds.me.id` → account phone digits.
 * "218910089975:9@s.whatsapp.net" → "218910089975" (device suffix ignored).
 * Accepts a bare digit string as a convenience; null when unparseable.
 * استخراج أرقام الحساب من معرف الحساب المرتبط.
 */
export function extractAccountDigits(meId: string): string | null {
  const s = String(meId ?? "").trim();
  const m = /^(\d{8,15})(?::\d+)?@s\.whatsapp\.net$/.exec(s);
  if (m) return m[1];
  return /^\d{8,15}$/.test(s) ? s : null;
}

/**
 * `creds.me.lid` → LID digits.
 * "192616985542878:9@lid" → "192616985542878" (device suffix ignored).
 * LIDs are longer than phone numbers (up to ~18 digits); null when
 * unparseable. استخراج أرقام LID من معرف الحساب.
 */
export function extractLidDigits(meLid: string): string | null {
  const s = String(meLid ?? "").trim();
  const m = /^(\d{8,18})(?::\d+)?@lid$/.exec(s);
  if (m) return m[1];
  return /^\d{8,18}$/.test(s) ? s : null;
}

/** Resolved outbound route for a send. مسار الإرسال المحسوب. */
export interface SendRoute {
  /** JID the engine should send to (LID form for modern self-chats). */
  jid: string;
  /** Plain phone-number JID — the fallback target when viaLid. */
  pnJid: string;
  /** Is the target the account's own number (self-chat)? */
  selfSend: boolean;
  /** Did we rewrite to the `${lid}@lid` self-chat route? */
  viaLid: boolean;
}

/**
 * Self-send detection + LID routing.
 *
 * WhatsApp's modern self-chat ("Message yourself") is addressed by the
 * account's LID, not its phone JID — sending OTP to the account's own PN
 * JID lands in a legacy path that breaks on any signal-state drift.
 * When the target digits equal the linked account's digits, LID digits are
 * known, and self-send-LID is enabled, route to `${lid}@lid`; otherwise the
 * plain PN JID.
 *
 * كشف الإرسال الذاتي: توجيه المحادثة الذاتية الحديثة عبر LID بدل رقم الهاتف.
 */
export function resolveSendJid(
  targetDigits: string,
  accountDigits: string | null | undefined,
  accountLidDigits: string | null | undefined,
  selfSendLidEnabled: boolean,
): SendRoute {
  const digits = chatDigits(targetDigits);
  const pnJid = `${digits}@s.whatsapp.net`;
  const selfSend = Boolean(accountDigits) && digits === accountDigits;
  if (selfSend && selfSendLidEnabled && accountLidDigits) {
    return { jid: `${accountLidDigits}@lid`, pnJid, selfSend: true, viaLid: true };
  }
  return { jid: pnJid, pnJid, selfSend, viaLid: false };
}

/** One step in a message's delivery timeline. خطوة في خط تسليم الرسالة. */
export interface DeliveryTimelineEntry {
  status: string;
  at: string;
}

/**
 * Append a delivery status to a timeline — unless it repeats the previous
 * status (WhatsApp re-acks the same state; consecutive duplicates add noise,
 * not information) — keeping only the last DELIVERY_TIMELINE_CAP transitions
 * (oldest dropped). Regressions ARE appended: the timeline is the audit
 * record; monotonicity is enforced on the authoritative status instead
 * (advanceDeliveryStatus). Timestamp injectable for tests.
 * دمج حالة تسليم جديدة — بدون تكرار متتالٍ — بحد آخر 10 انتقالات.
 */
export function mergeDeliveryTimeline(
  existing: DeliveryTimelineEntry[],
  newStatus: string,
  at: string = new Date().toISOString(),
): DeliveryTimelineEntry[] {
  const last = existing[existing.length - 1];
  if (last && last.status === newStatus) return existing;
  const appended = [...existing, { status: newStatus, at }];
  const overflow = appended.length - Math.max(1, DELIVERY_TIMELINE_CAP);
  return overflow > 0 ? appended.slice(overflow) : appended;
}

/** One engine-sent message's delivery record. سجل تسليم رسالة أرسلها المحرك. */
export interface DeliveryLogEntry {
  messageId: string;
  chatId: string;
  sentAt: string;
  timeline: DeliveryTimelineEntry[];
  /** Authoritative status = the MAX rank ever observed for this message
   * (WA-04: protocol regressions never lower it). */
  lastStatus?: string;
  lastStatusAt?: string;
  /** Memo of the max-rank status — survives timeline capping at 10. */
  maxStatus?: string;
}

/**
 * Append an entry to a delivery log with a ring-buffer cap (oldest evicted
 * past `cap`, default 500). Pure: returns a new array, never mutates input.
 * إضافة مدخل إلى سجل التسليم بحلقة محدودة — الأقدم يُحذف عند التجاوز.
 */
export function pushDeliveryLog<T extends DeliveryLogEntry>(
  log: T[],
  entry: T,
  cap: number = DELIVERY_LOG_CAP,
): T[] {
  const next = [...log, entry];
  const overflow = next.length - Math.max(1, cap);
  return overflow > 0 ? next.slice(overflow) : next;
}

// ── Session identity + connection-close handling (WA-02) ───────────────────

/**
 * The session state fields that belong to a PAIRING, not to the session
 * row. When WhatsApp revokes a pairing (loggedOut) these must die with
 * the credentials — otherwise the re-paired session presents the OLD
 * pairing's identity (stale accountDigits/lastReadyAt on the admin view)
 * and, worse, the "only persist after proven ready" gate reopens because
 * a stale lastReadyAt passes it, persisting half-bound creds during
 * qr_ready (the exact regression that gate was built to prevent).
 * حقول الهوية التي تموت مع إبطال الاقتران.
 */
export interface SessionIdentityState {
  lastReadyAt?: string;
  connectedAt?: string;
  accountDigits?: string;
  accountName?: string;
  accountLidDigits?: string;
  lastDeliveryStatus?: string;
  deliveryLog?: DeliveryLogEntry[];
}

/**
 * Wipe every pairing-scoped identity field (WA-02). In-place reset of the
 * given state object; deliveryLog is emptied (old pairing's acks are not
 * evidence for the new one). تصفير هوية الاقتران الميت.
 */
export function resetSessionIdentity(rs: SessionIdentityState): void {
  rs.lastReadyAt = undefined;
  rs.connectedAt = undefined;
  rs.accountDigits = undefined;
  rs.accountName = undefined;
  rs.accountLidDigits = undefined;
  rs.lastDeliveryStatus = undefined;
  rs.deliveryLog = [];
}

/** Runtime fields the connection-close reducer touches. */
export interface SessionCloseState extends SessionIdentityState {
  status: string;
  socket?: unknown;
}

/** Side effects injected by index.ts (engine-owned, untestable here). */
export interface SessionCloseEffects {
  /** Wipe dead credentials: cancel pending debounced saves, remove the
   * local auth dir, delete the persisted blob (WA-02 — order matters:
   * the wipe must land AFTER any save it must supersede). */
  wipeCredentials(): void;
  /** Best-effort local wipe so the next start() produces a fresh QR. */
  markRestartable(): void;
  /** Immediate snapshot flush (disconnect path only — never loggedOut). */
  flushSnapshot(): void;
  /** Arm the auto-reconnect timer. */
  scheduleReconnect(): void;
}

/**
 * Reducer for the connection.update "close" event — extracted verbatim
 * from the old inline handler so the WA-02 semantics are unit-testable:
 *
 *   loggedOut | stopRequested → status "failed", identity reset,
 *       credentials wiped, NO persistence (creds are being wiped; a
 *       flushNow here would race the wipe and could resurrect the dead
 *       blob — the flush guard is rs.lastReadyAt, which the reset just
 *       cleared), no reconnect.
 *   otherwise → "disconnected": flush the LATEST signal state NOW (not
 *       debounced-then-dead — if the process dies inside the reconnect
 *       window the next boot must restore the latest state), then arm
 *       the reconnect. Identity is PRESERVED (same pairing resumes).
 *
 * معالج حدث الإغلاق المستخرج — دلالات WA-02 قابلة للاختبار الآن.
 */
export function applyConnectionClose(
  rs: SessionCloseState,
  close: { loggedOut: boolean; stopRequested: boolean },
  fx: SessionCloseEffects,
): "failed" | "disconnected" {
  if (close.loggedOut || close.stopRequested) {
    // Pairing revoked (device logged out elsewhere) or session stopped —
    // credentials are dead. Reset the identity that belonged to them.
    rs.status = "failed";
    rs.socket = undefined;
    resetSessionIdentity(rs);
    fx.wipeCredentials();
    fx.markRestartable();
    return "failed";
  }

  rs.status = "disconnected";
  rs.socket = undefined;
  // Snapshot NOW, not debounced-then-dead — and only once the session
  // has proven itself connected (the WA-02 "no persist before ready"
  // gate: a session that never went ready must not persist interim creds).
  if (rs.lastReadyAt) fx.flushSnapshot();
  fx.scheduleReconnect();
  return "disconnected";
}
