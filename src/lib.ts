/**
 * Pure helpers extracted from the engine — deterministic, side-effect-free
 * (except timestamps, which are injectable where it matters), and unit
 * testable with zero dependencies (tests/lib.test.mjs imports dist/lib.js).
 *
 * دوال نقية مستخرجة من المحرك — يمكن اختبارها بدون Baileys/Express/Postgres.
 *
 * Shared by index.ts for: chat normalization, account/LID digit extraction,
 * self-send LID routing, and the outbound delivery log. Also hosts the
 * Express-4 async-rejection wrapper and the startSession single-flight
 * guard (r98/98-F6) — both type-only Express imports, zero runtime deps.
 */
import type { NextFunction, Request, Response } from "express";

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

// ── Express-4 async-rejection safety (r98/98-F6, P2-1) ─────────────────────

/**
 * Wrap an async Express route handler so a REJECTION is converted to
 * `next(err)` and reaches the terminal error middleware that index.ts
 * mounts after all routes. Express 4 does NOT route async rejections
 * itself (that landed in v5): without this wrapper an unexpected throw in
 * an async handler leaves the HTTP request hanging forever — the process
 * guard only LOGS unhandledRejection. Express 4 already catches SYNC
 * throws, so only async handlers need wrapping.
 * تغويل رفض الدوال غير المتزامنة إلى next(err) بدل تعليق الطلب للأبد.
 */
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => unknown,
): (req: Request, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// ── startSession single-flight guard (r98/98-F6, P2-2) ─────────────────────

/** Runtime fields that carry the memoized in-flight engine start. */
export interface SessionStartState {
  /** Memoized in-flight start promise — set until the engine start settles
   * (then cleared, so a FAILED start is retryable). */
  starting?: Promise<void>;
}

/**
 * TOCTOU guard for startSession: `rs.socket` is only assigned AFTER the
 * `useMultiFileAuthState` + `fetchLatestBaileysVersion` awaits, so a plain
 * "if (!rs.socket) start()" check lets two overlapping starts build TWO
 * Baileys sockets on one auth folder — WhatsApp answers that conflict with
 * DisconnectReason.loggedOut, whose close handler WIPES the credentials
 * (session loss). Memoizing the in-flight promise on the record makes every
 * concurrent caller (POST /start, dashboard start, reconnect timer, boot
 * self-heal) await the SAME engine start instead of starting a second one.
 * حارس سباق بدء الجلسة: كل المتصلين المتزامنين ينتظرون نفس الوعد.
 */
export function beginSessionStart(
  rs: SessionStartState,
  start: () => Promise<void>,
): Promise<void> {
  rs.starting ??= start().finally(() => {
    rs.starting = undefined;
  });
  return rs.starting;
}

// ── PII masking for stdout logs (r98/98-F6, P3-3) ──────────────────────────

/**
 * Redact phone digits for STDOUT logs (the log platform retains them —
 * Render historically, Docker/Coolify today): keep only the
 * LAST 4 digits behind an ellipsis — "218910089975" → "…9975". Full values
 * stay where they belong: the key-gated /api responses, the delivery-log
 * ring buffer, and the encrypted DB blob. Only the log surface is masked.
 * إخفاء أرقام الهواتف في السجلات — آخر 4 أرقام فقط.
 */
export function maskDigits(raw: string): string {
  const digits = chatDigits(raw);
  return digits.length === 0 ? "" : `…${digits.slice(-4)}`;
}

/**
 * JID-aware masking: masks the user part but KEEPS the domain suffix —
 * "218910089975@s.whatsapp.net" → "…9975@s.whatsapp.net",
 * "192616985542878@lid" → "…2878@lid" — so operators can still tell a
 * self-send LID route from a plain phone JID while the digits stay redacted.
 * قناع واعٍ بالصيغة: يخفي الأرقام ويُبقي نطاق العنوان.
 */
export function maskJid(jid: string): string {
  const s = String(jid ?? "");
  const at = s.indexOf("@");
  if (at <= 0) return maskDigits(s);
  return `${maskDigits(s.slice(0, at))}@${s.slice(at + 1)}`;
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

// ── TRUST_PROXY knob (R111, O1-M4) ──────────────────────────────────────────

/**
 * Forwarded-identity trust switch, shared by the /api rate limiter
 * (rate-limit.ts) and the dashboard login lockout (dashboard.ts).
 *
 *   TRUST_PROXY=0|false|off|no → X-Forwarded-For and CF-Connecting-IP are
 *       NEVER trusted: the socket remote address is the whole client
 *       identity. For DIRECT-publish deployments (no trusted reverse
 *       proxy in front — e.g. a raw published port): with XFF trust on, a
 *       forged single-entry X-Forwarded-For hands the attacker an
 *       attacker-chosen identity → unlimited rate-limit bucket splitting
 *       and lockout bypass.
 *   unset (or any other value) → the current deployment posture is kept:
 *       the RIGHTMOST XFF entry is trusted (the trusted edge proxy
 *       appends the true peer there — Render's edge historically,
 *       Coolify's proxy today; compose traffic is loopback-direct with
 *       no XFF at all). The default must stay trusting, otherwise every
 *       proxied client would collapse into the edge proxy's shared buckets.
 *
 * Read per-call (no import-time snapshot) so tests can flip it live.
 * مفتاح الوكيل الموثوق: تعطيل ترويسات التحويل عند النشر المباشر.
 */
export function trustForwardedHeaders(): boolean {
  const raw = (process.env.TRUST_PROXY ?? "").trim().toLowerCase();
  return !(raw === "0" || raw === "false" || raw === "off" || raw === "no");
}

// ── Restore-gate decision (R111, O2-F1) ─────────────────────────────────────

/**
 * Should the DB credentials blob be restored over the LOCAL auth folder at
 * session start? The old gate restored only when local creds.json did not
 * EXIST — interim pairing creds (registered !== true, written by an
 * interrupted pairing while the DB still held the good registered blob)
 * permanently shadowed the restore on persistent volumes: QR refs
 * exhausted → timedOut close → backoff → fresh QR → an infinite qr_ready
 * loop, and the operator's only dashboard fix (DELETE) destroyed the good
 * row too. The DB only ever stores post-ready snapshots ("no persist
 * before ready"), so it is preferred whenever the local state is absent
 * OR not fully registered.
 * بوابة الاسترجاع: يُفضَّل بلوب قاعدة البيانات على بيانات محلية غائبة أو
 * غير مسجلة (ناقصة الاقتران).
 */
export function shouldPreferDbBlobOverLocal(
  localHasCreds: boolean,
  localRegistered: boolean,
): boolean {
  return !localHasCreds || !localRegistered;
}

// ── Terminal error status (R111, O2-F6) ─────────────────────────────────────

/**
 * Status code for the terminal error middleware: body-parser rejections
 * (the 256kb JSON limit) carry statusCode 413, and http-errors-convention
 * errors carry `status` — the old blanket 500 misreported an oversized
 * CLIENT payload as a server fault. The first sane 4xx/5xx code found
 * wins (statusCode before status, the body-parser convention); anything
 * else (plain Error, junk/non-integer/out-of-range values) stays a
 * generic 500. كود حالة الخطأ الطرفي: يُحترم كود المحلل إن وُجد وإلا 500 عام.
 */
export function httpErrorStatus(err: unknown): number {
  const raw = err as { status?: unknown; statusCode?: unknown } | null | undefined;
  for (const candidate of [raw?.statusCode, raw?.status]) {
    if (
      typeof candidate === "number" &&
      Number.isInteger(candidate) &&
      candidate >= 400 &&
      candidate <= 599
    ) {
      return candidate;
    }
  }
  return 500;
}
