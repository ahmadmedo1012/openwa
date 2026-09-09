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

/** Ring-buffer cap for the per-session delivery log. حد سجل التسليم لكل جلسة. */
export const DELIVERY_LOG_CAP = 25;

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
 * not information). Timestamp injectable for tests.
 * دمج حالة تسليم جديدة — بدون تكرار نفس الحالة المتتالية.
 */
export function mergeDeliveryTimeline(
  existing: DeliveryTimelineEntry[],
  newStatus: string,
  at: string = new Date().toISOString(),
): DeliveryTimelineEntry[] {
  const last = existing[existing.length - 1];
  if (last && last.status === newStatus) return existing;
  return [...existing, { status: newStatus, at }];
}

/** One engine-sent message's delivery record. سجل تسليم رسالة أرسلها المحرك. */
export interface DeliveryLogEntry {
  messageId: string;
  chatId: string;
  sentAt: string;
  timeline: DeliveryTimelineEntry[];
  lastStatus?: string;
  lastStatusAt?: string;
}

/**
 * Append an entry to a delivery log with a ring-buffer cap (oldest evicted
 * past `cap`, default 25). Pure: returns a new array, never mutates input.
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
