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
export function chatDigits(raw) {
    return String(raw ?? "").replace(/[^0-9]/g, "");
}
/**
 * `218913456789@c.us` | `218913456789@s.whatsapp.net` | `+218913456789`
 * | bare digits → normalized `@s.whatsapp.net` JID, or null when the digit
 * count is outside E.164-ish bounds (8–15).
 */
export function normalizeChatId(raw) {
    const digits = chatDigits(raw);
    return digits.length >= 8 && digits.length <= 15 ? `${digits}@s.whatsapp.net` : null;
}
/**
 * `creds.me.id` → account phone digits.
 * "218910089975:9@s.whatsapp.net" → "218910089975" (device suffix ignored).
 * Accepts a bare digit string as a convenience; null when unparseable.
 * استخراج أرقام الحساب من معرف الحساب المرتبط.
 */
export function extractAccountDigits(meId) {
    const s = String(meId ?? "").trim();
    const m = /^(\d{8,15})(?::\d+)?@s\.whatsapp\.net$/.exec(s);
    if (m)
        return m[1];
    return /^\d{8,15}$/.test(s) ? s : null;
}
/**
 * `creds.me.lid` → LID digits.
 * "192616985542878:9@lid" → "192616985542878" (device suffix ignored).
 * LIDs are longer than phone numbers (up to ~18 digits); null when
 * unparseable. استخراج أرقام LID من معرف الحساب.
 */
export function extractLidDigits(meLid) {
    const s = String(meLid ?? "").trim();
    const m = /^(\d{8,18})(?::\d+)?@lid$/.exec(s);
    if (m)
        return m[1];
    return /^\d{8,18}$/.test(s) ? s : null;
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
export function resolveSendJid(targetDigits, accountDigits, accountLidDigits, selfSendLidEnabled) {
    const digits = chatDigits(targetDigits);
    const pnJid = `${digits}@s.whatsapp.net`;
    const selfSend = Boolean(accountDigits) && digits === accountDigits;
    if (selfSend && selfSendLidEnabled && accountLidDigits) {
        return { jid: `${accountLidDigits}@lid`, pnJid, selfSend: true, viaLid: true };
    }
    return { jid: pnJid, pnJid, selfSend, viaLid: false };
}
/**
 * Append a delivery status to a timeline — unless it repeats the previous
 * status (WhatsApp re-acks the same state; consecutive duplicates add noise,
 * not information). Timestamp injectable for tests.
 * دمج حالة تسليم جديدة — بدون تكرار نفس الحالة المتتالية.
 */
export function mergeDeliveryTimeline(existing, newStatus, at = new Date().toISOString()) {
    const last = existing[existing.length - 1];
    if (last && last.status === newStatus)
        return existing;
    return [...existing, { status: newStatus, at }];
}
/**
 * Append an entry to a delivery log with a ring-buffer cap (oldest evicted
 * past `cap`, default 25). Pure: returns a new array, never mutates input.
 * إضافة مدخل إلى سجل التسليم بحلقة محدودة — الأقدم يُحذف عند التجاوز.
 */
export function pushDeliveryLog(log, entry, cap = DELIVERY_LOG_CAP) {
    const next = [...log, entry];
    const overflow = next.length - Math.max(1, cap);
    return overflow > 0 ? next.slice(overflow) : next;
}
