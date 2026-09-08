/**
 * OpenWA operator dashboard — cookie-authenticated web UI for managing
 * WhatsApp sessions (list / create / start / pair via QR or phone code /
 * delete) without ever exposing OPENWA_API_KEY to the browser.
 *
 * Design contract:
 *   - The REST surface under /api stays EXACTLY as-is (X-API-Key). The
 *     SubNation backend keeps consuming it untouched.
 *   - The dashboard lives at "/" and is guarded by a username+password
 *     login. Session cookies are HMAC-SHA256 signed (tamper-proof),
 *     httpOnly, SameSite=Lax, Secure in production, 12h expiry.
 *   - Login is rate-limited per IP with an escalating lockout
 *     (5 failures in 15 minutes → 15-minute lock). Timing-safe compare.
 *   - The dashboard talks to the SAME in-process session registry —
 *     no HTTP self-calls, no key in any client payload.
 *
 * Env:
 *   DASHBOARD_USERNAME   login username (default: none → dashboard
 *                         DISABLED and "/" returns 404-style notice)
 *   DASHBOARD_PASSWORD   login password (min 8 chars when set)
 *   DASHBOARD_SESSION_SECRET  cookie-signing secret; falls back to a
 *                         scrypt derivation of OPENWA_API_KEY so the
 *                         default deployment is secure out of the box.
 */
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
const DASHBOARD_USERNAME = (process.env.DASHBOARD_USERNAME ?? "").trim().toLowerCase();
const DASHBOARD_PASSWORD = (process.env.DASHBOARD_PASSWORD ?? "").trim();
const COOKIE_NAME = "openwa_dash";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
function sessionSecret() {
    const explicit = (process.env.DASHBOARD_SESSION_SECRET ?? "").trim();
    if (explicit.length >= 32)
        return explicit;
    // Derive a purpose-scoped key from the API key (which is already a
    // required secret). scrypt with a static salt keeps the derivation
    // slow and the cookie domain independent from the API-key domain.
    return scryptSync(process.env.OPENWA_API_KEY ?? "", "openwa-dashboard-v1", 32).toString("hex");
}
export function dashboardEnabled() {
    return Boolean(DASHBOARD_USERNAME && DASHBOARD_PASSWORD.length >= 8);
}
// ── Signed cookie tokens ─────────────────────────────────────────────────────
function sign(payload) {
    return createHmac("sha256", sessionSecret()).update(payload).digest("base64url");
}
function issueToken() {
    const payload = `v1.${Date.now()}.${randomBytes(12).toString("base64url")}`;
    return `${payload}.${sign(payload)}`;
}
/** Verifies signature + TTL. Returns true when the cookie is valid. */
function verifyToken(token) {
    if (!token)
        return false;
    const parts = token.split(".");
    if (parts.length !== 4)
        return false;
    const payload = parts.slice(0, 3).join(".");
    const sig = parts[3];
    const expected = sign(payload);
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b))
        return false;
    const issued = Number(parts[1]);
    if (!Number.isFinite(issued))
        return false;
    return Date.now() - issued < SESSION_TTL_MS;
}
function cookieOptions() {
    const secure = process.env.NODE_ENV === "production";
    return {
        httpOnly: true,
        sameSite: "lax",
        secure,
        path: "/",
        maxAge: SESSION_TTL_MS,
    };
}
// ── Brute-force lockout ──────────────────────────────────────────────────────
const MAX_FAILURES = 5;
const WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const attempts = new Map();
function clientIp(req) {
    const xf = req.header("x-forwarded-for") ?? "";
    const first = xf.split(",")[0].trim();
    return first || req.socket.remoteAddress || "unknown";
}
function isLocked(ip) {
    const rec = attempts.get(ip);
    if (!rec)
        return false;
    return rec.lockedUntil > Date.now();
}
function recordFailure(ip) {
    const now = Date.now();
    const rec = attempts.get(ip) ?? { fails: [], lockedUntil: 0 };
    rec.fails = rec.fails.filter((t) => now - t < WINDOW_MS);
    rec.fails.push(now);
    if (rec.fails.length >= MAX_FAILURES) {
        rec.lockedUntil = now + LOCK_MS;
        rec.fails = [];
    }
    attempts.set(ip, rec);
}
function clearFailures(ip) {
    attempts.delete(ip);
}
/** Constant-time-ish credential check. */
function credentialsOk(username, password) {
    const u = Buffer.from(username.trim().toLowerCase());
    const eu = Buffer.from(DASHBOARD_USERNAME);
    const p = Buffer.from(password);
    const ep = Buffer.from(DASHBOARD_PASSWORD);
    const uOk = u.length === eu.length && timingSafeEqual(u, eu);
    const pOk = p.length === ep.length && timingSafeEqual(p, ep);
    return uOk && pOk;
}
// Periodic sweep so the lockout map cannot grow unbounded.
setInterval(() => {
    const now = Date.now();
    for (const [ip, rec] of attempts) {
        const stale = rec.fails.every((t) => now - t > WINDOW_MS) && rec.lockedUntil <= now;
        if (stale)
            attempts.delete(ip);
    }
}, 10 * 60 * 1000).unref();
// ── Minimal helpers used by the mounted router ───────────────────────────────
function escapeHtml(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
function jsonSafeDate(iso) {
    return iso ? new Date(iso).toISOString() : "";
}
// ── Re-exports for the router module ─────────────────────────────────────────
export { issueToken, verifyToken, cookieOptions, clientIp, isLocked, recordFailure, clearFailures, credentialsOk, escapeHtml, jsonSafeDate, COOKIE_NAME, };
