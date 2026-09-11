/**
 * Postgres-backed credential persistence for WhatsApp sessions.
 *
 * Free-tier Render instances are ephemeral: any restart/deploy wipes the
 * local Baileys auth folder AND the in-memory registry, forcing a fresh QR
 * scan. Persisting the (encrypted) credentials blob in the app's Neon
 * database lets every boot restore previously-paired sessions automatically.
 *
 * Security: credentials are AES-256-GCM encrypted with a key derived from
 * OPENWA_API_KEY via scrypt. The DB stores ciphertext only.
 */
import { Pool } from "pg";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import pino from "pino";
const log = pino({ level: process.env.LOG_LEVEL ?? "info" });
const PERSISTENCE_URL = (process.env.PERSISTENCE_URL ?? "").trim();
const API_KEY = (process.env.OPENWA_API_KEY ?? "").trim();
let pool = null;
function key() {
    return scryptSync(API_KEY, "openwa-gateway-creds-v1", 32);
}
function encrypt(plain) {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key(), iv);
    const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}
function decrypt(blob) {
    const iv = blob.subarray(0, 12);
    const tag = blob.subarray(12, 28);
    const data = blob.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", key(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}
async function ensurePool() {
    if (!PERSISTENCE_URL || !API_KEY)
        return null;
    if (!pool) {
        pool = new Pool({ connectionString: PERSISTENCE_URL, max: 2 });
        await pool.query(`
      CREATE TABLE IF NOT EXISTS openwa_sessions (
        name       TEXT PRIMARY KEY,
        creds      BYTEA NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
        log.info("[persist] ready (table ensured)");
    }
    return pool;
}
export function persistenceEnabled() {
    return Boolean(PERSISTENCE_URL && API_KEY);
}
/** ms since the last SUCCESSFUL save of a session (null = never saved). */
const lastSavedAt = new Map();
/**
 * WA-02 resurrection guard: timestamp of the LAST credentials wipe per
 * session name. A save that STARTED before a wipe (pending debounce or
 * an in-flight flushNow) must never upsert AFTER it — the async wipe and
 * a slow save can otherwise land out of order and resurrect dead creds
 * in the DB. Timestamp comparison (>= start-of-save) keeps a legitimate
 * save from a LATER re-pair working untouched.
 * شاهد قبر يمنع إنعاش بيانات اعتماد ميتة بعد المسح.
 */
const wipedAt = new Map();
/** Core save: serialize + encrypted upsert + bookkeeping. جوهر الحفظ. */
async function doSave(name, serialize) {
    const p = await ensurePool();
    if (!p)
        return;
    const startedAt = Date.now();
    // Guard (pre-serialize): a wipe that already landed kills this save.
    const wipe1 = wipedAt.get(name);
    if (wipe1 != null && wipe1 >= startedAt)
        return;
    const json = await serialize();
    // Guard (post-serialize): the folder read above may have raced a wipe.
    const wipe2 = wipedAt.get(name);
    if (wipe2 != null && wipe2 >= startedAt)
        return;
    await p.query(`INSERT INTO openwa_sessions (name, creds, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (name) DO UPDATE SET creds = $2, updated_at = NOW()`, [name, encrypt(json)]);
    lastSavedAt.set(name, Date.now());
    log.info({ name }, "[persist] credentials saved");
}
/**
 * Debounced save of one session's serialized auth state.
 * `delayMs` is variable: signal-store write-through uses a fast 300ms,
 * the legacy creds path keeps the relaxed 3s default.
 */
const pending = new Map();
export function scheduleSave(name, serialize, delayMs = 3_000) {
    if (!persistenceEnabled())
        return;
    const existing = pending.get(name);
    if (existing)
        clearTimeout(existing);
    pending.set(name, setTimeout(() => {
        pending.delete(name);
        void doSave(name, serialize).catch((err) => {
            log.warn({ err, name }, "[persist] save failed");
        });
    }, delayMs));
}
/**
 * Cancel a pending debounced save WITHOUT writing anything (WA-02).
 * Called when credentials are being wiped: a stale timer firing after
 * the wipe would serialize the (possibly still-present) folder and
 * upsert the dead blob back into the DB.
 * إلغاء الحفظ المؤجل المعلّق دون أي كتابة.
 */
export function cancelPendingSave(name) {
    const existing = pending.get(name);
    if (existing) {
        clearTimeout(existing);
        pending.delete(name);
    }
}
/**
 * Cancel any pending debounce and persist immediately (awaited).
 * Used by the SIGTERM/SIGINT shutdown flush and the disconnect path —
 * a debounced save would die with the process.
 * إلغاء الـ debounce المعلّق وتنفيذ الحفظ فورًا.
 */
export async function flushNow(name, serialize) {
    if (!persistenceEnabled())
        return;
    const existing = pending.get(name);
    if (existing) {
        clearTimeout(existing);
        pending.delete(name);
    }
    try {
        await doSave(name, serialize);
    }
    catch (err) {
        log.warn({ err, name }, "[persist] flush failed");
    }
}
/**
 * Milliseconds since the last SUCCESSFUL save of this session's snapshot,
 * or null when it has never been saved (fresh pairing / persistence off).
 * عمر آخر snapshot محفوظ بالمللي ثانية.
 */
export function persistAge(name) {
    const t = lastSavedAt.get(name);
    return t == null ? null : Date.now() - t;
}
/** Load + decrypt stored credentials JSON for a session name (or null). */
export async function loadCreds(name) {
    try {
        const p = await ensurePool();
        if (!p)
            return null;
        const res = await p.query(`SELECT creds FROM openwa_sessions WHERE name = $1`, [name]);
        if (res.rowCount === 0)
            return null;
        return decrypt(res.rows[0].creds);
    }
    catch (err) {
        log.warn({ err, name }, "[persist] load failed");
        return null;
    }
}
/** Names of all persisted sessions (for boot-time auto-restore). */
export async function listPersistedNames() {
    try {
        const p = await ensurePool();
        if (!p)
            return [];
        const res = await p.query(`SELECT name FROM openwa_sessions ORDER BY name`);
        return res.rows.map((r) => r.name);
    }
    catch (err) {
        log.warn({ err }, "[persist] list failed");
        return [];
    }
}
/**
 * Wipe the persisted credentials blob for a session (the local auth dir
 * is the caller's job). WA-02 hardening: cancels any pending debounced
 * save, tombstones the name (an in-flight save that started earlier can
 * never upsert the dead blob afterwards) and drops the persistAge marker.
 * مسح البيانات المحفوظة مع إلغاء أي حفظ معلّق وشاهد قبر يمنع الإنعاش.
 */
export async function deletePersisted(name) {
    cancelPendingSave(name);
    wipedAt.set(name, Date.now());
    lastSavedAt.delete(name);
    try {
        const p = await ensurePool();
        if (!p)
            return;
        await p.query(`DELETE FROM openwa_sessions WHERE name = $1`, [name]);
    }
    catch {
        // best-effort
    }
}
