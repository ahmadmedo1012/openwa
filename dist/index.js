/**
 * OpenWA gateway — WhatsApp multi-session REST gateway built on Baileys.
 *
 * Implements the REST surface consumed by SubNation's
 * backend/src/services/openwa.service.ts:
 *
 *   Auth:  header `X-API-Key: <KEY>` on every /api request.
 *
 *     GET  /api/sessions                       → SessionRecord[]
 *     GET  /api/sessions/{id}                  → SessionRecord | 404
 *     POST /api/sessions        {name}         → SessionRecord
 *     POST /api/sessions/{id}/start            → SessionRecord
 *     GET  /api/sessions/{id}/qr               → operator HTML page w/ QR
 *     POST /api/sessions/{id}/messages/send-text {chatId,text} → {ok,messageId,selfSend}
 *     POST /api/sessions/{id}/messages/test      {chatId}      → {ok,messageId,selfSend}
 *     GET  /api/sessions/{id}/delivery-log                     → {deliveries:DeliveryLogEntry[]}
 *     GET  /api/sessions/{id}/contacts/check/{number} → {exists:boolean}
 *
 * Self-send (OTP to the linked account's own number) is detected and routed
 * via the account's LID — the modern "Message yourself" path.
 *
 * Rate limits (R97-04 partial, in-memory sliding window per IP):
 *     /api/sessions/{id}/pair-code                → 5 / hour
 *     /api/sessions/{id}/messages/send-text|test  → 60 / minute
 *     every other /api request (GET included)      → 240 / minute
 *   429 {error:"rate_limited",retry_after_sec} + Retry-After header;
 *   /healthz is outside /api and never throttled. See src/rate-limit.ts.
 *
 * Operator dashboard (browser): GET / — username+password login
 * (DASHBOARD_USERNAME / DASHBOARD_PASSWORD env), cookie-authenticated
 * session management UI. Never exposes OPENWA_API_KEY to the browser.
 *
 *   Lifecycle: created → initializing → qr_ready → ready →
 *              (disconnected ⇄ reconnect) | failed
 *
 * Session credentials persist under ${DATA_DIR}/sessions/<name>/ so a
 * scanned QR survives process restarts and redeploys (mount a volume at
 * DATA_DIR — a Coolify volume / compose volume).
 */
import express from "express";
import pino from "pino";
import { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion, DisconnectReason, } from "@whiskeysockets/baileys";
import { nanoid } from "nanoid";
import { timingSafeEqual } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { persistenceEnabled, scheduleSave, flushNow, persistAge, loadCreds, listPersistedNames, deletePersisted, cancelPendingSave, isSafeBlobFilename, } from "./persist.js";
import { normalizeChatId, extractAccountDigits, extractLidDigits, resolveSendJid, mergeDeliveryTimeline, pushDeliveryLog, advanceDeliveryStatus, applyConnectionClose, asyncHandler, beginSessionStart, httpErrorStatus, maskDigits, maskJid, shouldPreferDbBlobOverLocal, } from "./lib.js";
import { createApiRateLimiter } from "./rate-limit.js";
import { mountDashboard } from "./dashboard-routes.js";
import { dashboardEnabled } from "./dashboard.js";
const log = pino({ level: process.env.LOG_LEVEL ?? "info" });
const PORT = Number(process.env.PORT ?? 2785);
const API_KEY = (process.env.OPENWA_API_KEY ?? "").trim();
const DATA_DIR = (process.env.DATA_DIR ?? "/data").replace(/\/+$/, "");
// Self-send LID routing (OTP to the operator's own number): on by default,
// opt-out with OPENWA_SELF_SEND_LID=0. توجيه المحادثة الذاتية عبر LID.
const SELF_SEND_LID_ENABLED = (process.env.OPENWA_SELF_SEND_LID ?? "").trim() !== "0";
if (!API_KEY) {
    log.error("OPENWA_API_KEY is required — refusing to start (refusing an open relay)");
    process.exit(1);
}
// FH-A2 P3-2: the API key is the SOLE auth of the /api surface — timing-safe
// compare and the pre-gate rate limits bound guessing speed, but key entropy
// is what they defend. Warn (not refuse) so existing deployments keep booting.
if (API_KEY.length < 32) {
    log.warn({ length: API_KEY.length }, "[gateway] OPENWA_API_KEY is shorter than 32 chars — recommended: openssl rand -hex 32");
}
const SESSION_NAME_RE = /^[A-Za-z0-9-]{3,50}$/;
// ── Registry ─────────────────────────────────────────────────────────────────
/** R104 (AG7-4): 24 h in-process cache for the baileys version registry. */
let versionCache;
let versionCacheAt = 0;
const sessions = new Map(); // by id
function publicView(rs) {
    const persistAgeMs = persistAge(rs.name);
    return {
        id: rs.id,
        name: rs.name,
        status: rs.status,
        createdAt: rs.createdAt,
        ...(rs.pairingId ? { pairingId: rs.pairingId } : {}),
        ...(rs.lastReadyAt ? { lastReadyAt: rs.lastReadyAt } : {}),
        ...(rs.lastDeliveryStatus ? { lastDeliveryStatus: rs.lastDeliveryStatus } : {}),
        ...(rs.accountDigits ? { accountDigits: rs.accountDigits } : {}),
        ...(rs.accountName ? { accountName: rs.accountName } : {}),
        ...(rs.connectedAt ? { connectedAt: rs.connectedAt } : {}),
        ...(persistAgeMs != null ? { persistAgeMs } : {}),
    };
}
function findByName(name) {
    return [...sessions.values()].find((s) => s.name === name);
}
// ── Socket wiring ────────────────────────────────────────────────────────────
/**
 * Serializer builder shared by EVERY persistence path (debounced snapshot,
 * signal-store write-through, SIGTERM flush): reads the session's whole auth
 * folder into one JSON blob. بانٍ موحّد لدالة التسلسل لكل مسارات الحفظ.
 */
function buildSerializer(name) {
    return async () => {
        const dir = `${DATA_DIR}/sessions/${name}`;
        const files = await fs.readdir(dir);
        const out = {};
        for (const f of files) {
            out[f] = await fs.readFile(path.join(dir, f), "utf8");
        }
        return JSON.stringify(out);
    };
}
async function startSession(rs) {
    rs.stopRequested = false;
    rs.qrString = undefined;
    // Restore persisted credentials (if any) into the auth folder BEFORE the
    // engine reads it — this is what makes restarts/deploy self-healing.
    if (persistenceEnabled()) {
        try {
            const dir = `${DATA_DIR}/sessions/${rs.name}`;
            const existing = await fs.readdir(dir).catch(() => []);
            const hasCreds = existing.includes("creds.json");
            // O2-F1 (R111): INTERIM local creds (registered !== true, written by
            // an interrupted pairing while the DB still held the good registered
            // blob) used to permanently shadow the restore on persistent
            // volumes — the old gate tested creds.json EXISTENCE only, so the
            // boot self-heal looped qr_ready forever while the registered blob
            // sat unused in the DB. The DB only ever stores post-ready snapshots
            // (the "no persist before ready" gate), so it is preferred whenever
            // the local state is absent OR not fully registered. يُفضَّل بلوب
            // قاعدة البيانات على بيانات اعتماد محلية غير مسجلة.
            let localRegistered = false;
            if (hasCreds) {
                try {
                    const raw = await fs.readFile(path.join(dir, "creds.json"), "utf8");
                    localRegistered = Boolean(JSON.parse(raw)?.registered);
                }
                catch {
                    localRegistered = false; // unreadable local creds → treat as interim
                }
            }
            if (shouldPreferDbBlobOverLocal(hasCreds, localRegistered)) {
                const blob = await loadCreds(rs.name);
                if (blob) {
                    if (hasCreds) {
                        // The interim folder also holds pre-keys/sessions the
                        // registered blob knows nothing about — a MIXED folder is not
                        // a valid auth state, so wipe it first: the restore below then
                        // rewrites the folder byte-identically to the fresh path.
                        await fs.rm(dir, { recursive: true, force: true }).catch(() => { });
                        log.warn({ sessionId: rs.id, name: rs.name }, "[persist] interim local credentials replaced by the DB blob (O2-F1)");
                    }
                    await fs.mkdir(dir, { recursive: true });
                    const creds = JSON.parse(blob);
                    for (const [fname, content] of Object.entries(creds)) {
                        // 110-K (109-h P3): the blob comes from the DB — validate every
                        // filename BEFORE writing it (see isSafeBlobFilename in
                        // persist.ts). A tampered/foreign blob must never plant a file
                        // outside the session dir via an absolute path, `..` traversal
                        // or separators. Skip + warn on the FILENAME only (blob content
                        // is secret and never logged); one bad name must not abort the
                        // rest of the restore, and the restore must not crash the boot.
                        if (!isSafeBlobFilename(fname)) {
                            log.warn({ sessionId: rs.id, name: rs.name, fname: fname.slice(0, 64) }, "[persist] restore skipped a suspicious blob filename (path-traversal guard)");
                            continue;
                        }
                        await fs.writeFile(path.join(dir, fname), typeof content === "string" ? content : JSON.stringify(content));
                    }
                    log.info({ sessionId: rs.id, name: rs.name }, "[persist] credentials restored from DB");
                }
            }
        }
        catch (err) {
            log.warn({ err, name: rs.name }, "[persist] restore failed — continuing fresh");
        }
    }
    const { state, saveCreds } = await useMultiFileAuthState(`${DATA_DIR}/sessions/${rs.name}`);
    // ── Write-through persistence ──────────────────────────────────────────
    // Signal-store writes (sessions / pre-keys / sender-keys) rotate on every
    // send & receipt; the old code persisted only on creds.update/send, so a
    // restore brought back a STALE signal state → the phone rendered
    // "Waiting for this message". Every keys mutation now schedules a fast
    // (300ms) debounced snapshot. كل كتابة signal store تُطلق حفظًا سريعًا.
    const serialize = buildSerializer(rs.name);
    rs.persistSerialize = serialize;
    rs.persistFlush = () => flushNow(rs.name, serialize);
    const scheduleKeySave = () => {
        // Only once the session has proven itself connected — interim pairing
        // state must never reach the DB (same gate as creds.update below).
        if (rs.lastReadyAt)
            scheduleSave(rs.name, serialize, 300);
    };
    const origSet = state.keys.set.bind(state.keys);
    state.keys.set = async (data) => {
        await origSet(data);
        scheduleKeySave();
    };
    const keysAsDel = state.keys;
    if (typeof keysAsDel.del === "function") {
        const origDel = keysAsDel.del.bind(state.keys);
        keysAsDel.del = async (data) => {
            await origDel(data);
            scheduleKeySave();
        };
    }
    // R104 (AG7-4): 24 h in-process cache. The registry fetch fired on
    // EVERY session start (each boot-restore after an idle sleep included)
    // — one outbound HTTPS call per wake for a value that changes a few
    // times a year.
    let version;
    if (versionCache && Date.now() - versionCacheAt > 86_400_000) {
        versionCache = undefined;
    }
    version = versionCache;
    if (!version) {
        try {
            // O2-F3 (R111): axios defaults to NO timeout — a black-holed registry
            // fetch stalled this session start (and, in the serial boot loop,
            // every session behind it) for as long as the OS held the socket.
            // 3s bound; baileys' own baked-in version is the fallback on failure.
            const latest = await fetchLatestBaileysVersion({ timeout: 3_000 });
            version = latest.version;
            versionCache = version;
            versionCacheAt = Date.now();
        }
        catch {
            // offline registry / transient — baileys falls back to its baked-in version
        }
    }
    rs.status = rs.status === "created" ? "initializing" : rs.status;
    if (hasStoredCreds(state)) {
        // Credentials exist from a previous successful pairing — go straight
        // to connecting; QR only reappears if WhatsApp rejects them.
        rs.status = "initializing";
    }
    const sock = makeWASocket({
        version,
        auth: state,
        printQRInTerminal: false,
        browser: ["Windows", "Chrome", "133.0"],
        markOnlineOnConnect: false,
        syncFullHistory: false,
    });
    rs.socket = sock;
    // O1-M1 (R111): a DELETE that landed while this start was still in
    // flight has already set stopRequested (the reset at the top of
    // startSession ran BEFORE the delete, and rs.socket was not yet
    // assigned — so the deleter's socket?.end() no-oped). End the freshly
    // created socket right now: the close handler below sees stopRequested
    // and runs the failed+wipe path, so the start can never go on to open a
    // connection on a detached record (persist gates reopen → upsert lands
    // after the tombstone → the deleted row resurrects).
    if (rs.stopRequested) {
        try {
            sock.end(undefined);
        }
        catch {
            // already dead
        }
    }
    const persistSnapshot = () => {
        if (!persistenceEnabled() || !rs.lastReadyAt)
            return;
        scheduleSave(rs.name, serialize);
    };
    rs.persistSnapshot = persistSnapshot;
    // messages.upsert is now ONLY a persistence trigger — the old
    // lastOutMsgId capture was broken: messages typed on the operator's OWN
    // phone are also fromMe, so they polluted outbound tracking and made
    // lastDeliveryStatus untrustworthy. التقاط lastOutMsgId المعطوب أُزيل.
    sock.ev.on("messages.upsert", (upsert) => {
        if (upsert.type !== "notify")
            return;
        // Incoming traffic advances app-state/signal material — refresh the
        // snapshot fast so restores stay decryptable. الرسائل الواردة تحفظ.
        scheduleKeySave();
    });
    // Outbound delivery tracking: WhatsApp acks ENGINE-sent messages through
    // messages.update (PENDING → SERVER_ACK → DELIVERED/READ, or ERROR).
    // u.key.id is matched against the per-message delivery log — never
    // against whatever fromMe message happened to arrive last, so the
    // operator's own phone traffic can no longer fake a delivery status.
    // تتبع تسليم صحيح: مطابقة معرف رسالة أرسلها المحرك نفسه فقط.
    //
    // WA-04: WhatsApp statuses can REGRESS (a live 3→2 re-ack burst was
    // observed at the exact second a pairing was revoked). Every
    // transition is recorded in the timeline (audit), but the
    // authoritative status — per entry AND on the session view — is the
    // MAX rank ever observed, never the raw last event.
    // الحالة الموثوقة = الأعلى رتبةً — الانحدار يُسجَّل ولا يُعتمد.
    sock.ev.on("messages.update", (updates) => {
        for (const u of updates) {
            const msgId = typeof u.key.id === "string" ? u.key.id : null;
            const rawStatus = u.update?.status;
            if (msgId == null || rawStatus == null)
                continue;
            const logArr = rs.deliveryLog;
            if (!logArr || logArr.length === 0)
                continue;
            const newStatus = String(rawStatus);
            for (let i = logArr.length - 1; i >= 0; i--) {
                if (logArr[i].messageId !== msgId)
                    continue;
                const entry = logArr[i];
                const prevMax = entry.maxStatus ?? entry.lastStatus;
                const nextMax = advanceDeliveryStatus(prevMax, newStatus);
                const advanced = nextMax !== prevMax;
                const nextEntry = {
                    ...entry,
                    timeline: mergeDeliveryTimeline(entry.timeline, newStatus),
                    lastStatus: nextMax,
                    maxStatus: nextMax,
                    // lastStatusAt tracks when the authoritative status last
                    // ADVANCED — a regression keeps its own timeline timestamp.
                    ...(advanced || !entry.lastStatusAt ? { lastStatusAt: new Date().toISOString() } : {}),
                };
                const next = [...logArr];
                next[i] = nextEntry;
                rs.deliveryLog = next;
                // Session-level status: the MAX seen across engine-sent messages
                // (legacy "last message only" contract replaced — an older
                // message's ack is still real evidence of delivery capability).
                const before = rs.lastDeliveryStatus;
                rs.lastDeliveryStatus = advanceDeliveryStatus(before, newStatus);
                if (rs.lastDeliveryStatus !== before) {
                    log.info({ sessionId: rs.id, messageId: msgId, status: rs.lastDeliveryStatus }, "[delivery] status");
                }
                else {
                    log.info({ sessionId: rs.id, messageId: msgId, status: newStatus }, "[delivery] status (regression recorded, max kept)");
                }
                break;
            }
        }
    });
    sock.ev.on("creds.update", () => {
        void Promise.resolve(saveCreds()).then(() => {
            // Persist ONLY once the session has proven itself connected at least
            // once. creds.update fires during pairing with INTERIM credentials;
            // saving those captured half-paired state, and every later boot
            // restored credentials WhatsApp had already invalidated.
            persistSnapshot();
        });
    });
    sock.ev.on("connection.update", (update) => {
        const { connection, lastDisconnect, qr } = update;
        if (qr) {
            rs.qrString = qr;
            rs.status = "qr_ready";
            log.info({ sessionId: rs.id, name: rs.name }, "[session] QR ready — awaiting scan");
            return;
        }
        if (connection === "connecting") {
            // After a scan the engine moves connecting→open; keep qr_ready until
            // either open or creds.update confirms registration.
            if (rs.status !== "qr_ready")
                rs.status = "initializing";
            return;
        }
        if (connection === "open") {
            rs.status = "ready";
            rs.qrString = undefined;
            rs.lastReadyAt = new Date().toISOString();
            rs.connectedAt = rs.lastReadyAt;
            // R104 (AG4-2): stable pairing identity — registrationId lives in
            // the creds folder, so a RESTORE re-observes the same value while a
            // re-pair observes a new one. Undefined on legacy/edge shapes (the
            // backend then falls back to lastReadyAt — no behavior change).
            const registrationId = sock.authState.creds.registrationId;
            if (typeof registrationId === "number")
                rs.pairingId = String(registrationId);
            rs.reconnectAttempts = 0; // R104 (AG4-3): backoff decays after a healthy connect
            // Capture the linked-account identity for self-send detection +
            // enriched views. التقاط هوية الحساب المرتبط (رقم/اسم/LID).
            const me = sock.authState.creds.me;
            rs.accountDigits = me?.id ? (extractAccountDigits(me.id) ?? undefined) : undefined;
            rs.accountName = me?.name;
            rs.accountLidDigits = me?.lid ? (extractLidDigits(me.lid) ?? undefined) : undefined;
            log.info({
                sessionId: rs.id,
                name: rs.name,
                // r98/98-F6 P3-3: stdout is a retained surface (Render logs) —
                // phone digits are masked to the last 4. Full values stay in the
                // key-gated /api views and the encrypted DB blob.
                accountDigits: maskDigits(rs.accountDigits ?? ""),
                accountName: rs.accountName ?? null,
                accountLidDigits: maskDigits(rs.accountLidDigits ?? ""),
            }, "[session] connected (ready)");
            return;
        }
        if (connection === "close") {
            // O2-F4 (R111): a LATE close from a superseded socket (a reconnect
            // already opened a new one on this record) must never run the close
            // reducer — it would clobber the live registration, mark the session
            // disconnected and arm a SECOND start on the same auth folder;
            // WhatsApp answers that conflict with loggedOut → credential wipe.
            // Only the CURRENT socket's close is processed (undefined ⇒ a close
            // was already processed for the previous socket — a duplicate close
            // is equally stale). إغلاق متقادم من سوكت مستبدَل يُتجاهل — لا
            // يُعالَج إلا إغلاق السوكت الحالي.
            if (rs.socket !== sock) {
                log.warn({ sessionId: rs.id, name: rs.name }, "[session] stale close from a superseded socket ignored");
                return;
            }
            const code = lastDisconnect?.error
                ?.output?.statusCode;
            const loggedOut = code === DisconnectReason.loggedOut;
            const outcome = applyConnectionClose(rs, { loggedOut, stopRequested: Boolean(rs.stopRequested) }, {
                // WA-02: dead credentials must never be resurrected. Cancel any
                // pending debounced save FIRST (a stale timer firing after the
                // wipe would upsert the dead blob back into the DB), then wipe
                // the local dir, then the persisted blob — deletePersisted
                // re-cancels and tombstones the name so even an in-flight
                // flushNow that started earlier cannot land after the wipe.
                // إبطال بيانات ميتة بلا إنعاش: إلغاء الحفظ المعلّق أولًا ثم المسح.
                wipeCredentials: () => {
                    void (async () => {
                        try {
                            cancelPendingSave(rs.name);
                            await fs.rm(`${DATA_DIR}/sessions/${rs.name}`, { recursive: true, force: true });
                            await deletePersisted(rs.name);
                            log.warn({ sessionId: rs.id, name: rs.name }, "[session] dead credentials wiped (local+persistence)");
                        }
                        catch { }
                    })();
                },
                markRestartable: () => void restartable(rs),
                // Snapshot NOW, not debounced-then-dead: if the process dies
                // inside the 5s reconnect window, the next boot must restore
                // the LATEST signal state, not the pre-disconnect one.
                // حفظ فوري قبل نافذة إعادة الاتصال.
                flushSnapshot: () => void flushNow(rs.name, serialize),
                // Auto-reconnect with backoff unless explicitly stopped. The
                // start goes through the SAME single-flight guard as the routes
                // (P2-2): a reconnect-timer race with a manual start can never
                // build a second socket on the auth folder.
                scheduleReconnect: () => {
                    // R104 (AG4-3): exponential backoff + jitter (was a fixed 5 s
                    // with no cap on attempts). During a WhatsApp/network outage
                    // the fixed cadence fired ~12 attempts/min per session and
                    // every disconnect ALSO flushed a Neon snapshot — bounded
                    // churn that now decays to one attempt per 5 min.
                    const attempt = (rs.reconnectAttempts = (rs.reconnectAttempts ?? 0) + 1);
                    const base = Math.min(5_000 * 2 ** (attempt - 1), 300_000);
                    const delay = base * (0.75 + Math.random() * 0.5);
                    const timer = setTimeout(() => {
                        const cur = sessions.get(rs.id);
                        if (!cur || cur.stopRequested || cur.status !== "disconnected")
                            return;
                        cur.status = "initializing";
                        // O2-F2 (R111): mirror the /start route — a failed engine
                        // start must land on "failed", not wedge at initializing
                        // forever (no socket ⇒ no close event ⇒ nothing re-arms).
                        void beginSessionStart(cur, () => startSession(cur)).catch((err) => {
                            cur.status = "failed";
                            log.error({ err, sessionId: rs.id }, "[session] reconnect failed");
                        });
                    }, delay);
                    timer.unref?.();
                },
            });
            if (outcome === "failed") {
                log.warn({ sessionId: rs.id, name: rs.name, loggedOut }, "[session] closed permanently");
            }
            else {
                log.info({ sessionId: rs.id, name: rs.name, code }, "[session] disconnected — will restart on demand");
            }
        }
    });
}
/** Wipe stored credentials so the next start() produces a fresh QR. */
async function restartable(rs) {
    try {
        const fs = await import("node:fs/promises");
        await fs.rm(`${DATA_DIR}/sessions/${rs.name}`, { recursive: true, force: true });
    }
    catch {
        // best-effort
    }
}
/** Heuristic: does the auth store look previously-paired? */
function hasStoredCreds(state) {
    try {
        const s = state;
        return Boolean(s?.creds?.registered);
    }
    catch {
        return false;
    }
}
// ── Helpers ──────────────────────────────────────────────────────────────────
function requireKey(req, res) {
    // SEC1/P3: timing-safe comparison — a plain !== leaks key bytes via
    // early-exit timing on a high-precision remote clock.
    const given = Buffer.from(req.header("x-api-key") ?? "");
    const expected = Buffer.from(API_KEY);
    const ok = given.length === expected.length && timingSafeEqual(given, expected);
    if (!ok) {
        res.status(401).json({ error: "invalid or missing X-API-Key" });
        return false;
    }
    return true;
}
function findOr404(id, res) {
    // R104 (AG4-4): accept the session NAME in the {id} path too. The OTP
    // backend configured by name (`WHATSAPP_OTP_SESSION=subnation-otp`)
    // used to GET /api/sessions/subnation-otp → guaranteed 404 → list →
    // resolve — two requests per probe, the first always doomed. Name
    // lookup after the id miss makes the first request succeed; ids stay
    // authoritative (a name that collides with an id shape still resolves
    // by id first).
    let rs = sessions.get(id);
    if (!rs && id && !id.startsWith("sess_")) {
        // RT-8 (R104 red team): malformed percent-sequences must 404, not 500.
        let name = id;
        try {
            name = decodeURIComponent(id);
        }
        catch {
            // keep the raw value — it will simply not match any session name
        }
        rs = findByName(name);
    }
    if (!rs)
        res.status(404).json({ error: "session not found" });
    return rs;
}
// ── App ──────────────────────────────────────────────────────────────────────
const app = express();
// SEC1/P2-2 + P3 hardening: clickjacking backstop for the destructive
// session-delete dialog, CSP allows only self + the QR data-URL, no
// server banner, and no browser/proxy caching of any dynamic response.
app.disable("x-powered-by");
app.use((_req, res, next) => {
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Content-Security-Policy", 
    // 'unsafe-inline' for script/style: the pages are 100% server-rendered
    // templates whose ONLY dynamic values pass through escapeHtml()/esc()
    // (verified by the red-team sweep) — no third-party or user-supplied
    // markup ever executes. Everything else is locked to 'none'.
    "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'");
    if (_req.path.startsWith("/dash/") ||
        _req.path === "/" ||
        _req.path === "/login" ||
        // r98/98-F6 P3-1: /api responses carry the QR pairing secret and the
        // linked account's phone digits — they must never be heuristically
        // cached by an intermediary either.
        _req.path.startsWith("/api")) {
        res.setHeader("Cache-Control", "no-store");
    }
    next();
});
app.use(express.json({ limit: "256kb" }));
app.get("/healthz", (_req, res) => {
    const ready = [...sessions.values()].filter((s) => s.status === "ready").length;
    res.json({ ok: true, sessions: sessions.size, ready, dashboard: dashboardEnabled() });
});
// ── Operator dashboard (browser UI) ───────────────────────────────────────────
// Mounted BEFORE the /api key gate: it authenticates with its own signed
// cookie, never with the API key, so the browser never learns it.
const bootedAt = Date.now();
function toDashboardView(rs) {
    return {
        id: rs.id,
        name: rs.name,
        status: rs.status,
        createdAt: rs.createdAt,
        lastReadyAt: rs.lastReadyAt,
        lastDeliveryStatus: rs.lastDeliveryStatus,
        accountDigits: rs.accountDigits,
        accountName: rs.accountName,
        connectedAt: rs.connectedAt,
        persistAgeMs: persistAge(rs.name) ?? undefined,
        async start() {
            if (!rs.socket) {
                rs.status = rs.status === "created" ? "initializing" : rs.status;
                // P2-2 single-flight: a start already in flight (API route,
                // reconnect timer, another tab) is AWAITED, never duplicated.
                await beginSessionStart(rs, () => startSession(rs));
            }
        },
        async requestPairCode(phone) {
            if (!rs.socket)
                throw new Error("session_not_started");
            return rs.socket.requestPairingCode(phone);
        },
        qrString: () => rs.qrString ?? null,
        async delete() {
            rs.stopRequested = true;
            // O1-M1 (R111): a start still in flight has not assigned rs.socket
            // yet — end() would no-op and the background start would go on to
            // open a connection on a detached record (persist gates reopen →
            // upsert after the tombstone → resurrection). Await the in-flight
            // start (bounded: it settles once handlers are wired — it never
            // waits for the connection itself), then end the now-assigned
            // socket. يُنتظر البدء الجاري قبل إنهاء السوكت.
            await rs.starting?.catch(() => { });
            try {
                rs.socket?.end(undefined);
            }
            catch {
                // engine may already be dead
            }
            sessions.delete(rs.id);
            await fs
                .rm(`${DATA_DIR}/sessions/${rs.name}`, { recursive: true, force: true })
                .catch(() => { });
            await deletePersisted(rs.name);
            log.info({ sessionId: rs.id, name: rs.name }, "[session] deleted (dashboard)");
        },
    };
}
async function createSessionRecord(name) {
    if (findByName(name))
        return { error: "يوجد جلسة بنفس الاسم بالفعل", conflict: true };
    const rs = {
        id: `sess_${nanoid(16)}`,
        name,
        status: "created",
        createdAt: new Date().toISOString(),
    };
    sessions.set(rs.id, rs);
    log.info({ sessionId: rs.id, name }, "[session] created (dashboard)");
    return { id: rs.id, name: rs.name, status: rs.status, createdAt: rs.createdAt };
}
// SEC1/P3: CSRF backstop for the cookie-authenticated dashboard
// mutations. SameSite=Lax already blocks cross-site POST from rendered
// pages; this additionally verifies the Origin header browsers ALWAYS
// attach to non-GET fetches. Absent Origin (curl / server-to-server)
// is allowed — those callers cannot carry a victim's cookie.
app.use("/dash", (req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD")
        return next();
    const origin = req.header("origin");
    if (!origin)
        return next();
    let host = null;
    try {
        host = new URL(origin).host;
    }
    catch {
        host = null;
    }
    const ownHost = req.header("host") ?? "";
    if (!host || !ownHost || host !== ownHost) {
        res.status(403).json({ error: "cross_origin_blocked" });
        return;
    }
    return next();
});
mountDashboard(app, {
    sessions: () => [...sessions.values()].map(toDashboardView),
    info: () => ({
        uptimeSec: Math.floor((Date.now() - bootedAt) / 1000),
        persist: persistenceEnabled(),
        version: "1.3.0",
    }),
    createSession: createSessionRecord,
});
// R97-04 (partial): in-memory sliding-window rate limits for the whole
// /api surface — mounted BEFORE the X-API-Key gate so unauthenticated
// key guessing is bounded per IP as well. /healthz lives outside /api
// and stays exempt (the SubNation backend readiness probe must never be
// throttled — R104: the keep-alive self-ping was removed 2026-09-20).
app.use("/api", createApiRateLimiter());
app.use("/api", (req, res, next) => {
    if (!requireKey(req, res))
        return;
    next();
});
app.get("/api/docs", (_req, res) => {
    res.json({
        service: "openwa-gateway",
        endpoints: [
            "GET    /api/sessions",
            "GET    /api/sessions/{id}",
            "POST   /api/sessions                body: {name}",
            "POST   /api/sessions/{id}/start",
            "POST   /api/sessions/{id}/pair-code  body: {phone}",
            "GET    /api/sessions/{id}/qr        (operator: scan with WhatsApp)",
            "POST   /api/sessions/{id}/messages/send-text   body: {chatId,text} → {ok,messageId,selfSend}",
            "POST   /api/sessions/{id}/messages/test        body: {chatId} → {ok,messageId,selfSend}",
            "GET    /api/sessions/{id}/delivery-log",
            "GET    /api/sessions/{id}/contacts/check/{number}",
        ],
        auth: "X-API-Key header",
    });
});
// List sessions
app.get("/api/sessions", (_req, res) => {
    res.json([...sessions.values()].map(publicView));
});
// Create session
app.post("/api/sessions", asyncHandler(async (req, res) => {
    const name = String(req.body?.name ?? "").trim();
    if (!SESSION_NAME_RE.test(name)) {
        return res.status(400).json({ error: "name must match [A-Za-z0-9-]{3,50}" });
    }
    const created = await createSessionRecord(name);
    if ("error" in created) {
        return res.status(created.conflict ? 409 : 500).json({ error: created.error });
    }
    return res.status(201).json(created);
}));
// Get one session
app.get("/api/sessions/:id", (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    return res.json(publicView(rs));
});
// Start (or restart) a session
app.post("/api/sessions/:id/start", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    if (!rs.socket && !rs.starting) {
        // First caller owns the start; the response still goes out immediately
        // and the status advances via events (unchanged contract).
        rs.status = rs.status === "created" ? "initializing" : rs.status;
        res.json(publicView(rs));
        // r98/98-F6 P2-2: single-flight — the in-flight start is memoized on the
        // record, so a concurrent start (double-submit, dashboard start, the
        // reconnect timer racing this route) awaits THIS promise instead of
        // building a second socket on the same auth folder (WhatsApp answers a
        // socket conflict with loggedOut → credential wipe → forced re-pair).
        void beginSessionStart(rs, () => startSession(rs)).catch((err) => {
            rs.status = "failed";
            log.error({ err, sessionId: rs.id }, "[session] start failed");
        });
        return;
    }
    if (rs.starting) {
        // P2-2: ride the in-flight start — a concurrent second start awaits
        // the SAME promise and never spawns a second engine start.
        await rs.starting.then(() => res.json(publicView(rs)), () => res.status(500).json({ error: "start_failed" }));
        return;
    }
    return res.json(publicView(rs)); // already running
}));
// Operator QR page — renders the current pairing QR as PNG in a minimal
// auto-refreshing HTML page (also serves plain JSON when requested as such).
//
// STATUS CONTRACT (r98/98-F6, verified against the consumer — SubNation
// backend/src/services/openwa.service.ts getWhatsAppSessionQr): the JSON
// path (Accept: application/json) answers 404 {id,name,status,qr:null} while
// a QR is not available yet — the consumer's gatewayJson maps any !ok to
// gateway_request_failed, so 404-while-pairing IS the polling signal, and
// 200+{qr:null} is only returned once the session is already "ready". The
// HTML (operator browser) path ALWAYS answers 200 with an auto-refreshing
// page. The duality is intentional — do NOT unify it.
app.get("/api/sessions/:id/qr", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    const wantsHtml = String(req.header("accept") ?? "").includes("text/html");
    if (!rs.qrString) {
        const body = { id: rs.id, name: rs.name, status: rs.status, qr: null };
        if (wantsHtml) {
            return res
                .status(200)
                .type("html")
                .send(`<meta http-equiv="refresh" content="3"><body style="font-family:sans-serif;background:#0b141a;color:#fff;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><p>الحالة: <b>${rs.status}</b></p><p>${rs.status === "ready"
                ? "✅ الجلسة جاهزة — يمكنك إغلاق الصفحة"
                : "لا يوجد QR حالياً… تحديث تلقائي كل 3 ثوانٍ"}</p></div></body>`);
        }
        return res.status(rs.status === "ready" ? 200 : 404).json(body);
    }
    const QRCode = await import("qrcode");
    const dataUrl = await QRCode.toDataURL(rs.qrString, { margin: 2, width: 320 });
    if (!wantsHtml) {
        return res.json({ id: rs.id, name: rs.name, status: rs.status, qr: rs.qrString, qrImage: dataUrl });
    }
    return res
        .status(200)
        .type("html")
        .send(`<meta http-equiv="refresh" content="20"><body style="font-family:sans-serif;background:#0b141a;color:#fff;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><h2>@${rs.name}</h2><img alt="QR" src="${dataUrl}" width="320" height="320"><p>WhatsApp ← الأجهزة المرتبطة ← ربط جهاز</p><p>تحديث تلقائي كل 20 ثانية</p><p>الحالة: <b>${rs.status}</b></p></div></body>`);
}));
// Preflight number check (also warms Baileys' LID cache before send-text).
app.get("/api/sessions/:id/contacts/check/:number", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    if (!rs.socket || rs.status !== "ready") {
        return res.status(409).json({ error: "session_not_ready", status: rs.status });
    }
    const digits = req.params.number.replace(/[^0-9]/g, "");
    // r98/98-F6 P3-5: same E.164-ish bounds as pair-code/send-text (8–15
    // digits) — an unbounded digit string went straight into the WhatsApp
    // preflight before.
    if (digits.length < 8 || digits.length > 15) {
        return res.status(400).json({ error: "number must be 8-15 digits" });
    }
    try {
        const result = await rs.socket.onWhatsApp(digits);
        const exists = Array.isArray(result) && result[0]?.exists === true;
        return res.json({ exists });
    }
    catch (err) {
        log.warn({ err, sessionId: rs.id }, "[contacts/check] failed");
        return res.status(500).json({ error: "check_failed" });
    }
}));
// Request a phone-number pairing code (the reliable alternative to QR:
// no rotation timing, entered manually on the phone under
// Linked devices → "Link with phone number instead").
app.post("/api/sessions/:id/pair-code", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    if (!rs.socket) {
        return res.status(409).json({ error: "session_not_started", status: rs.status });
    }
    const phone = String(req.body?.phone ?? "").replace(/[^0-9]/g, "");
    if (phone.length < 10 || phone.length > 15) {
        return res.status(400).json({ error: "phone must be E.164 digits (e.g. 21891XXXXXXX)" });
    }
    try {
        const code = await rs.socket.requestPairingCode(phone);
        rs.qrString = undefined;
        log.info({ sessionId: rs.id }, "[pair-code] issued");
        return res.json({ id: rs.id, name: rs.name, status: rs.status, code });
    }
    catch (err) {
        log.error({ err, sessionId: rs.id }, "[pair-code] request failed");
        return res.status(500).json({ error: "pair_code_failed" });
    }
}));
// Delete a session (stops engine, wipes local + persisted credentials).
app.delete("/api/sessions/:id", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    try {
        rs.stopRequested = true;
        // O1-M1 (R111): await any in-flight start BEFORE ending the socket —
        // the delete twin of the dashboard path above (socket not yet
        // assigned ⇒ end() no-ops and the detached start resurrects the
        // row). قبل الإنهاء يُنتظر البدء الجاري إن وُجد.
        await rs.starting?.catch(() => { });
        rs.socket?.end(undefined);
    }
    catch {
        // engine may already be dead
    }
    sessions.delete(rs.id);
    await fs.rm(`${DATA_DIR}/sessions/${rs.name}`, { recursive: true, force: true }).catch(() => { });
    await deletePersisted(rs.name);
    log.info({ sessionId: rs.id, name: rs.name }, "[session] deleted");
    return res.json({ deleted: true, id: rs.id });
}));
/**
 * Shared send path for send-text + test: validates input, detects self-send
 * (target digits === linked account digits) and routes the modern self-chat
 * via the account's LID — falling back to the plain PN JID when the LID form
 * fails. The REAL messageId from the engine's own sendMessage is recorded in
 * the delivery log so later acks are matched per message.
 * مسار الإرسال الموحّد — كشف self-send وتوجيه LID مع تسجيل معرف فعلي.
 */
async function engineSend(rs, chatIdRaw, text) {
    const sock = rs.socket;
    if (!sock || rs.status !== "ready") {
        return { ok: false, code: 409, error: "session_not_ready" };
    }
    const pnJid = normalizeChatId(chatIdRaw);
    if (!pnJid || !text || text.length > 4096) {
        return { ok: false, code: 400, error: "invalid chatId/text" };
    }
    const targetDigits = pnJid.slice(0, pnJid.indexOf("@"));
    const route = resolveSendJid(targetDigits, rs.accountDigits, rs.accountLidDigits, SELF_SEND_LID_ENABLED);
    if (route.viaLid) {
        log.info(
        // r98/98-F6 P3-3: digits masked in stdout; full values stay in the
        // delivery-log/API surfaces.
        { sessionId: rs.id, accountDigits: maskDigits(rs.accountDigits ?? ""), lid: maskDigits(rs.accountLidDigits ?? "") }, "[send] self-send detected — routing via LID (مسار المحادثة الذاتية)");
    }
    let messageId = null;
    let usedJid = route.jid;
    try {
        const msg = await sock.sendMessage(route.jid, { text });
        const id = msg?.key?.id;
        messageId = typeof id === "string" ? id : null;
    }
    catch (err) {
        if (!route.viaLid) {
            log.error({ err, sessionId: rs.id, chatId: maskDigits(targetDigits) }, "[send] failed");
            return { ok: false, code: 500, error: "send_failed" };
        }
        // LID self-send rejected — retry the legacy PN form before giving up.
        // فشل الإرسال بصيغة LID: إعادة المحاولة بصيغة رقم الهاتف الأصلية.
        log.warn({ err, sessionId: rs.id }, "[send] LID self-send failed — retrying via PN jid");
        try {
            const msg = await sock.sendMessage(route.pnJid, { text });
            const id = msg?.key?.id;
            messageId = typeof id === "string" ? id : null;
            usedJid = route.pnJid;
        }
        catch (err2) {
            log.error({ err: err2, sessionId: rs.id, chatId: maskDigits(targetDigits) }, "[send] PN retry failed too");
            return { ok: false, code: 500, error: "send_failed" };
        }
    }
    // Track the messageId the ENGINE generated — acks in messages.update are
    // matched against this, never against arbitrary fromMe traffic.
    // تسجيل معرف الرسالة الفعلي في سجل التسليم (حلقة بحد 500).
    if (messageId) {
        rs.deliveryLog = pushDeliveryLog(rs.deliveryLog ?? [], {
            messageId,
            chatId: usedJid,
            sentAt: new Date().toISOString(),
            timeline: [],
        });
    }
    log.info({
        sessionId: rs.id,
        // r98/98-F6 P3-3: stdout keeps the masked JID (last-4 digits +
        // domain); the FULL chatId is preserved in the delivery-log entry
        // above and the DB blob — only the log surface is redacted.
        chatId: maskJid(usedJid),
        selfSend: route.selfSend,
        viaLid: usedJid !== route.pnJid,
        messageId,
    }, "[send] delivered to engine");
    // Sending rotates sender-key material server-side; refreshing the
    // persisted snapshot here keeps restores decryptable (a stale snapshot
    // produced 'waiting for this message' after boot self-heal).
    rs.persistSnapshot?.();
    return { ok: true, messageId, selfSend: route.selfSend };
}
// Send text
app.post("/api/sessions/:id/messages/send-text", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    if (!rs.socket || rs.status !== "ready") {
        return res.status(409).json({ error: "session_not_ready", status: rs.status });
    }
    const out = await engineSend(rs, String(req.body?.chatId ?? ""), String(req.body?.text ?? ""));
    if (!out.ok) {
        return res.status(out.code).json({ error: out.error });
    }
    return res.json({
        ok: true,
        messageId: out.messageId,
        selfSend: out.selfSend,
        delivery: rs.lastDeliveryStatus ?? "pending",
    });
}));
// Live channel test: fixed text through the exact send-text logic (incl.
// self-send LID routing) and recorded in the delivery log.
// اختبار حي لقناة واتساب برسالة ثابتة — للتحقق من وصول الرسائل فعليًا.
const TEST_MESSAGE_TEXT = "🔧 رسالة اختبار من نظام SubNation — إن وصلتك هذه الرسالة فقناة واتساب تعمل بشكل سليم";
app.post("/api/sessions/:id/messages/test", asyncHandler(async (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    if (!rs.socket || rs.status !== "ready") {
        return res.status(409).json({ error: "session_not_ready", status: rs.status });
    }
    const out = await engineSend(rs, String(req.body?.chatId ?? ""), TEST_MESSAGE_TEXT);
    if (!out.ok) {
        return res.status(out.code).json({ error: out.error });
    }
    return res.json({ ok: true, messageId: out.messageId, selfSend: out.selfSend });
}));
// Outbound delivery log (ENGINE-sent messages only) — the OTP backend polls
// this to verify an OTP actually reached the device instead of guessing.
// سجل تسليم الرسائل الصادرة من المحرك فقط (حتى 500 رسالة).
app.get("/api/sessions/:id/delivery-log", (req, res) => {
    const rs = findOr404(req.params.id, res);
    if (!rs)
        return;
    return res.json({ deliveries: rs.deliveryLog ?? [] });
});
// JSON 404 for anything else under /api
app.use("/api", (_req, res) => res.status(404).json({ error: "not found" }));
// ── Terminal error middleware (r98/98-F6, P2-1) ─────────────────────────────
// Express 4 does NOT route async rejections anywhere: every async handler
// above is wrapped with asyncHandler (lib.ts) so an unexpected rejection
// becomes next(err) and lands HERE instead of leaving the request hanging
// forever (the process guard only LOGS unhandledRejection). Covers the
// dashboard router too: mountDashboard registers its routes on THIS app
// (no separate express instance), and requireAuth forwards `next` for
// exactly that reason. The body stays generic — the real error goes to
// pino, never to the response. headersSent → delegate to Express's default
// final handler (it safely destroys the stream).
app.use((err, _req, res, next) => {
    // O2-F6 (R111): body-parser rejections (the 256kb JSON limit) carry
    // statusCode 413 — the old blanket 500 misreported an oversized CLIENT
    // payload as a server fault. Honor the status code the error already
    // chose (httpErrorStatus: statusCode/status, sane 4xx/5xx only);
    // anything else stays a generic 500.
    const status = httpErrorStatus(err);
    log.error({ err, status }, "[http] unhandled error — answered generically");
    if (res.headersSent) {
        next(err);
        return;
    }
    res.status(status).json({ error: status === 413 ? "payload_too_large" : "internal" });
});
app.listen(PORT, "0.0.0.0", async () => {
    log.info({ port: PORT, dataDir: DATA_DIR }, "[gateway] listening");
    // ── Self-ping keep-alive — REMOVED (2026-09-20 free-infrastructure round)
    //
    // This block used to fetch our own PUBLIC /healthz every 4 minutes so
    // Render's free-tier idle timer never expired. That is artificial
    // traffic: it kept the gateway (and every dependency it touches)
    // awake 24/7 and burned the free quota the tier depends on.
    //
    // Accepted model now: the gateway SLEEPS when idle. The first real
    // WhatsApp request (OTP start / admin panel / readiness probe) wakes
    // it; the self-heal below then restores persisted sessions at boot,
    // so pairing survives spin-downs. /healthz stays lightweight (no DB,
    // no session side effects) so Render's health checks remain cheap.
    // Self-heal: auto-create + start every persisted session so a restart or
    // redeploy restores WhatsApp pairing without any operator action.
    if (!persistenceEnabled())
        return;
    try {
        const names = await listPersistedNames();
        for (const name of names) {
            if (findByName(name))
                continue;
            // O1-M2 (R111): names read from the DB get the SAME validation as
            // POST create + the dashboard (SESSION_NAME_RE). r110 hardened the
            // blob FILENAMES but not the name column, which is joined into
            // filesystem paths below — path.join normalizes `..` (verified →
            // /data/evil). Defense-in-depth (needs a DB write to exploit);
            // skip + warn mirrors the restore-path pattern. فحص اسم الجلسة
            // القادم من قاعدة البيانات قبل الاسترجاع الذاتي.
            if (!SESSION_NAME_RE.test(name)) {
                log.warn({ name: name.slice(0, 64) }, "[boot] persisted session name failed SESSION_NAME_RE — skipped (path-traversal guard)");
                continue;
            }
            const rs = {
                id: `sess_${nanoid(16)}`,
                name,
                status: "initializing",
                createdAt: new Date().toISOString(),
            };
            sessions.set(rs.id, rs);
            // P2-2 single-flight: a manual /start or dash start racing the boot
            // restore awaits the SAME in-flight start, never a second socket.
            await beginSessionStart(rs, () => startSession(rs)).catch((err) => {
                // O2-F2 (R111): land on "failed" (same as the /start route) — the
                // boot loop must never leave a permanently-"initializing" session.
                rs.status = "failed";
                log.error({ err, name }, "[boot] auto-restore failed");
            });
            log.info({ name }, "[boot] session restored from persistence");
        }
    }
    catch (err) {
        log.warn({ err }, "[boot] persistence scan failed");
    }
});
// ── Last-resort process guards ────────────────────────────────────────────────
// A throw inside a Baileys event callback must never take the whole gateway
// (and every live WhatsApp session) down. Log loudly and keep serving.
process.on("uncaughtException", (err) => {
    log.error({ err }, "[process] uncaughtException — keeping the process alive");
});
process.on("unhandledRejection", (reason) => {
    log.error({ reason: String(reason) }, "[process] unhandledRejection — keeping the process alive");
});
// ── Graceful shutdown: final persistence flush ────────────────────────────
// The orchestrator (Docker/Coolify) sends SIGTERM before stopping the
// container (stop / redeploy).
// Pending debounced saves (300ms / 3s) would die with the process, so the
// next boot would restore a STALE snapshot → decryption failures on the
// phone ("Waiting for this message"). Flush every ready session now, then
// exit cleanly.
// تدفّق نهائي عند الإيقاف: حفظ كل جلسة جاهزة قبل الخروج.
// O2-F5 (R111): budget 10s (the compose SIGTERM grace is 15s — this stays
// under it with room for exit overhead) and each flush's OWN upsert runs
// with a 3s transaction-local statement_timeout (persist.ts flushNow), so
// a single stuck write cannot eat the whole budget. The old 4s budget
// lost the race against the pool-level 10s statement_timeout: a flush
// queued behind a stuck upsert simply never ran.
let isShuttingDown = false;
const SHUTDOWN_FLUSH_BUDGET_MS = 10_000;
async function shutdownFlush(signal) {
    if (isShuttingDown)
        return; // a second signal must never double-flush
    isShuttingDown = true;
    const ready = [...sessions.values()].filter((s) => s.status === "ready" && s.persistFlush);
    log.info({ signal, sessions: ready.length, budgetMs: SHUTDOWN_FLUSH_BUDGET_MS }, "[shutdown] flushing persisted credentials before exit");
    const flushes = ready.map((s) => s.persistFlush());
    const budget = new Promise((resolve) => setTimeout(resolve, SHUTDOWN_FLUSH_BUDGET_MS));
    try {
        await Promise.race([Promise.all(flushes), budget]);
    }
    catch (err) {
        log.warn({ err }, "[shutdown] flush error — exiting anyway");
    }
    log.info({ signal }, "[shutdown] flush complete — exiting");
    process.exit(0);
}
process.on("SIGTERM", () => void shutdownFlush("SIGTERM"));
process.on("SIGINT", () => void shutdownFlush("SIGINT"));
