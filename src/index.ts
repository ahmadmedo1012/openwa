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
 *     POST /api/sessions/{id}/messages/send-text {chatId,text}
 *     GET  /api/sessions/{id}/contacts/check/{number} → {exists:boolean}
 *
 *   Lifecycle: created → initializing → qr_ready → authenticating →
 *              ready → (disconnected ⇄ reconnect) | failed
 *
 * Session credentials persist under DATA_DIR/<name>/ so a scanned QR
 * survives process restarts and redeploys (attach a Render disk).
 */
import express from "express";
import pino from "pino";
import {
  makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  DisconnectReason,
  type WASocket,
} from "@whiskeysockets/baileys";
import { nanoid } from "nanoid";
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  persistenceEnabled,
  scheduleSave,
  loadCreds,
  listPersistedNames,
  deletePersisted,
} from "./persist.js";

const log = pino({ level: process.env.LOG_LEVEL ?? "info" });

const PORT = Number(process.env.PORT ?? 2785);
const API_KEY = (process.env.OPENWA_API_KEY ?? "").trim();
const DATA_DIR = (process.env.DATA_DIR ?? "/data").replace(/\/+$/, "");
if (!API_KEY) {
  log.error("OPENWA_API_KEY is required — refusing to start (refusing an open relay)");
  process.exit(1);
}

// ── Types ────────────────────────────────────────────────────────────────────

type SessionStatus =
  | "created"
  | "initializing"
  | "qr_ready"
  | "authenticating"
  | "ready"
  | "disconnected"
  | "failed";

interface SessionRecord {
  id: string;
  name: string;
  status: SessionStatus;
  createdAt: string;
  lastReadyAt?: string;
}

interface RuntimeSession extends SessionRecord {
  socket?: WASocket;
  qrString?: string;
  stopRequested?: boolean;
  persistSnapshot?: () => void;
}

const SESSION_NAME_RE = /^[A-Za-z0-9-]{3,50}$/;

// ── Registry ─────────────────────────────────────────────────────────────────

const sessions = new Map<string, RuntimeSession>(); // by id

function publicView(s: RuntimeSession): SessionRecord {
  return {
    id: s.id,
    name: s.name,
    status: s.status,
    createdAt: s.createdAt,
    ...(s.lastReadyAt ? { lastReadyAt: s.lastReadyAt } : {}),
  };
}

function findByName(name: string): RuntimeSession | undefined {
  return [...sessions.values()].find((s) => s.name === name);
}

// ── Socket wiring ────────────────────────────────────────────────────────────

async function startSession(rs: RuntimeSession): Promise<void> {
  rs.stopRequested = false;
  rs.qrString = undefined;

  // Restore persisted credentials (if any) into the auth folder BEFORE the
  // engine reads it — this is what makes restarts/deploy self-healing.
  if (persistenceEnabled()) {
    try {
      const dir = `${DATA_DIR}/sessions/${rs.name}`;
      const existing = await fs.readdir(dir).catch(() => [] as string[]);
      const hasCreds = existing.includes("creds.json");
      if (!hasCreds) {
        const blob = await loadCreds(rs.name);
        if (blob) {
          await fs.mkdir(dir, { recursive: true });
          const creds = JSON.parse(blob) as Record<string, unknown>;
          for (const [fname, content] of Object.entries(creds)) {
            await fs.writeFile(
              path.join(dir, fname),
              typeof content === "string" ? content : JSON.stringify(content),
            );
          }
          log.info({ sessionId: rs.id, name: rs.name }, "[persist] credentials restored from DB");
        }
      }
    } catch (err) {
      log.warn({ err, name: rs.name }, "[persist] restore failed — continuing fresh");
    }
  }

  const { state, saveCreds } = await useMultiFileAuthState(`${DATA_DIR}/sessions/${rs.name}`);
  let version: [number, number, number] | undefined;
  try {
    const latest = await fetchLatestBaileysVersion();
    version = latest.version;
  } catch {
    // offline registry / transient — baileys falls back to its baked-in version
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

  const persistSnapshot = (): void => {
    if (!persistenceEnabled() || !rs.lastReadyAt) return;
    scheduleSave(rs.name, async () => {
      const dir = `${DATA_DIR}/sessions/${rs.name}`;
      const files = await fs.readdir(dir);
      const out: Record<string, string> = {};
      for (const f of files) {
        out[f] = await fs.readFile(path.join(dir, f), "utf8");
      }
      return JSON.stringify(out);
    });
  };
  rs.persistSnapshot = persistSnapshot;

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
      if (rs.status !== "qr_ready") rs.status = "initializing";
      return;
    }

    if (connection === "open") {
      rs.status = "ready";
      rs.qrString = undefined;
      rs.lastReadyAt = new Date().toISOString();
      log.info({ sessionId: rs.id, name: rs.name }, "[session] connected (ready)");
      return;
    }

    if (connection === "close") {
      const code = (lastDisconnect?.error as { output?: { statusCode?: number } } | undefined)
        ?.output?.statusCode;
      const loggedOut = code === DisconnectReason.loggedOut;

      if (loggedOut || rs.stopRequested) {
        // Pairing revoked (device logged out elsewhere) — credentials are
        // dead. Wipe so the next start issues a fresh QR.
        rs.status = "failed";
        rs.socket = undefined;
        log.warn({ sessionId: rs.id, name: rs.name, loggedOut }, "[session] closed permanently");
        void restartable(rs);
        return;
      }

      rs.status = "disconnected";
      rs.socket = undefined;
      log.info({ sessionId: rs.id, name: rs.name, code }, "[session] disconnected — will restart on demand");
      // Auto-reconnect with backoff unless explicitly stopped.
      setTimeout(() => {
        const cur = sessions.get(rs.id);
        if (cur && !cur.stopRequested && cur.status === "disconnected") {
          cur.status = "initializing";
          void startSession(cur).catch((err) =>
            log.error({ err, sessionId: rs.id }, "[session] reconnect failed"),
          );
        }
      }, 5_000);
    }
  });
}

/** Wipe stored credentials so the next start() produces a fresh QR. */
async function restartable(rs: RuntimeSession): Promise<void> {
  try {
    const fs = await import("node:fs/promises");
    await fs.rm(`${DATA_DIR}/sessions/${rs.name}`, { recursive: true, force: true });
  } catch {
    // best-effort
  }
}

/** Heuristic: does the auth store look previously-paired? */
function hasStoredCreds(state: unknown): boolean {
  try {
    const s = state as { creds?: { registered?: boolean } };
    return Boolean(s?.creds?.registered);
  } catch {
    return false;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function requireKey(req: express.Request, res: express.Response): boolean {
  if ((req.header("x-api-key") ?? "") !== API_KEY) {
    res.status(401).json({ error: "invalid or missing X-API-Key" });
    return false;
  }
  return true;
}

/** `218913456789@c.us` | `218913456789@s.whatsapp.net` | bare digits → normalized JID. */
function normalizeChatId(raw: string): string | null {
  const digits = raw.replace(/[^0-9]/g, "");
  return digits.length >= 8 && digits.length <= 15 ? `${digits}@s.whatsapp.net` : null;
}

function findOr404(id: string, res: express.Response): RuntimeSession | undefined {
  const rs = sessions.get(id);
  if (!rs) res.status(404).json({ error: "session not found" });
  return rs;
}

// ── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: "256kb" }));

app.get("/healthz", (_req, res) => {
  const ready = [...sessions.values()].filter((s) => s.status === "ready").length;
  res.json({ ok: true, sessions: sessions.size, ready });
});

app.use("/api", (req, res, next) => {
  if (!requireKey(req, res)) return;
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
      "POST   /api/sessions/{id}/messages/send-text   body: {chatId,text}",
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
app.post("/api/sessions", async (req, res) => {
  const name = String(req.body?.name ?? "").trim();
  if (!SESSION_NAME_RE.test(name)) {
    return res.status(400).json({ error: "name must match [A-Za-z0-9-]{3,50}" });
  }
  if (findByName(name)) {
    return res.status(409).json({ error: "session name already exists" });
  }
  const rs: RuntimeSession = {
    id: `sess_${nanoid(16)}`,
    name,
    status: "created",
    createdAt: new Date().toISOString(),
  };
  sessions.set(rs.id, rs);
  log.info({ sessionId: rs.id, name }, "[session] created");
  return res.status(201).json(publicView(rs));
});

// Get one session
app.get("/api/sessions/:id", (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
  return res.json(publicView(rs));
});

// Start (or restart) a session
app.post("/api/sessions/:id/start", async (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
  if (rs.socket) {
    return res.json(publicView(rs)); // already running
  }
  rs.status = rs.status === "created" ? "initializing" : rs.status;
  res.json(publicView(rs)); // respond immediately; status advances via events
  try {
    await startSession(rs);
  } catch (err) {
    rs.status = "failed";
    log.error({ err, sessionId: rs.id }, "[session] start failed");
  }
});

// Operator QR page — renders the current pairing QR as PNG in a minimal
// auto-refreshing HTML page (also serves plain JSON when requested as such).
app.get("/api/sessions/:id/qr", async (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
  const wantsHtml = String(req.header("accept") ?? "").includes("text/html");
  if (!rs.qrString) {
    const body = { id: rs.id, name: rs.name, status: rs.status, qr: null };
    if (wantsHtml) {
      return res
        .status(200)
        .type("html")
        .send(
          `<meta http-equiv="refresh" content="3"><body style="font-family:sans-serif;background:#0b141a;color:#fff;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><p>الحالة: <b>${rs.status}</b></p><p>${
            rs.status === "ready"
              ? "✅ الجلسة جاهزة — يمكنك إغلاق الصفحة"
              : "لا يوجد QR حالياً… تحديث تلقائي كل 3 ثوانٍ"
          }</p></div></body>`,
        );
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
    .send(
      `<meta http-equiv="refresh" content="20"><body style="font-family:sans-serif;background:#0b141a;color:#fff;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><h2>@${rs.name}</h2><img alt="QR" src="${dataUrl}" width="320" height="320"><p>WhatsApp ← الأجهزة المرتبطة ← ربط جهاز</p><p>تحديث تلقائي كل 20 ثانية</p><p>الحالة: <b>${rs.status}</b></p></div></body>`,
    );
});

// Preflight number check (also warms Baileys' LID cache before send-text).
app.get("/api/sessions/:id/contacts/check/:number", async (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
  if (!rs.socket || rs.status !== "ready") {
    return res.status(409).json({ error: "session_not_ready", status: rs.status });
  }
  const digits = req.params.number.replace(/[^0-9]/g, "");
  try {
    const result = await rs.socket.onWhatsApp(digits);
    const exists = Array.isArray(result) && result[0]?.exists === true;
    return res.json({ exists });
  } catch (err) {
    log.warn({ err, sessionId: rs.id }, "[contacts/check] failed");
    return res.status(500).json({ error: "check_failed" });
  }
});

// Request a phone-number pairing code (the reliable alternative to QR:
// no rotation timing, entered manually on the phone under
// Linked devices → "Link with phone number instead").
app.post("/api/sessions/:id/pair-code", async (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
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
  } catch (err) {
    log.error({ err, sessionId: rs.id }, "[pair-code] request failed");
    return res.status(500).json({ error: "pair_code_failed" });
  }
});

// Delete a session (stops engine, wipes local + persisted credentials).
app.delete("/api/sessions/:id", async (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
  try {
    rs.stopRequested = true;
    rs.socket?.end(undefined);
  } catch {
    // engine may already be dead
  }
  sessions.delete(rs.id);
  await fs.rm(`${DATA_DIR}/sessions/${rs.name}`, { recursive: true, force: true }).catch(() => {});
  deletePersisted(rs.name);
  log.info({ sessionId: rs.id, name: rs.name }, "[session] deleted");
  return res.json({ deleted: true, id: rs.id });
});

// Send text
app.post("/api/sessions/:id/messages/send-text", async (req, res) => {
  const rs = findOr404(req.params.id, res);
  if (!rs) return;
  if (!rs.socket || rs.status !== "ready") {
    return res.status(409).json({ error: "session_not_ready", status: rs.status });
  }
  const chatIdRaw = String(req.body?.chatId ?? "");
  const text = String(req.body?.text ?? "");
  const jid = normalizeChatId(chatIdRaw);
  if (!jid || !text || text.length > 4096) {
    return res.status(400).json({ error: "invalid chatId/text" });
  }
  try {
    await rs.socket.sendMessage(jid, { text });
    log.info({ sessionId: rs.id, chatId: jid.slice(0, jid.indexOf("@")) + "@…" }, "[send-text] delivered to engine");
    // Sending rotates sender-key material server-side; refreshing the
    // persisted snapshot here keeps restores decryptable (a stale snapshot
    // produced 'waiting for this message' after boot self-heal).
    rs.persistSnapshot?.();
    return res.json({ ok: true });
  } catch (err) {
    log.error({ err, sessionId: rs.id }, "[send-text] failed");
    return res.status(500).json({ error: "send_failed" });
  }
});

// JSON 404 for anything else under /api
app.use("/api", (_req, res) => res.status(404).json({ error: "not found" }));

app.listen(PORT, "0.0.0.0", async () => {
  log.info({ port: PORT, dataDir: DATA_DIR }, "[gateway] listening");

  // ── Self-ping keep-alive ────────────────────────────────────────────────
  // Free-tier instances idle-spin after ~15 min without INBOUND traffic,
  // which wipes the in-memory session registry. GitHub-cron pings proved
  // unreliable (jitter 30-55 min). A request to our own PUBLIC URL crosses
  // Render's router and counts as real traffic — deterministic heartbeat.
  const publicUrl = (process.env.RENDER_EXTERNAL_URL ?? "").replace(/\/+$/, "");
  if (publicUrl) {
    const PING_MS = 4 * 60 * 1000;
    setInterval(() => {
      fetch(`${publicUrl}/healthz`, { signal: AbortSignal.timeout(10_000) })
        .then((r) => log.debug({ status: r.status }, "[keep-alive] self-ping"))
        .catch((err) => log.warn({ err }, "[keep-alive] self-ping failed"));
    }, PING_MS);
    log.info({ publicUrl, everyMs: PING_MS }, "[keep-alive] self-ping armed");
  }

  // Self-heal: auto-create + start every persisted session so a restart or
  // redeploy restores WhatsApp pairing without any operator action.
  if (!persistenceEnabled()) return;
  try {
    const names = await listPersistedNames();
    for (const name of names) {
      if (findByName(name)) continue;
      const rs: RuntimeSession = {
        id: `sess_${nanoid(16)}`,
        name,
        status: "initializing",
        createdAt: new Date().toISOString(),
      };
      sessions.set(rs.id, rs);
      await startSession(rs).catch((err) =>
        log.error({ err, name }, "[boot] auto-restore failed"),
      );
      log.info({ name }, "[boot] session restored from persistence");
    }
  } catch (err) {
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
