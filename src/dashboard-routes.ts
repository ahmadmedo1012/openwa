/**
 * Dashboard router + HTML — see src/dashboard.ts for the auth core.
 *
 * Exposed routes (all cookie-authenticated except /login):
 *   GET    /                      → login page or dashboard
 *   POST   /login                 → form login (rate-limited + lockout)
 *   POST   /logout                → clears cookie
 *   GET    /dash/api/state        → { sessions, info } (polled by the UI)
 *   POST   /dash/api/sessions     → create {name}
 *   POST   /dash/api/sessions/:id/start
 *   POST   /dash/api/sessions/:id/pair-code  {phone}
 *   GET    /dash/api/sessions/:id/qr         → {qrImage,status}
 *   DELETE /dash/api/sessions/:id
 *
 * The registry + engine functions are injected by index.ts so this file
 * never imports the engine directly (no cycles, testable in isolation).
 */
import express from "express";
import { dashboardPage, disabledPage, loginPage } from "./dashboard-html.js";
import {
  dashboardEnabled,
  issueToken,
  verifyToken,
  isLocked,
  recordFailure,
  clearFailures,
  credentialsOk,
  cookieOptions,
  clientIp,
  escapeHtml,
  jsonSafeDate,
  COOKIE_NAME,
} from "./dashboard.js";

export interface DashboardSessionView {
  id: string;
  name: string;
  status: string;
  createdAt: string;
  lastReadyAt?: string;
  lastDeliveryStatus?: string;
  /** Linked-account identity (enriched view). هوية الحساب المرتبط. */
  accountDigits?: string;
  accountName?: string;
  /** Timestamp of the CURRENT open. وقت الاتصال الحالي. */
  connectedAt?: string;
  /** ms since the last persisted snapshot (null = never). عمر آخر لقطة. */
  persistAgeMs?: number;
  /** Runtime hooks provided by index.ts (structural, no import cycle). */
  start(): Promise<void>;
  requestPairCode(phone: string): Promise<string>;
  qrString(): string | null;
  delete(): Promise<void>;
}

export interface DashboardDeps {
  sessions: () => DashboardSessionView[];
  info: () => { uptimeSec: number; persist: boolean; version: string };
  /** Engine-owned session creation (name validated by the caller). */
  createSession: (
    name: string,
  ) => Promise<
    | { id: string; name: string; status: string; createdAt: string }
    | { error: string; conflict?: boolean }
  >;
}

type Handler = (req: express.Request, res: express.Response) => void | Promise<void>;

/** Wrap a handler so it requires a valid session cookie. */
function requireAuth(handler: Handler): Handler {
  return (req, res) => {
    if (!verifyToken(req.cookies?.[COOKIE_NAME])) {
      if (req.path.startsWith("/dash/api/")) {
        res.status(401).json({ error: "unauthorized" });
        return;
      }
      res.redirect("/");
      return;
    }
    return handler(req, res);
  };
}

export function mountDashboard(app: express.Express, deps: DashboardDeps): void {
  // Bare-bones cookie parsing (no dependency needed) — only for the
  // dashboard cookie. Values are base64url + signature, no separators.
  app.use((req, _res, next) => {
    const header = req.header("cookie") ?? "";
    const jar: Record<string, string> = {};
    for (const part of header.split(";")) {
      const eq = part.indexOf("=");
      if (eq <= 0) continue;
      const k = part.slice(0, eq).trim();
      const v = part.slice(eq + 1).trim();
      if (!k || !v) continue;
      // SEC1/P2-1: a malformed percent-escape (Cookie: x=%) crashed
      // decodeURIComponent → 500 on EVERY route including the key-gated
      // /api surface. Malformed values fall through raw — the signed
      // token verification rejects them anyway.
      try {
        jar[k] = decodeURIComponent(v);
      } catch {
        jar[k] = v;
      }
    }
    (req as express.Request & { cookies?: Record<string, string> }).cookies = jar;
    next();
  });

  // Login form target
  app.post(
    "/login",
    express.urlencoded({ limit: "16kb", extended: false }),
    (req, res) => {
      if (!dashboardEnabled()) {
        res.status(503).send("dashboard disabled");
        return;
      }
      const ip = clientIp(req);
      if (isLocked(ip)) {
        res.status(429).type("html").send(loginPage("تم القفل مؤقتًا بعد محاولات خاطئة متكررة — انتظر 15 دقيقة"));
        return;
      }
      const username = String(req.body?.username ?? "");
      const password = String(req.body?.password ?? "");
      if (!credentialsOk(username, password)) {
        recordFailure(ip);
        // Log without the submitted values.
        console.warn(JSON.stringify({ level: "warn", dashboard: "login_failed", ip }));
        res.status(401).type("html").send(loginPage("بيانات الدخول غير صحيحة"));
        return;
      }
      clearFailures(ip);
      res.cookie(COOKIE_NAME, issueToken(), cookieOptions());
      res.redirect("/");
    },
  );

  app.get("/", (req, res) => {
    if (!dashboardEnabled()) {
      res.status(404).type("html").send(disabledPage());
      return;
    }
    if (!verifyToken((req as express.Request & { cookies?: Record<string, string> }).cookies?.[COOKIE_NAME])) {
      res.status(200).type("html").send(loginPage());
      return;
    }
    res.status(200).type("html").send(dashboardPage());
  });

  app.post("/logout", (req, res) => {
    res.clearCookie(COOKIE_NAME, { ...cookieOptions(), maxAge: 0 });
    res.redirect("/");
  });

  const json = (res: express.Response, code: number, body: unknown) => {
    res.status(code).json(body);
  };

  app.get("/dash/api/state", requireAuth((_req, res) => {
    const sessions = deps.sessions().map((s) => ({
      id: s.id,
      name: s.name,
      status: s.status,
      createdAt: jsonSafeDate(s.createdAt),
      lastReadyAt: s.lastReadyAt ? jsonSafeDate(s.lastReadyAt) : null,
      lastDeliveryStatus: s.lastDeliveryStatus ?? null,
      accountDigits: s.accountDigits ?? null,
      accountName: s.accountName ?? null,
      connectedAt: s.connectedAt ? jsonSafeDate(s.connectedAt) : null,
      persistAgeMs: s.persistAgeMs ?? null,
    }));
    json(res, 200, { sessions, info: deps.info() });
  }));

  app.post("/dash/api/sessions", requireAuth(async (req, res) => {
    const name = String(req.body?.name ?? "").trim();
    if (!/^[A-Za-z0-9-]{3,50}$/.test(name)) {
      json(res, 400, { error: "الاسم يجب أن يكون 3–50 حرفًا إنجليزيًا/رقمًا/شرطة" });
      return;
    }
    // Delegate creation to the engine's create path (name already validated).
    const created = await deps.createSession(name);
    if ("error" in created) {
      json(res, created.conflict ? 409 : 500, { error: created.error });
      return;
    }
    json(res, 201, { session: created });
  }));

  app.post("/dash/api/sessions/:id/start", requireAuth(async (req, res) => {
    const s = deps.sessions().find((x) => x.id === req.params.id);
    if (!s) {
      json(res, 404, { error: "الجلسة غير موجودة" });
      return;
    }
    try {
      await s.start();
      json(res, 200, { ok: true });
    } catch {
      json(res, 500, { error: "تعذر تشغيل الجلسة" });
    }
  }));

  app.post("/dash/api/sessions/:id/pair-code", requireAuth(async (req, res) => {
    const s = deps.sessions().find((x) => x.id === req.params.id);
    if (!s) {
      json(res, 404, { error: "الجلسة غير موجودة" });
      return;
    }
    const phone = String(req.body?.phone ?? "").replace(/[^0-9]/g, "");
    if (phone.length < 10 || phone.length > 15) {
      json(res, 400, { error: "أدخل رقمًا دوليًا صحيحًا مثل 21891XXXXXXX" });
      return;
    }
    try {
      const code = await s.requestPairCode(phone);
      json(res, 200, { code });
    } catch {
      json(res, 502, { error: "تعذر إصدار رمز الربط — تأكد أن الجلسة قيد التشغيل ثم أعد المحاولة" });
    }
  }));

  app.get("/dash/api/sessions/:id/qr", requireAuth(async (req, res) => {
    const s = deps.sessions().find((x) => x.id === req.params.id);
    if (!s) {
      json(res, 404, { error: "الجلسة غير موجودة" });
      return;
    }
    const QRCode = await import("qrcode");
    const raw = s.qrString();
    if (!raw) {
      json(res, 200, { qrImage: null, status: s.status });
      return;
    }
    const qrImage = await QRCode.toDataURL(raw, { margin: 2, width: 320 });
    json(res, 200, { qrImage, status: s.status });
  }));

  app.delete("/dash/api/sessions/:id", requireAuth(async (req, res) => {
    const s = deps.sessions().find((x) => x.id === req.params.id);
    if (!s) {
      json(res, 404, { error: "الجلسة غير موجودة" });
      return;
    }
    try {
      await s.delete();
      json(res, 200, { ok: true });
    } catch {
      json(res, 500, { error: "تعذر حذف الجلسة" });
    }
  }));
}
