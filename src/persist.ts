/**
 * Postgres-backed credential persistence for WhatsApp sessions.
 *
 * Free-tier Render instances are ephemeral: any restart/deploy wipes the
 * local Baileys auth folder AND the in-memory registry, forcing a fresh QR
 * scan. Persisting the (encrypted) credentials blob in the app's Neon
 * database lets every boot restore previously-paired sessions automatically.
 *
 * Security (2026-09-20 final audit — key separation): credentials are
 * AES-256-GCM encrypted with a key derived via scrypt. The key material
 * prefers the dedicated OPENWA_CREDENTIALS_KEY env var; when unset it
 * falls back to OPENWA_API_KEY (the original derivation — byte-identical,
 * so existing persisted blobs decrypt with ZERO migration). Splitting the
 * two concerns means rotating the API key (request auth) no longer
 * invalidates every stored session, and a leaked API key alone can no
 * longer decrypt the credential blobs.
 *
 * Transparent re-key: when OPENWA_CREDENTIALS_KEY is set (and differs
 * from the API key), a blob that fails to decrypt with the current key is
 * retried with the legacy API-key derivation; on success the plaintext is
 * re-encrypted with the current key and re-stored immediately. The
 * WA-02 wipe tombstone is respected (a wiped name is never resurrected).
 * The DB stores ciphertext only.
 */
import { Pool } from "pg";
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import pino from "pino";

const log = pino({ level: process.env.LOG_LEVEL ?? "info" });

const PERSISTENCE_URL = (process.env.PERSISTENCE_URL ?? "").trim();
const API_KEY = (process.env.OPENWA_API_KEY ?? "").trim();
/**
 * Dedicated credentials-encryption secret. Empty (unset) keeps the exact
 * pre-2026-09-20 behaviour: credentials key == API key.
 */
const CREDENTIALS_KEY = (process.env.OPENWA_CREDENTIALS_KEY ?? "").trim();

if (CREDENTIALS_KEY && CREDENTIALS_KEY.length < 32) {
  log.warn(
    { length: CREDENTIALS_KEY.length },
    "[persist] OPENWA_CREDENTIALS_KEY is shorter than 32 chars — recommended: openssl rand -hex 32",
  );
}

let pool: Pool | null = null;

/** Effective key material for credentials encryption. */
function credentialsKeyMaterial(): string {
  return CREDENTIALS_KEY || API_KEY;
}

/**
 * True when a DEDICATED credentials key is active and differs from the
 * API key — i.e. blobs written before the split still decrypt with the
 * legacy derivation and may need the transparent re-key path.
 */
function legacyKeyAvailable(): boolean {
  return Boolean(CREDENTIALS_KEY && CREDENTIALS_KEY !== API_KEY);
}

// Memoized derivations (2026-09-20 final audit): scryptSync is expensive
// (~50-100 ms per call) and ran on EVERY encrypt/decrypt — the debounced
// write-through saves every few seconds. Same memoization discipline as
// dashboard.ts sessionSecret (SEC1/P1-2).
const keyCache = new Map<string, Buffer>();
function deriveKey(material: string): Buffer {
  let k = keyCache.get(material);
  if (!k) {
    k = scryptSync(material, "openwa-gateway-creds-v1", 32);
    keyCache.set(material, k);
  }
  return k;
}

function key(): Buffer {
  return deriveKey(credentialsKeyMaterial());
}

function encrypt(plain: string): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}

/** Decrypt with an EXPLICIT key (current or legacy). Throws on wrong key. */
function decryptWith(blob: Buffer, k: Buffer): string {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const data = blob.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", k, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

function decrypt(blob: Buffer): string {
  return decryptWith(blob, key());
}

async function ensurePool(): Promise<Pool | null> {
  if (!PERSISTENCE_URL || !API_KEY) return null;
  if (!pool) {
    // FH-A5 P3-1 (Neon autosuspend hygiene): an idle client killed by a TCP
    // reset or a Neon suspend race surfaces as a pool 'error' event — without
    // a listener it escapes as an uncaughtException (process-level guard logs
    // it, but as a crash-look-alike). Logging here keeps the signal clean and
    // lets the pool replace the dead client on the next acquire.
    // statement_timeout 10s: every query here is a single-row upsert/select
    // against a tiny table (slowest legitimate case ≈ boot DDL on a cold,
    // just-woken Neon ~2s) — 10s is comfortable headroom while guaranteeing a
    // hung query can never pin one of only 2 clients. idleTimeout 30s ≪
    // Neon's ~5-min autosuspend closes idle clients proactively; keepalives
    // keep a live connection from being silently dropped mid-flight.
    // connectionTimeoutMillis 10s (110-K, 109-e P3; pg default = NO timeout):
    // a hung CONNECT (DNS blackhole, silently-dropped SYN) must never pin
    // one of only 2 clients for the process lifetime — 10s matches the
    // statement_timeout scale, and a legitimate cold-Neon connect (~2s)
    // keeps comfortable headroom.
    pool = new Pool({
      connectionString: PERSISTENCE_URL,
      max: 2,
      connectionTimeoutMillis: 10_000,
      statement_timeout: 10_000,
      idleTimeoutMillis: 30_000,
      keepAlive: true,
      keepAliveInitialDelayMillis: 30_000,
    });
    pool.on("error", (err) => {
      log.error({ err }, "[persist] pool error (idle client dropped? pool will recover)");
    });
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

export function persistenceEnabled(): boolean {
  return Boolean(PERSISTENCE_URL && API_KEY);
}

/** ms since the last SUCCESSFUL save of a session (null = never saved). */
const lastSavedAt = new Map<string, number>();

/**
 * WA-02 resurrection guard: timestamp of the LAST credentials wipe per
 * session name. A save that STARTED before a wipe (pending debounce or
 * an in-flight flushNow) must never upsert AFTER it — the async wipe and
 * a slow save can otherwise land out of order and resurrect dead creds
 * in the DB. Timestamp comparison (>= start-of-save) keeps a legitimate
 * save from a LATER re-pair working untouched.
 * شاهد قبر يمنع إنعاش بيانات اعتماد ميتة بعد المسح.
 */
const wipedAt = new Map<string, number>();

/**
 * WA-02 write serialization (110-K, closes the guard2→upsert window): a
 * per-name FIFO promise chain for every DB mutation (save upsert, wipe
 * DELETE). Node's single thread interleaves async operations at await
 * points — WITHOUT the chain, a save that had already passed both
 * tombstone guards could still land its upsert AFTER a wipe's DELETE
 * completed (the await between guard2 and the upsert is the window; a
 * cold just-woken Neon can park an upsert for seconds) and resurrect the
 * dead row. WITH the chain, the DELETE queues behind the in-flight
 * upsert and lands last — the wipe ALWAYS wins. The tombstone guards
 * above stay: they kill saves that were only REQUESTED before the wipe
 * without wasting a query. (The legacy re-key path needs no chain — it
 * is a plain `UPDATE … WHERE name = $1`, which can never re-INSERT a
 * deleted row; pinned by a test.)
 * سلسلة وعود لكل اسم: المسح ينتصر دائمًا على الحفظ المتقادم.
 */
const writeChains = new Map<string, Promise<void>>();

function orderedWrites<T>(name: string, op: () => Promise<T>): Promise<T> {
  const prev = writeChains.get(name) ?? Promise.resolve();
  const run = prev.then(op, op); // run even if the previous op rejected
  // The chain tail never rejects (later ops must always run); the map
  // entry is dropped once nothing newer queued behind it — bounded map
  // across many delete/re-pair cycles, same discipline as the wipedAt
  // tombstone pruning.
  const tail: Promise<void> = run.then(
    () => {
      if (writeChains.get(name) === tail) writeChains.delete(name);
    },
    () => {
      if (writeChains.get(name) === tail) writeChains.delete(name);
    },
  );
  writeChains.set(name, tail);
  return run;
}

/**
 * The single upsert every save path lands (debounced background saves AND
 * the bounded flush path below share it — the WA-02 chain + tombstone
 * guards around it are what keep a wipe always winning).
 * الإدراج-التحديث الموحّد لكل مسارات الحفظ.
 */
const UPSERT_SQL = `
  INSERT INTO openwa_sessions (name, creds, updated_at)
  VALUES ($1, $2, NOW())
  ON CONFLICT (name) DO UPDATE SET creds = $2, updated_at = NOW()`;

/** Core save: serialize + encrypted upsert + bookkeeping. جوهر الحفظ. */
async function doSave(
  name: string,
  serialize: () => Promise<string>,
  opts: { flushStatementTimeoutMs?: number } = {},
): Promise<void> {
  // 110-K: startedAt + the chain entry are captured SYNCHRONOUSLY at
  // request time (pre-await) so that (a) the WA-02 tombstone comparison
  // anchors to the request instant, and (b) per-name DB mutations
  // strictly follow CALL order — a wipe issued later can never be
  // overtaken by this save's upsert.
  const startedAt = Date.now();
  await orderedWrites(name, async () => {
    const p = await ensurePool();
    if (!p) return;
    // Guard (pre-serialize): a wipe that already landed kills this save.
    const wipe1 = wipedAt.get(name);
    if (wipe1 != null && wipe1 >= startedAt) return;
    const json = await serialize();
    // Guard (post-serialize): the folder read above may have raced a wipe.
    const wipe2 = wipedAt.get(name);
    if (wipe2 != null && wipe2 >= startedAt) return;
    if (opts.flushStatementTimeoutMs != null) {
      // O2-F5 (R111): bounded flush — the flush path (SIGTERM/SIGINT + the
      // disconnect snapshot) runs its upsert on a DEDICATED client inside a
      // transaction with a transaction-local statement_timeout, so a stuck
      // write fails fast instead of eating the whole shutdown budget (the
      // pool-level 10s is larger than it). SET LOCAL cannot leak past the
      // COMMIT/ROLLBACK to other pooled queries. حد أقصى 3 ثوان لاستعلام
      // التدفّق النهائي داخل معاملة محلية.
      const client = await p.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `SET LOCAL statement_timeout = ${Math.floor(opts.flushStatementTimeoutMs)}`,
        );
        await client.query(UPSERT_SQL, [name, encrypt(json)]);
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK").catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    } else {
      await p.query(UPSERT_SQL, [name, encrypt(json)]);
    }
    lastSavedAt.set(name, Date.now());
    log.info({ name }, "[persist] credentials saved");
  });
}

/**
 * Debounced save of one session's serialized auth state.
 * `delayMs` is variable: signal-store write-through uses a fast 300ms,
 * the legacy creds path keeps the relaxed 3s default.
 */
const pending = new Map<string, ReturnType<typeof setTimeout>>();

export function scheduleSave(
  name: string,
  serialize: () => Promise<string>,
  delayMs = 3_000,
): void {
  if (!persistenceEnabled()) return;
  const existing = pending.get(name);
  if (existing) clearTimeout(existing);
  pending.set(
    name,
    setTimeout(() => {
      pending.delete(name);
      void doSave(name, serialize).catch((err) => {
        log.warn({ err, name }, "[persist] save failed");
      });
    }, delayMs),
  );
}

/**
 * Cancel a pending debounced save WITHOUT writing anything (WA-02).
 * Called when credentials are being wiped: a stale timer firing after
 * the wipe would serialize the (possibly still-present) folder and
 * upsert the dead blob back into the DB.
 * إلغاء الحفظ المؤجل المعلّق دون أي كتابة.
 */
export function cancelPendingSave(name: string): void {
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
 *
 * O2-F5 (R111): the flush's OWN upsert runs with a 3s transaction-local
 * statement_timeout (see doSave) — the shutdown budget is smaller than the
 * pool-level 10s, so a stuck upsert must fail fast instead of hanging the
 * process into the SIGKILL and losing the last signal state anyway.
 */
const FLUSH_STATEMENT_TIMEOUT_MS = 3_000;

export async function flushNow(name: string, serialize: () => Promise<string>): Promise<void> {
  if (!persistenceEnabled()) return;
  const existing = pending.get(name);
  if (existing) {
    clearTimeout(existing);
    pending.delete(name);
  }
  try {
    await doSave(name, serialize, { flushStatementTimeoutMs: FLUSH_STATEMENT_TIMEOUT_MS });
  } catch (err) {
    log.warn({ err, name }, "[persist] flush failed");
  }
}

/**
 * Milliseconds since the last SUCCESSFUL save of this session's snapshot,
 * or null when it has never been saved (fresh pairing / persistence off).
 * عمر آخر snapshot محفوظ بالمللي ثانية.
 */
export function persistAge(name: string): number | null {
  const t = lastSavedAt.get(name);
  return t == null ? null : Date.now() - t;
}

/**
 * Load + decrypt stored credentials JSON for a session name (or null).
 *
 * 2026-09-20 key-separation: tries the CURRENT key first; on failure (GCM
 * auth-tag mismatch = wrong key) and when a dedicated credentials key is
 * active, retries with the LEGACY API-key derivation. A legacy success is
 * transparently re-encrypted with the current key and re-stored, so the
 * blob migrates on first read with zero operator action. If both keys
 * fail the blob is treated as unreadable (null) — the session re-pairs
 * via QR exactly as before; the blob itself is left untouched so an
 * operator who unset a WRONG credentials key can still recover by
 * restarting (the legacy path will decrypt it again).
 */
export async function loadCreds(name: string): Promise<string | null> {
  try {
    const p = await ensurePool();
    if (!p) return null;
    const res = await p.query(`SELECT creds FROM openwa_sessions WHERE name = $1`, [name]);
    if (res.rowCount === 0) return null;
    const blob = res.rows[0].creds as Buffer;

    try {
      return decrypt(blob);
    } catch (currentKeyErr) {
      if (!legacyKeyAvailable()) {
        log.warn(
          { err: currentKeyErr, name },
          "[persist] decrypt failed with the current key — treating as absent",
        );
        return null;
      }
      let plaintext: string;
      try {
        plaintext = decryptWith(blob, deriveKey(API_KEY));
      } catch (legacyErr) {
        // r98/98-F6 P3-2: name the env vars + the recovery path so an
        // operator who rotated/typo'd a key gets an actionable pointer
        // instead of a bare crypto error.
        log.warn(
          {
            err: legacyErr,
            name,
            recovery:
              "unset the wrong OPENWA_CREDENTIALS_KEY (or restore the key that encrypted this blob) " +
              "and restart — the stored blob is untouched, so the correct key (or the legacy " +
              "OPENWA_API_KEY derivation) decrypts it on the next boot; only a truly unreadable " +
              "blob forces a fresh QR pairing",
          },
          "[persist] decrypt failed with BOTH OPENWA_CREDENTIALS_KEY (current) and OPENWA_API_KEY (legacy) — treating as absent",
        );
        return null;
      }
      // Legacy decrypt succeeded → transparent re-key. WA-02 discipline:
      // never resurrect a wiped name (the boot path has no tombstones, but
      // this guard keeps the invariant total).
      const wipe = wipedAt.get(name);
      if (wipe != null) {
        log.warn({ name }, "[persist] legacy blob readable but name is tombstoned — skipping re-key");
        return null;
      }
      try {
        await p.query(
          `UPDATE openwa_sessions SET creds = $2, updated_at = NOW() WHERE name = $1`,
          [name, encrypt(plaintext)],
        );
        log.info(
          { name },
          "[persist] re-keyed legacy credentials blob to OPENWA_CREDENTIALS_KEY",
        );
      } catch (rekeyErr) {
        // Re-key write failed (transient DB issue): still return the
        // plaintext — the next save writes it with the current key anyway.
        log.warn(
          { err: rekeyErr, name },
          "[persist] re-key UPDATE failed — returning plaintext; next save will re-encrypt",
        );
      }
      return plaintext;
    }
  } catch (err) {
    log.warn({ err, name }, "[persist] load failed");
    return null;
  }
}

/** Names of all persisted sessions (for boot-time auto-restore). */
export async function listPersistedNames(): Promise<string[]> {
  try {
    const p = await ensurePool();
    if (!p) return [];
    const res = await p.query(`SELECT name FROM openwa_sessions ORDER BY name`);
    return res.rows.map((r) => r.name as string);
  } catch (err) {
    log.warn({ err }, "[persist] list failed");
    return [];
  }
}

/**
 * Restore-path hardening (110-K, 109-h P3): a filename key inside a stored
 * credentials blob is only trusted after this check. The blob comes from
 * the DATABASE — normally written by the gateway's own serializer from a
 * genuine auth-folder listing, but a tampered or foreign blob must never be
 * able to plant a file OUTSIDE the session dir (absolute path, `..`
 * traversal, separators, NUL/control bytes) or under a >255-char name the
 * filesystem would reject. The charset is deliberately wider than bare
 * `[A-Za-z0-9._-]` because it must stay LOSSLESS for every filename the
 * Baileys multi-file auth store produces (verified against its source —
 * fixFileName only rewrites `/`→`__` and `:`→`-`):
 *   creds.json · pre-key-<id> · session-<user>.<device>
 *   sender-key-<groupJid>--<user>.<device>      (JIDs carry `@`)
 *   sender-key-memory-<jid>                      (JIDs carry `@`)
 *   app-state-sync-key-<base64>                 (base64 carries `+` `=`)
 *   app-state-sync-version-<name>               (names carry `_`)
 * `.`/`..` pass the charset and are rejected explicitly. Callers skip +
 * log the FILENAME only (blob content is secret and never logged) and must
 * not let one bad name abort the rest of the restore.
 * فحص اسم الملف داخل البلوب قبل الكتابة — لا كتابة خارج مجلد الجلسة أبدًا.
 */
const BLOB_FNAME_RE = /^[A-Za-z0-9._@+=-]+$/;
const BLOB_FNAME_MAX = 255; // Linux NAME_MAX per path component.

export function isSafeBlobFilename(fname: string): boolean {
  return (
    fname.length > 0 &&
    fname.length <= BLOB_FNAME_MAX &&
    fname !== "." &&
    fname !== ".." &&
    BLOB_FNAME_RE.test(fname)
  );
}

/**
 * Wipe the persisted credentials blob for a session (the local auth dir
 * is the caller's job). WA-02 hardening: cancels any pending debounced
 * save, tombstones the name (an in-flight save that started earlier can
 * never upsert the dead blob afterwards) and drops the persistAge marker.
 * مسح البيانات المحفوظة مع إلغاء أي حفظ معلّق وشاهد قبر يمنع الإنعاش.
 */
export async function deletePersisted(name: string): Promise<void> {
  cancelPendingSave(name);
  wipedAt.set(name, Date.now());
  lastSavedAt.delete(name);
  // r98/98-F6 P3-8 (optional hygiene): the tombstone only needs to outlive
  // saves that STARTED before the wipe — those settle within seconds, so
  // pruning it after 10 minutes keeps `wipedAt` from growing unbounded
  // across many delete/re-pair cycles. unref'd: never holds the process
  // open (same discipline as the rate-limit sweep timers).
  setTimeout(() => wipedAt.delete(name), 10 * 60_000).unref();
  try {
    // 110-K: the DELETE rides the SAME per-name write chain as the save
    // upserts — an in-flight save that already passed the tombstone
    // guards lands its upsert first, this DELETE lands right after it,
    // and the row ends up gone. The tombstone (set above, synchronously)
    // additionally kills any save that is merely REQUESTED later than
    // this call.
    await orderedWrites(name, async () => {
      const p = await ensurePool();
      if (!p) return;
      await p.query(`DELETE FROM openwa_sessions WHERE name = $1`, [name]);
    });
  } catch {
    // best-effort
  }
}

/**
 * @internal Test-only surface for the 2026-09-20 key-separation audit.
 * Exposes the pure crypto paths so tests can prove:
 *   - unset OPENWA_CREDENTIALS_KEY → byte-identical legacy derivation
 *   - set + differing → new derivation, legacy fallback readable
 *   - wrong key → decrypt throws (GCM auth tag)
 * Never used by runtime code paths.
 */
export function __cryptoForTest(): {
  encryptCurrent: (plain: string) => Buffer;
  decryptCurrent: (blob: Buffer) => string;
  decryptLegacy: (blob: Buffer) => string;
  legacyKeyAvailable: () => boolean;
} {
  return {
    encryptCurrent: encrypt,
    decryptCurrent: decrypt,
    decryptLegacy: (blob: Buffer) => decryptWith(blob, deriveKey(API_KEY)),
    legacyKeyAvailable,
  };
}

/**
 * @internal Test-only surface for the 110-K WA-02 race tests: swaps the
 * memoized pg pool for a fake. With PERSISTENCE_URL set to a dummy string,
 * ensurePool() returns the fake WITHOUT touching a real database — the
 * creation branch (pool `error` listener + boot DDL) is skipped whenever
 * `pool` is already set. Returns the previous pool so tests can restore
 * it. Never used by runtime code paths.
 */
export function __setPoolForTest(fake: Pool | null): Pool | null {
  const prev = pool;
  pool = fake;
  return prev;
}
