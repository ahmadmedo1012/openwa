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

let pool: Pool | null = null;

function key(): Buffer {
  return scryptSync(API_KEY, "openwa-gateway-creds-v1", 32);
}

function encrypt(plain: string): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}

function decrypt(blob: Buffer): string {
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const data = blob.subarray(28);
  const decipher = createDecipheriv("aes-256-gcm", key(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

async function ensurePool(): Promise<Pool | null> {
  if (!PERSISTENCE_URL || !API_KEY) return null;
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

export function persistenceEnabled(): boolean {
  return Boolean(PERSISTENCE_URL && API_KEY);
}

/** Debounced save of one session's serialized auth state. */
const pending = new Map<string, ReturnType<typeof setTimeout>>();

export function scheduleSave(name: string, serialize: () => Promise<string>): void {
  if (!persistenceEnabled()) return;
  const existing = pending.get(name);
  if (existing) clearTimeout(existing);
  pending.set(
    name,
    setTimeout(() => {
      pending.delete(name);
      void (async () => {
        try {
          const p = await ensurePool();
          if (!p) return;
          const json = await serialize();
          await p.query(
            `INSERT INTO openwa_sessions (name, creds, updated_at)
             VALUES ($1, $2, NOW())
             ON CONFLICT (name) DO UPDATE SET creds = $2, updated_at = NOW()`,
            [name, encrypt(json)],
          );
          log.info({ name }, "[persist] credentials saved");
        } catch (err) {
          log.warn({ err, name }, "[persist] save failed");
        }
      })();
    }, 3_000),
  );
}

/** Load + decrypt stored credentials JSON for a session name (or null). */
export async function loadCreds(name: string): Promise<string | null> {
  try {
    const p = await ensurePool();
    if (!p) return null;
    const res = await p.query(`SELECT creds FROM openwa_sessions WHERE name = $1`, [name]);
    if (res.rowCount === 0) return null;
    return decrypt(res.rows[0].creds as Buffer);
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

export function deletePersisted(name: string): void {
  void (async () => {
    try {
      const p = await ensurePool();
      if (!p) return;
      await p.query(`DELETE FROM openwa_sessions WHERE name = $1`, [name]);
    } catch {
      // best-effort
    }
  })();
}
