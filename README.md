# openwa-gateway

WhatsApp multi-session REST gateway (Baileys-based). Implements the session /
send-text contract consumed by SubNation's WhatsApp OTP service:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | liveness (no auth) |
| `GET /api/sessions` | list sessions |
| `POST /api/sessions` `{name}` | create a session |
| `GET /api/sessions/{id}` | one session |
| `POST /api/sessions/{id}/start` | start engine (emits QR) |
| `GET /api/sessions/{id}/qr` | operator page — scan with WhatsApp |
| `GET /api/sessions/{id}/contacts/check/{number}` | registered-on-WhatsApp preflight |
| `POST /api/sessions/{id}/messages/send-text` `{chatId,text}` | send text (`218…@c.us` accepted) |

Auth: `X-API-Key: $OPENWA_API_KEY` on every `/api` request.

Lifecycle: `created → initializing → qr_ready → ready`
(`disconnected` auto-reconnects; logged-out wipes credentials and re-QRs).

## Environment

| Var | Required | Meaning |
| --- | --- | --- |
| `OPENWA_API_KEY` | yes | shared secret for every `/api` call — the sole auth of the API surface, ≥ 32 chars recommended (`openssl rand -hex 32`; a boot warning fires below 32) |
| `OPENWA_CREDENTIALS_KEY` | no | dedicated secret for encrypting persisted session credentials (`openssl rand -hex 32`, ≥ 32 chars recommended). **Unset = legacy derivation from `OPENWA_API_KEY`** — existing blobs decrypt with zero migration; when set, a blob that still decrypts with the old key is transparently re-encrypted on first read |
| `PERSISTENCE_URL` | no | Postgres connection string — when set (together with `OPENWA_API_KEY`), session credentials are AES-256-GCM encrypted and persisted, so restarts/spin-downs restore pairings without a new QR scan |
| `DATA_DIR` | no (default `/data`) | where Baileys credentials persist — **mount a disk here** so the scanned QR survives restarts |
| `PORT` | no (default 2785) | listen port |

## Pairing a session

1. `POST /api/sessions {"name":"subnation-otp"}` → note the returned `id`.
2. `POST /api/sessions/{id}/start`.
3. Open `/api/sessions/{id}/qr` in a browser (with the API key cannot be put
   in the URL — use any client that can send headers, e.g.
   `curl -H "X-API-Key: …" …/qr > qr.html`) and scan with
   **WhatsApp ← الأجهزة المرتبطة ← ربط جهاز**.
4. Poll `GET /api/sessions/{id}` until `status === "ready"`.

Credentials live in `${DATA_DIR}/sessions/<name>/` — never delete that folder
unless you want to pair again from scratch.

## Docker

CI publishes a multi-arch (linux/amd64 + linux/arm64) image to GHCR on
every push to `main` and on `v*` tags (`.github/workflows/docker.yml`):

    ghcr.io/ahmadmedo1012/openwa

**Pull it sha-pinned.** Every build publishes an immutable `sha-<short>`
tag (one commit → one digest, never overwritten) — this is the tag the
SubNation compose policy pins and the one to use for reproducible
deployments:

    docker pull ghcr.io/ahmadmedo1012/openwa:sha-<short>   # immutable — pin this

The `:main` alias (and `:latest` / `:1.2.3` when a version tag exists) is
a FLOATING tag that silently moves with every build — fine for a quick
look, wrong for anything you want to be able to reproduce or roll back.
Run it with a volume mounted at `DATA_DIR` (`/data` in the image) and the
environment variables above.
