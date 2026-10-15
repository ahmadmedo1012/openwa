# openwa-gateway

WhatsApp multi-session REST gateway (Baileys-based). Implements the session /
send-text contract consumed by SubNation's WhatsApp OTP service:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | liveness (no auth) |
| `GET /api/sessions` | list sessions |
| `POST /api/sessions` `{name}` | create a session |
| `GET /api/sessions/{id}` | one session |
| `DELETE /api/sessions/{id}` | delete a session (wipes its credentials) |
| `POST /api/sessions/{id}/start` | start engine (emits QR) |
| `GET /api/sessions/{id}/qr` | operator page — scan with WhatsApp |
| `POST /api/sessions/{id}/pair-code` | pair via the phone-number code (alternative to QR) |
| `GET /api/sessions/{id}/contacts/check/{number}` | registered-on-WhatsApp preflight |
| `POST /api/sessions/{id}/messages/send-text` `{chatId,text}` | send text (`218…@c.us` accepted) |
| `POST /api/sessions/{id}/messages/test` | send a test message (dashboard button) |
| `GET /api/sessions/{id}/delivery-log` | recent delivery log |
| `GET /api/docs` | this table, machine-readable (JSON) |

Auth: `X-API-Key: $OPENWA_API_KEY` on every `/api` request.

Lifecycle: `created → initializing → qr_ready → ready`
(`disconnected` auto-reconnects; logged-out wipes credentials and re-QRs).

## Message retry contract (R149 + R150)

When a recipient device cannot decrypt a message (stale Signal session on
their side), it asks the sender to re-send it by message id. Baileys only
answers that request through the app-supplied `getMessage` callback —
without it the request is silently dropped and the recipient's chat shows
**"Waiting for this message. This may take a while."** forever
(WhiskeySockets/Baileys#1767). The gateway implements the full contract:

- Every engine-sent message's **content** is recorded by message id
  (per session; TTL 30 min = 6× the 5-min SubNation OTP validity; capped
  at the latest 500).
- `getMessage` serves that content on retry receipts — same message id, so
  the recipient's placeholder resolves into the original message (no
  duplicate), via a freshly established Signal session.
- Resend counters live on the session record (not the socket), so the
  protocol's 5-resend bound holds across reconnects instead of re-arming
  per connection.
- **R150 — restart persistence:** both stores ALSO survive process
  restarts. Every mutation is flushed (atomic tmp+rename) to
  `${DATA_DIR}/sessions/<name>/__openwa_retry_state.json`, which rides the
  existing persistence unit: it is snapshotted into the AES-256-GCM-
  encrypted DB blob alongside the credentials, restored on boot BEFORE the
  engine starts, TTL-anchored to the ORIGINAL send time (a restart never
  resets the 30-min window), and killed with the pairing by the WA-02
  folder wipe. A container redeploy inside a message's retry window no
  longer orphans it. At-rest exposure: plaintext only on the container-
  local `DATA_DIR` volume — the same class as the Signal keys already
  stored there — and inside the encrypted DB blob; bounded by TTL + cap.
- Each retry request is logged as `[retry] resend request` with the message
  id, masked JID, and `served: true/false` — no message content is ever
  logged. A `served: false` miss means the message predates the store
  window (sent > 30 min ago). Rehydrated boots log
  `[retry] state rehydrated from disk`.

Pairing death (`loggedOut`) clears the store AND removes the state file
with the credentials folder — a re-paired session can never re-serve the
old pairing's message content.

### Retry-outcome observability + log PII masking (R150)

Baileys is wired through a masking log adapter (`[baileys]`-prefixed
lines): `warn`/`error` are always forwarded, `info` only when
retry-relevant, every value JID-masked. The lines that matter when
chasing a "Waiting for this message" report:

- `[retry] resend request (getMessage)` — a recipient device asked for a
  re-send; `served` says whether the store had it.
- `[baileys] will not send message again, as sent too many times` — the
  5-resend budget is exhausted; the placeholder will not resolve.
- `[baileys] recv retry for not fromMe message` — the retry receipt was
  NOT classified as ours (LID/PN addressing drift — collect this evidence
  before any deeper change).
- `[baileys] error in sending message again` — the resend itself failed.

Without the adapter, Baileys' default bare-`pino()` logger forwards raw
recipient JIDs to stdout at `info` level — the adapter closes that leak.

### Deployment identity (R150)

`GET /healthz` exposes `release` — the commit SHA baked into the image at
build time (`ARG RELEASE_SHA`, wired through docker.yml). Verify a
deployment in one request:

```sh
docker exec <gateway-container> wget -qO- http://127.0.0.1:2785/healthz
# → {"ok":true,...,"release":"<full commit sha>"}
```

Compare against the GHCR `sha-<short>` tag the deployment pinned. `null`
means the image was built without the arg (local dev) — never guess.

### Companion identity (R150)

The socket now registers as `Browsers.ubuntu("Chrome")` — the upstream
Baileys DEFAULT — instead of the old `Windows/Chrome` override. WhatsApp
has been 428-rejecting WIN32/DARWIN companion identities at **pairing**
since ~2026-06-30 (WhiskeySockets/Baileys#2677); the already-linked
session is unaffected, and the next re-pair is protected.

## Environment

| Var | Required | Meaning |
| --- | --- | --- |
| `OPENWA_API_KEY` | yes | shared secret for every `/api` call — the sole auth of the API surface, ≥ 32 chars recommended (`openssl rand -hex 32`; a boot warning fires below 32) |
| `OPENWA_CREDENTIALS_KEY` | no | dedicated secret for encrypting persisted session credentials (`openssl rand -hex 32`, ≥ 32 chars recommended). **Unset = legacy derivation from `OPENWA_API_KEY`** — existing blobs decrypt with zero migration; when set, a blob that still decrypts with the old key is transparently re-encrypted on first read |
| `PERSISTENCE_URL` | no | Postgres connection string — when set (together with `OPENWA_API_KEY`), session credentials are AES-256-GCM encrypted and persisted, so restarts/spin-downs restore pairings without a new QR scan |
| `DATA_DIR` | no (default `/data`) | where Baileys credentials persist (under `${DATA_DIR}/sessions/<name>/`) — **mount a volume here** so the scanned QR survives restarts |
| `PORT` | no (default 2785) | listen port |
| `LOG_LEVEL` | no (default `info`) | pino log level (`debug`/`info`/`warn`/`error`) |
| `OPENWA_SELF_SEND_LID` | no (default: enabled) | set to a truthy value to DISABLE the self-send LID preference workaround — leave unset unless WhatsApp changes behavior |
| `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` | no | when BOTH set, the cookie-authenticated operator dashboard is enabled at `/` (login lockout included). Unset = disabled page |
| `DASHBOARD_SESSION_SECRET` | no (required when the dashboard is enabled) | ≥ 32 chars — signs the dashboard session cookie (`openssl rand -hex 32`) |
| `TRUST_PROXY` | no (default: trust) | forwarded-identity trust for the `/api` rate limits and the dashboard login lockout. Default (unset) trusts the RIGHTMOST `X-Forwarded-For` entry — correct behind a reverse proxy (Cloudflare → Traefik) and on loopback-direct compose. **Set `TRUST_PROXY=0` when the port is published DIRECTLY** (no reverse proxy in front, e.g. a raw Coolify port mapping): otherwise a forged `X-Forwarded-For` header hands an attacker an attacker-chosen identity (unlimited rate-limit bucket splitting + lockout bypass) |

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

**SINGLE-GATEWAY RULE — never run two instances against the same WhatsApp
session.** Exactly ONE container per WhatsApp credential: two overlapping
starts on the same `DATA_DIR` + `PERSISTENCE_URL` build two Baileys sockets
on one auth folder, and WhatsApp answers that conflict with `loggedOut` —
which WIPES the stored credentials and forces a QR re-pair. Stop the old
container before starting a new one (including during rollbacks: stop old,
start pinned-older image — never both). One replica, always.

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
