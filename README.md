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

Lifecycle: `created → initializing → qr_ready → authenticating → ready`
(`disconnected` auto-reconnects; logged-out wipes credentials and re-QRs).

## Environment

| Var | Required | Meaning |
| --- | --- | --- |
| `OPENWA_API_KEY` | yes | shared secret for every `/api` call |
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
