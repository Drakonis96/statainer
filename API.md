# statainer External API

statainer ships an optional, token-authenticated REST API that lets external
tools read container/host metrics and control containers (start, stop, restart,
update) without a browser session.

It is **disabled by default** and must be turned on explicitly. Every request is
authenticated with a per-key bearer token and authorized against the scopes you
grant when you create the key.

---

## 1. Enabling the API

1. Sign in as an **admin** user.
2. Open **Settings → API access**.
3. Toggle **Enable external API** on.
4. Create one or more API keys (see below).

While the master toggle is **off**, every endpoint responds with
`403 { "error": "api_disabled" }`, even with a valid key. Turning it off is a
global kill-switch; your keys are preserved.

---

## 2. Creating and managing keys

In **Settings → API access**:

- **Name** — a human label (e.g. `monitoring-bot`).
- **Permissions (scopes)** — tick exactly what this key may do. A key can only
  use the scopes you grant; everything else returns `403`.
- **Expiration in days** — optional. Leave blank for a key that never expires.

When you click **Create key**, the **plaintext token is shown once**. Copy it
immediately — statainer stores only a SHA-256 hash and can never show it again.
If you lose it, delete the key and create a new one.

Lifecycle controls per key:

| Action | Effect |
| --- | --- |
| **Pause** | Reversible revocation — the key is rejected until you **Resume** it. |
| **Resume** | Re-activate a paused key. |
| **Delete** | Permanent. Any client using the token loses access immediately. |

---

## 3. Base URL

The API lives under `/api/v1` of the same origin you use to reach the dashboard:

- Direct access: `http://<server-ip>:<port>/api/v1`
- Behind a reverse proxy: `https://<your-domain>/api/v1`

The **Settings → API access** tab shows the exact base URL for your deployment.

---

## 4. Authentication

Send your token in the `Authorization` header using the `Bearer` scheme:

```
Authorization: Bearer stnr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

`X-API-Key: <token>` is also accepted as an alternative.

Failure responses:

| Status | `error` | Meaning |
| --- | --- | --- |
| `403` | `api_disabled` | The master toggle is off. |
| `401` | `unauthorized` | Missing, unknown, paused or expired token. |
| `403` | `forbidden` | Valid token, but it lacks the required scope (see `required_scope`). |
| `429` | `rate_limited` | Per-key rate limit or per-IP auth-failure limit hit (see `Retry-After`). |
| `403` | `https_required` | A write request was made over plain HTTP while HTTPS-only writes are enabled. |
| `404` | `not_found` | Container not found. |
| `502` | `docker_unavailable` / `docker_error` | The Docker host could not be reached. |

---

## 5. Scopes

| Scope | Grants |
| --- | --- |
| `system:read` | `GET /system` — CPU cores, max RAM, Docker version, container counts. |
| `containers:read` | `GET /containers`, `GET /containers/<id>` — container list and metadata. |
| `stats:read` | `GET /stats`, `GET /containers/<id>/stats` — live CPU/RAM/network/disk metrics. |
| `containers:start` | `POST /containers/<id>/start` |
| `containers:stop` | `POST /containers/<id>/stop` |
| `containers:restart` | `POST /containers/<id>/restart` |
| `containers:update` | `POST /containers/<id>/update` |

`GET /ping` and `GET /me` require only a valid (enabled, unexpired) key — no
specific scope.

A container is addressable by its **full ID**, a **unique ID prefix**, or its
**name**.

---

## 6. Endpoints

### `GET /ping`
Liveness + token check.

```bash
curl -H "Authorization: Bearer $TOKEN" https://your-host/api/v1/ping
```
```json
{ "ok": true, "pong": true, "version": "v0.9.17" }
```

### `GET /me`
Metadata about the calling key.

```json
{
  "name": "monitoring-bot",
  "scopes": ["system:read", "stats:read"],
  "created_at": 1717400000.0,
  "expires_at": null,
  "last_used_at": 1717400500.0
}
```

### `GET /system` — scope `system:read`
```json
{
  "cpu_cores": 8,
  "max_cpu_percent": 800,
  "cpu_count_docker": 8,
  "memory_total_bytes": 16777216000,
  "memory_total_mb": 16000.0,
  "memory_total_gb": 15.62,
  "containers": 12,
  "containers_running": 9,
  "containers_paused": 0,
  "containers_stopped": 3,
  "images": 24,
  "docker_version": "27.0.3",
  "operating_system": "Debian GNU/Linux 12",
  "os_type": "linux",
  "architecture": "x86_64",
  "kernel_version": "6.1.0",
  "hostname": "docker-host",
  "app_version": "v0.9.17"
}
```

### `GET /containers` — scope `containers:read`
Returns counts plus per-container **metadata** (no live stats).

```json
{
  "count": 2,
  "running": 1,
  "exited": 1,
  "containers": [
    {
      "id": "9f0e…",
      "name": "web",
      "status": "running",
      "image": "nginx:latest",
      "ports": "8080->80/tcp",
      "restarts": 0,
      "uptime": "3h 12m",
      "uptime_sec": 11520,
      "update_available": 0,
      "compose_project": "demo",
      "compose_service": "web"
    }
  ]
}
```

Optional query filters (same as the dashboard): `?name=`, `?project=`,
`?status=`, `?sort=`, `?dir=`, `?source=cadvisor|docker`.

### `GET /containers/<id>` — scope `containers:read`
Metadata for a single container (by id, id-prefix or name). `404` if not found.

### `GET /stats` — scope `stats:read`
Full live metrics for every container.

```json
{
  "count": 1,
  "containers": [
    {
      "id": "9f0e…",
      "name": "web",
      "status": "running",
      "cpu": 12.5,
      "mem": 30.1,
      "mem_usage": 192.4,
      "mem_limit": 512.0,
      "net_io_rx": 1.2,
      "net_io_tx": 0.8,
      "block_io_r": 0.0,
      "block_io_w": 4.1,
      "pid_count": 12,
      "restarts": 0,
      "uptime_sec": 11520,
      "update_available": 0,
      "compose_project": "demo",
      "compose_service": "web"
    }
  ]
}
```

### `GET /containers/<id>/stats` — scope `stats:read`
Full live metrics for a single container. `404` if not found.

### `POST /containers/<id>/start` — scope `containers:start`
### `POST /containers/<id>/stop` — scope `containers:stop`
### `POST /containers/<id>/restart` — scope `containers:restart`
### `POST /containers/<id>/update` — scope `containers:update`

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://your-host/api/v1/containers/web/restart
```
```json
{ "ok": true, "action": "restart", "container_id": "9f0e…", "name": "web", "message": "Container web restarted." }
```

`update` uses the same safe-update pipeline as the UI and returns a
`history_entry` on success. A failed update returns `409` with `ok: false`.

---

## 7. Security model

- **Hashed at rest.** Only a SHA-256 hash of each token is stored; the plaintext
  is shown once and never persisted or logged.
- **Scoped least-privilege.** Grant a key only the scopes it needs. Read and
  write capabilities are independent.
- **Reversible + permanent revocation.** Pause a key instantly, or delete it.
- **Expiration.** Optional per-key expiry auto-disables a key after a date.
- **Rate limiting.** Per-key request throttling and per-IP throttling of failed
  auth attempts mitigate abuse and token guessing. Tune with the environment
  variables below.
- **Audit trail.** Key creation, updates, deletion, scope denials and all write
  actions are written to the audit log with the originating IP.
- **Isolation.** The API blueprint does not share the cookie/session auth used by
  the dashboard, so a leaked browser session cannot be replayed against it and
  vice-versa.
- **Transport.** Always run behind HTTPS in production (terminate TLS at your
  reverse proxy). Set `EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE=true` to reject
  plain-HTTP write requests outright. When behind a proxy, configure
  `TRUSTED_PROXY_HOPS`/`ENABLE_PROXY_FIX` so client IPs are recorded correctly.

### Tuning environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `EXTERNAL_API_RATE_LIMIT_MAX` | `120` | Max requests per key per window (`0` disables). |
| `EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window length. |
| `EXTERNAL_API_AUTH_FAIL_MAX` | `10` | Failed auth attempts per IP before a temporary block (`0` disables). |
| `EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS` | `60` | Auth-failure window length. |
| `EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE` | `false` | Require HTTPS for start/stop/restart/update. |

---

## 8. Quick start

```bash
# 1. Enable the API and create a key in Settings → API access, then:
export TOKEN="stnr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export BASE="https://your-host/api/v1"

# 2. Verify the token
curl -H "Authorization: Bearer $TOKEN" "$BASE/ping"

# 3. Read host capacity
curl -H "Authorization: Bearer $TOKEN" "$BASE/system"

# 4. List containers and live stats
curl -H "Authorization: Bearer $TOKEN" "$BASE/containers"
curl -H "Authorization: Bearer $TOKEN" "$BASE/stats"

# 5. Restart a container (needs the containers:restart scope)
curl -X POST -H "Authorization: Bearer $TOKEN" "$BASE/containers/web/restart"
```
