<div align="center">
  <img src="static/logo.png" alt="statainer" width="140">
  <h1>statainer</h1>
  <p><strong>A focused dashboard for container monitoring, safe updates, notifications, and Compose-aware operations.</strong></p>
</div>

## Overview

statainer is a lightweight web UI for Docker hosts. It combines live container metrics, Compose project grouping, configurable alerts, update discovery, rollback history, and day-to-day container controls in one interface.

It is designed for self-hosted environments where you want fast operational visibility without giving up practical controls.

## What It Does Well

### Monitoring
- Live CPU, RAM, network I/O, block I/O, uptime, restart count, process count, ports, image, and status visibility.
- Table and chart views for individual containers and top-N comparisons.
- Compose project summaries with grouped container states.
- Optional GPU metrics when NVIDIA tooling is available.

### Operations
- Start, stop, and restart containers from the UI.
- Open exposed container endpoints directly from the dashboard.
- Inspect container logs without leaving the app.
- Persist filters, visible columns, chart mode, theme, refresh interval, and layout preferences locally.

### Updates
- Detect update-ready containers and Compose stacks.
- Run Quick Update for individual targets.
- Run `Update selected` or `Update all` from the Update Manager.
- Show blocked stacks with explicit guidance when original Compose files are missing or externally managed.
- Keep a persistent update and rollback history.

### Notifications
- CPU, RAM, status, and image update alerts.
- Browser-side notification center with pending event history.
- External delivery through Pushover, Slack, Telegram, Discord, ntfy, and generic webhooks.

### Programmatic API
- Optional, admin-enabled REST API protected by scoped, per-key bearer tokens.
- Expose container counts, per-container metrics, host CPU cores and max RAM, and run/stop/restart/update controls — all gated by the scopes you grant each key.
- Tokens are hashed at rest and shown once; keys support optional expiration and reversible pause/delete. See **[API.md](API.md)** for the full reference.

## Screenshots

<table align="center">
  <tr>
    <td align="center">
      <a href="screenshots/screenshot-1.png">
        <img src="screenshots/screenshot-1.png" alt="screenshot 1" width="180">
      </a>
    </td>
    <td align="center">
      <a href="screenshots/screenshot-2.png">
        <img src="screenshots/screenshot-2.png" alt="screenshot 2" width="180">
      </a>
    </td>
    <td align="center">
      <a href="screenshots/screenshot-3.png">
        <img src="screenshots/screenshot-3.png" alt="screenshot 3" width="180">
      </a>
    </td>
    <td align="center">
      <a href="screenshots/screenshot-4.png">
        <img src="screenshots/screenshot-4.png" alt="screenshot 4" width="180">
      </a>
    </td>
  </tr>
  <tr>
    <td align="center">
      <a href="screenshots/screenshot-5.png">
        <img src="screenshots/screenshot-5.png" alt="screenshot 5" width="180">
      </a>
    </td>
    <td align="center">
      <a href="screenshots/screenshot-6.png">
        <img src="screenshots/screenshot-6.png" alt="screenshot 6" width="180">
      </a>
    </td>
    <td align="center">
      <a href="screenshots/screenshot-7.png">
        <img src="screenshots/screenshot-7.png" alt="screenshot 7" width="180">
      </a>
    </td>
    <td align="center">
      <a href="screenshots/screenshot-8.png">
        <img src="screenshots/screenshot-8.png" alt="screenshot 8" width="180">
      </a>
    </td>
  </tr>
</table>

## Quick Start

### Requirements
- Docker
- Docker Compose plugin
- Access to the Docker socket on the host

### Start With Docker Compose

```bash
git clone https://github.com/Drakonis96/statainer
cd statainer
docker compose up --build -d
```

Once started, open:

```text
http://localhost:5001
```

### Recommended Production Compose

For reverse-proxy deployments (e.g. behind Nginx / Caddy / Cloudflare Tunnel), uncomment and adjust the hardening variables already present in `docker-compose.yml`:

```yaml
services:
  statainer:
    image: drakonis96/statainer:latest
    environment:
      AUTH_ENABLED: "true"
      AUTH_USER: admin
      AUTH_PASSWORD_FILE: /run/secrets/auth_password
      APP_ENV: "production"
      APP_SECRET_KEY_FILE: /run/secrets/statainer_app_secret
      LOGIN_MODE: "page"
      SESSION_IDLE_MINUTES: "30"
      SESSION_COOKIE_SECURE: "true"
      TRUSTED_PROXY_HOPS: "1"
      CADVISOR_URL: http://cadvisor:8080
    ports:
      - "5001:5000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./data:/app/data
    secrets:
      - auth_password
      - statainer_app_secret
    restart: unless-stopped

secrets:
  auth_password:
    file: ./secrets/auth_password.txt
  statainer_app_secret:
    file: ./secrets/app_secret.txt
```

Generate a strong secret with `openssl rand -hex 32 > ./secrets/app_secret.txt`.

## Default Deployment Notes

The bundled [docker-compose.yml](docker-compose.yml) exposes:

- statainer on `5001`
- cAdvisor on `8080`

It also mounts:

- Docker socket as read-only
- Local app data into `./data`

The users/settings SQLite database lives inside the data directory (`/app/data` in the
container, configurable with `DATA_DIR`). Keep the `./data` volume mounted to persist
users and settings across updates. When upgrading from an older version that stored the
database at `/app/users.db`, it is moved into the data directory automatically on first
start, so existing accounts are preserved.

## Configuration

### Core Environment Variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `AUTH_ENABLED` | Enables authentication | `true` |
| `AUTH_USER` | Admin username | empty |
| `AUTH_PASSWORD` | Admin password | empty |
| `AUTH_PASSWORD_FILE` | Password file alternative | empty |
| `APP_SECRET_KEY` | Session secret | generated if missing outside production |
| `APP_SECRET_KEY_FILE` | Secret file alternative | empty |
| `APP_ENV` | Runtime mode. Use `production` behind a reverse proxy | `development` |
| `REQUIRE_EXPLICIT_SECRET_KEY` | Refuses startup with an ephemeral secret | `true` in production |
| `LOGIN_MODE` | Login flow: `popup` or `page` | `popup` |
| `APP_VERSION` | Version shown in the UI footer | repository `VERSION` file (`v0.9.20`) |
| `DATA_DIR` | Directory where the users/settings database is created and persisted (point it at a folder, not a file) | `/app/data` |
| `DOCKER_SOCKET_URL` | Docker socket URL | `unix:///var/run/docker.sock` |
| `CADVISOR_URL` | cAdvisor endpoint | `http://cadvisor:8080` |
| `GPU_METRICS_ENABLED` | Enables GPU collection | `true` in bundled compose |
| `SESSION_IDLE_MINUTES` | Inactivity timeout for page sessions | `30` |
| `SESSION_COOKIE_SECURE` | Marks the session cookie as HTTPS-only | `true` in production |
| `TRUSTED_PROXY_HOPS` | Number of trusted proxy hops for forwarded headers | `0` |
| `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | Failed login attempts before blocking an IP | `5` |
| `LOGIN_RATE_LIMIT_WINDOW_SECONDS` | Sliding window (seconds) for the attempt counter | `300` |

### Authentication Recommendations

- There are no built-in credentials.
- Set `AUTH_USER` and either `AUTH_PASSWORD` or `AUTH_PASSWORD_FILE` before exposing the app.
- Set `APP_SECRET_KEY` or `APP_SECRET_KEY_FILE` to keep sessions stable across restarts.
- If you want no authentication, set `AUTH_ENABLED=false` explicitly.

### Reverse Proxy Hardening

For Internet exposure behind Cloudflare and a reverse proxy, set at least:

```yaml
APP_ENV: "production"
APP_SECRET_KEY_FILE: "/run/secrets/statainer_app_secret"
LOGIN_MODE: "page"
SESSION_IDLE_MINUTES: "30"
SESSION_COOKIE_SECURE: "true"
TRUSTED_PROXY_HOPS: "1"
```

If your reverse proxy appends to `X-Forwarded-For` on top of Cloudflare's header chain, set `PROXY_FIX_X_FOR` to match the real number of trusted hops instead of relying on the default. statainer now sends a restrictive baseline CSP, frame protection, referrer policy, permission policy, and HSTS when the request reaches the app as HTTPS.

### Login Mode

Choose the login experience with:

```yaml
LOGIN_MODE: "page"
```

Available values:

- `popup`
- `page`

## Dashboard Capabilities

### Table and Filters
- Filter by container name, status, and Compose project.
- Sort by CPU, RAM, uptime, restarts, image, I/O, update availability, and more.
- Toggle visible columns per user.
- Export current metrics to CSV.

### Charts
- Line, bar, and pie visualizations.
- Top-N comparison views for CPU, RAM, and uptime.
- Zoom and pan support where applicable.

### Compose Awareness
- Group containers by Compose project.
- Inspect project summaries alongside per-container rows.
- Switch between `Containers` and `Compose Stacks` views from the dashboard tabs.

## Update Manager

The Update Manager is designed around safety and operator visibility.

### Available Actions
- `Quick Update` for a single target.
- `Update selected` for checked stacks or containers.
- `Update all` for all ready targets in a tab.

### Selection Workflow
- Each update-ready stack or standalone container exposes a checkbox.
- You can select a range with `Shift` to batch multiple adjacent targets.
- Batch operations run sequentially to avoid overlapping recreations.

### History and Rollback
- Every successful or failed managed update is recorded in history.
- Eligible successful updates expose rollback actions.
- History is persistent and survives modal reloads.

### Externally Managed Stacks

If a stack was originally created by another tool, statainer may not have the original Compose files available on disk. In that case the app can:

- mark the stack as blocked when it cannot safely manage it
- explain why the Compose files are unavailable
- use a safe external recreate workflow when runtime metadata is sufficient

This is especially relevant for stacks created through tools such as Portainer, Yacht, or similar management layers.

## Notifications

### Supported Providers

| Provider | Required Variables |
| --- | --- |
| Pushover | `PUSHOVER_TOKEN`, `PUSHOVER_USER` |
| Slack | `SLACK_WEBHOOK_URL` |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| Discord | `DISCORD_WEBHOOK_URL` |
| ntfy | `NTFY_TOPIC` |
| Generic webhook | `GENERIC_WEBHOOK_URL` |

### Common Workflow

1. Set the provider environment variables.
2. Restart statainer.
3. Open the notification panel as an admin user.
4. Enable the event types you want.
5. Save the configuration.
6. Use `Send test` before relying on the provider in production.

### Events That Can Trigger Alerts
- CPU threshold exceeded
- RAM threshold exceeded
- Container status changed
- Update available

### Provider Examples

<details>
  <summary>Pushover</summary>

```env
PUSHOVER_TOKEN=your-application-token
PUSHOVER_USER=your-user-key
```

</details>

<details>
  <summary>Slack</summary>

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

</details>

<details>
  <summary>Telegram</summary>

```env
TELEGRAM_BOT_TOKEN=123456:abcde...
TELEGRAM_CHAT_ID=123456789
```

</details>

<details>
  <summary>Discord</summary>

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

</details>

<details>
  <summary>ntfy</summary>

Basic public ntfy setup:

```env
NTFY_TOPIC=statainer-home
NTFY_SERVER_URL=https://ntfy.sh
```

Protected or self-hosted ntfy examples:

```env
NTFY_TOPIC=statainer-prod
NTFY_SERVER_URL=https://ntfy.example.com
NTFY_TOKEN=tk_your_token_here
```

```env
NTFY_TOPIC=statainer-prod
NTFY_SERVER_URL=https://ntfy.example.com
NTFY_USERNAME=myuser
NTFY_PASSWORD=mysecret
NTFY_TAGS=docker,monitoring,prod
NTFY_MARKDOWN=false
```

</details>

<details>
  <summary>Generic webhook</summary>

Simple JSON webhook:

```env
GENERIC_WEBHOOK_URL=https://example.com/hooks/statainer
```

Plain-text body example:

```env
GENERIC_WEBHOOK_URL=https://example.com/hooks/statainer
GENERIC_WEBHOOK_METHOD=POST
GENERIC_WEBHOOK_CONTENT_TYPE=text/plain; charset=utf-8
GENERIC_WEBHOOK_BODY_TEMPLATE=[{event_type}] {title}\n{message}
```

Custom headers:

```env
GENERIC_WEBHOOK_URL=https://example.com/hooks/statainer
GENERIC_WEBHOOK_HEADERS={"Authorization":"Bearer super-secret-token","X-Environment":"prod"}
```

Available placeholders:

- `{app}`
- `{host}`
- `{title}`
- `{message}`
- `{priority}`
- `{priority_label}`
- `{event_type}`
- `{container}`
- `{container_id}`
- `{value}`
- `{prev_value}`
- `{timestamp}`
- `{timestamp_iso}`
- `{event_json}`

</details>

## External API

statainer exposes an optional, token-authenticated REST API for external tools
(dashboards, automation, monitoring). It is **disabled by default**.

- Enable it and manage keys under **Settings → API access** (admin only).
- Each key is created with a name, a set of **scopes**, and an optional
  expiration. Keys can be **paused** (reversible) or **deleted** to revoke
  access instantly.
- Tokens are shown once and stored only as a SHA-256 hash.
- Reach it at `<your dashboard URL>/api/v1`, authenticating with
  `Authorization: Bearer <token>`. This works the same whether you hit the
  server directly (`IP:port`) or through a reverse proxy.

```bash
curl -H "Authorization: Bearer $TOKEN" https://your-host/api/v1/system
```

Hardening is configurable via `EXTERNAL_API_RATE_LIMIT_MAX`,
`EXTERNAL_API_AUTH_FAIL_MAX`, and `EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE`
(see the table in [API.md](API.md)).

**Full reference, scope list, and per-endpoint examples: [API.md](API.md).**

## Metrics Backends

statainer can work with:

- Docker API only
- Docker API plus cAdvisor

The Docker API path is usually enough. cAdvisor is useful if you want broader metric compatibility or a more established metrics source for some host environments.

## GPU Metrics

GPU metrics are available for NVIDIA-enabled hosts.

### Requirements
- NVIDIA drivers on the host
- `nvidia-smi` available in the runtime environment
- GPU-enabled container access where applicable

### Enablement

```yaml
environment:
  GPU_METRICS_ENABLED: true
```

If GPU data is available, statainer surfaces GPU load and memory usage per container in the dashboard.

## Runtime Notes

### CPU Usage

CPU percentage is calculated per core. On multi-core systems the effective ceiling is:

```text
100% x number of available CPU cores
```

### Exited Containers

Exited containers stay visible in the main table so you can:

- inspect their last known state
- review recent resource usage
- restart them directly from the UI

## Safety Notice

statainer requires access to your Docker environment to inspect containers, operate on them, and evaluate updates. Use it only on systems where you understand the implications of Docker socket access and trust the deployment.

Managed updates are designed to preserve volumes, configuration, environment, networks, and other persistent state whenever possible, but you should still review updates before applying them in production.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
