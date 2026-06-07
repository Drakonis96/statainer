# Changelog

## v0.9.19

### Security
- **Hardened login against user enumeration.** `validate_user` now always performs a password-hash comparison — against a constant decoy hash when the username does not exist — so the response time no longer reveals which usernames are valid (timing-based account enumeration).
- **Constant-time CSRF token validation.** The submitted CSRF token is now compared with `hmac.compare_digest` instead of `==`, removing a timing side-channel on the token.
- **Login rate limiter can no longer be turned into a memory-exhaustion DoS.** The in-memory per-IP attempt tracker now purges expired buckets and caps the number of tracked IPs (10,000), bounding memory even under a flood of spoofed/rotating source IPs (e.g. attacker-controlled `X-Forwarded-For` behind a proxy).
- **`Retry-After` header on rate-limited (429) responses** for both page-based and Basic Auth (popup) login, so clients and reverse proxies can back off correctly.
- **Login page is now marked non-cacheable** (`Cache-Control: no-store`), preventing intermediaries from caching the login form or its CSRF token.

### Notes
- No configuration or API changes. All existing environment variables, endpoints and the external `/api/v1` programmatic API behave exactly as before; these are defensive hardening changes only.

## v0.9.18

### Fixed
- **API access tab layout.** The "Create key" button used the sticky action style and overlapped the scopes/keys list below it, making the panel look broken. It is now inline so the form, the one-time key reveal, and the existing-keys list flow cleanly.
- Restyled the Base URL hint into a subtle, self-contained box (with light/dark variants) instead of reusing the tab-pane card style.

### Changed
- Added `?v=<app_version>` cache-busting to the dashboard stylesheet and the dashboard JS entry point so browsers and reverse proxies pick up new assets immediately after an update. This prevents a stale cached `context.js` from leaving the API access tab non-functional (form not wired, keys not listed) after upgrading.

## v0.9.17

### Added
- **External programmatic API with API keys.** A new **Settings → API access** tab (admin only) lets you expose a secure, scoped REST API:
  - **Master toggle** to enable/disable the whole API at runtime. While disabled every key is rejected; keys keep their configuration.
  - **Create named keys** with **granular scopes** (`system:read`, `containers:read`, `stats:read`, `containers:start`, `containers:stop`, `containers:restart`, `containers:update`) and an **optional expiration** (in days).
  - **Reversible revocation:** pause/resume a key without deleting it, or delete it to immediately cut off access.
  - Tokens are shown **once** on creation and stored only as a **SHA-256 hash** — the plaintext is never persisted.
  - Endpoints under `/api/v1`: `GET /ping`, `GET /me`, `GET /system` (CPU cores, max RAM, Docker info, counts), `GET /containers`, `GET /containers/<id>`, `GET /stats`, `GET /containers/<id>/stats`, and `POST /containers/<id>/{start,stop,restart,update}`.
  - Authenticate with `Authorization: Bearer <token>` (or `X-API-Key`). The base URL follows however you reach the dashboard — direct `IP:port` or a reverse-proxy domain.
  - Hardening: per-key **rate limiting**, per-IP **auth-failure throttling**, **audit logging** of key management and write actions, optional **HTTPS-only writes**, and isolation from the session-auth UI routes.
- New environment variables to tune the API: `EXTERNAL_API_RATE_LIMIT_MAX` (default `120`), `EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS` (default `60`), `EXTERNAL_API_AUTH_FAIL_MAX` (default `10`), `EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS` (default `60`), and `EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE` (default `false`).
- New [API.md](API.md) documenting authentication, scopes, every endpoint, curl examples and security notes (linked from the README).

## v0.9.16

### Fixed
- Fixed mobile notification panel not displaying when opened from the sidebar menu. The document-level click handler was immediately closing the panel due to event propagation; the sidebar toggle now stops propagation correctly.
- Fixed notification panel remaining in a visible ghost state after being dismissed. The `hidePanel()` and `resetPanelInlineStyle()` functions in the notification controller now clear the `mobile-notif-visible` CSS class, preventing the `!important` display override from re-showing the panel and blocking pointer events.
- Fixed excessive vertical gap between the Update Manager toolbar text and controls on mobile by reducing the column flex gap and tightening spacing.
- Added a CSS class-based visibility override (`mobile-notif-visible`) for the notification panel to ensure reliable display above all other layers on mobile.

### Changed
- Redesigned the Update Manager mobile layout for a compact, grouped vertical flow:
  - Removed the experimental warning banner and verbose subtitle on mobile to reclaim space.
  - Hidden the toolbar heading; the meta summary line now serves as a compact status indicator with a subtle themed background.
  - Search bar takes full width; sort, hide-blocked, and refresh controls now align in a single horizontal row below it.
  - Update Manager tabs render as a 2×2 grid instead of a scrollable row on mobile.
  - Per-tab action buttons display in a two-column grid with smaller text and hidden icons for compactness.
  - Pane-head eyebrow labels are hidden and heading font sizes reduced.
  - Modal header subtitle and body top padding tightened for additional space savings.
- All changes are scoped to mobile breakpoints (`max-width: 768px`); the desktop experience is unchanged.

## v0.9.15

### Added
- Added in-app login rate limiting: after a configurable number of failed attempts (default 5) from the same IP address, further login requests are blocked for a sliding window (default 5 minutes). Works for both page-based and Basic Auth (popup) login modes.
- New environment variables `LOGIN_RATE_LIMIT_MAX_ATTEMPTS` (default `5`) and `LOGIN_RATE_LIMIT_WINDOW_SECONDS` (default `300`) to tune the rate limiter. Set `LOGIN_RATE_LIMIT_MAX_ATTEMPTS=0` to disable.

### Fixed
- Fixed the version footer displaying "dev" instead of the actual version number when running in Docker. The `VERSION` file is now included in the container image.

## v0.9.14

### Fixed
- Fixed login page logo overflow and disproportionate sizing by consolidating all styles into the external stylesheet and adding `max-width` constraint.
- Removed conflicting inline `<style>` block from the login template that overrode the modern design (old purple button, missing text colors).
- Fixed Update Manager desktop button layout by switching toolbar and pane actions from `inline-flex` to `flex` and removing rigid `flex-shrink: 0` so buttons wrap correctly.
- Restored the sort dropdown arrow indicator that was hidden by a CSS `background` shorthand override removing the Bootstrap background-image.
- Improved search icon alignment inside the toolbar pill with explicit `line-height` and `flex-shrink` properties.
- Enhanced Update Manager checkboxes with larger size, themed green border, and dark-mode visibility so selection controls are clearly visible in all tabs.

## v0.9.13

### Added
- Added Update Manager search, per-tab A-Z sorting, `Autoupdate selected`, and mobile-style icon tabs that reveal labels only for the active section.
- Added stricter backend deployment hardening with optional trusted-proxy support, secure session cookies, inactivity-based page-session expiry, and baseline security headers for reverse-proxy deployments.

### Changed
- Unified the app version surfaces on `v0.9.13`, including the UI footer, rendered pages, diagnostics payloads, SSE test fixtures, and release documentation.
- Reworked the login screen so desktop and mobile now share the dashboard-style background and a simpler centered brand block.

### Testing
- Expanded route and end-to-end coverage for Update Manager filtering, sorting, bulk auto-update, button sizing, version consistency, login rendering, and the new backend security headers and session policy.

## v0.9.12

- Prevented Update Manager inventory rendering from falling back to live registry lookups when sampler cache details are missing, which keeps the modal responsive on slow or unreachable registries.
- Reused the already-built update candidate inventory for the auto-update tab so ready targets still appear there even when they do not currently have a pending update.
- Added a 15 second timeout to Update Manager fetches in the dashboard and surface a clearer error when Docker or registry metadata takes too long to respond.

## v0.9.11

- Added a dedicated Auto-Update Management tab to the Update Manager with per-item enable and disable controls, support-aware inventory, and last update timestamps.
- Added background auto-update execution for opted-in standalone containers and Compose stacks when a newly detected update becomes available.
- Improved update notifications so they identify the updated container or stack and include the recorded version transition whenever it is available.

## v0.9.10

### Added
- Added modal-based chart and log workflows so comparison graphs, per-container history charts, and live logs stay inside the dashboard with responsive layouts, internal scrolling, and mobile-safe behavior.
- Added live log streaming controls with default tail limits, configurable line counts, auto-scroll pause/resume, and `.txt` download support.
- Added update-completion notifications for both successful and failed update actions, plus automatic cleanup for update history entries after 15 days with a visible retention notice in the history tab.

### Changed
- Simplified the mobile dashboard structure with a dedicated four-tab section navigation under the header for `Info`, `Workspace`, `Containers`, and `Stacks`.
- Refined modal sizing and viewport handling across the app so action buttons remain visible and modal content scrolls internally on desktop and mobile.
- Expanded notification timing controls to accept minutes and seconds for threshold windows, cooldowns, and deduplication intervals.
- Refreshed the README with updated product screenshots that reflect the current dashboard, charts, logs, and update-manager flows.

### Testing
- Extended backend and end-to-end coverage for modal charts, live logs, notification timing controls, update notifications, retention cleanup, and responsive mobile modal behavior.

## v0.9.9

### Added
- Added per-target selection checkboxes to the Update Manager for both Compose stacks and standalone containers, including `Shift` range selection and dedicated `Update selected` actions in each tab.

### Changed
- Batch updates now add their history entries locally as each target completes, so the history tab reflects successful or failed items immediately instead of waiting for the final inventory refresh.
- Reorganized the README into a cleaner product-style structure with clearer feature areas, quick start guidance, configuration tables, update-manager notes, and notification setup sections.

### Fixed
- Hardened the shared confirmation modal so confirm actions requested during the opening transition still close cleanly and continue into the requested update workflow.
- Stabilized the end-to-end update-manager coverage around modal transitions and the new selected-update flow.

## v0.9.8

### Added
- Added `Update all` actions to both Update Manager tabs so ready compose stacks and standalone containers can be updated from one place.

### Changed
- Bulk updates now run sequentially through the existing safe update workflow, with per-target progress surfaced in the live action modal and a single consolidated refresh at the end.

### Fixed
- Brought the E2E update-manager fixtures in line with the real external-stack lifecycle so synthetic Portainer-style targets appear before update, disappear once current, and return after rollback.
- Hardened end-to-end coverage around bulk stack and container updates, including progress summaries and disabled bulk buttons once no ready targets remain.

## v0.9.7

### Changed
- Rebalanced the main dashboard tabs so the active `Containers` or `Compose Stacks` state keeps a clear accent treatment on hover, with centered spacing and stronger visual hierarchy in both light and dark themes.
- Refined button theming across the dashboard, settings, notifications, update manager, admin controls, and theme toggles so dark mode keeps readable text, borders, and icons across default, hover, active, and disabled states.
- Stabilized modal presentation so centered dialogs keep their own internal scroll area and preserve visible action footers without shifting the page background when opened.

### Fixed
- Removed the global scrollbar gutter regression that was widening the document and breaking the container table layout checks after recent modal changes.
- Prevented light-mode active tabs from washing out on hover by stopping a later generic tab rule from overriding the intended active treatment.

### Testing
- Expanded end-to-end coverage for dark-mode button readability, tab hover contrast, centered modal layout, internal modal scrolling, and the existing container overflow constraints.

## v0.9.6

### Added
- Added a safe external stack update path for Compose projects whose original files are no longer accessible on disk, allowing Portainer/Yacht-style stacks to be updated by recreating the running services directly from Docker's current runtime metadata.
- Added rollback support for those externally managed stack updates using the recorded previous image versions and the same safe container recreation workflow.

### Changed
- Externally managed stacks with missing compose files now surface as updateable when statainer can safely operate on the running services, with explicit `External safe recreate` labeling and guidance in the Update Manager UI.

### Fixed
- Constrained Update Manager action modal copy so long progress and result messages wrap inside the modal instead of overflowing.
- Preserved all-or-nothing behavior for external stack updates by pulling required images first and automatically reverting already-updated services if a later service fails.

### Testing
- Expanded backend and end-to-end coverage for external stack updates, external stack rollback, blocked stack filtering, and action modal text containment.

## v0.9.5

### Added
- Added clearer blocked-stack diagnostics in the Update Manager, including external manager detection for Portainer/Yacht-style compose paths, missing-file details, recovery guidance, and explicit externally managed states.

### Changed
- Added a `Hide blocked` filter and `Quick Update` action to the Update Manager inventory for faster triage of update-ready targets.
- Added a live update action modal that reports progress, success, and failure in real time while update and rollback operations are running.
- Reordered the dashboard tabs so `Containers` comes first and refreshed the tab styling to better match the rest of the interface.
- Added temporary success feedback states for key actions such as `Save Settings`, `Save notification settings`, and `Send test`.

### Fixed
- Optimized Update Manager refreshes by deduplicating registry lookups per image reference and resolving them in parallel instead of rechecking each container sequentially.
- Kept blocked externally managed compose stacks visible but non-actionable, so statainer no longer presents them as update candidates it can safely manage.
- Contained horizontal overflow inside the `Containers` table block so enabling all columns does not push the whole page sideways.

### Testing
- Expanded backend and end-to-end coverage for blocked external compose stacks, button success feedback, tab order, internal table scrolling, and the new Update Manager action modal.

## v0.9.4

### Fixed
- Contained the containers table horizontal scroll inside the `Containers` panel again so the page no longer expands sideways with the table width.
- Added explicit width/min-width guards around the dashboard tab content and table shell to prevent document-level horizontal overflow regressions.

### Testing
- Added an end-to-end layout regression check to verify the document width stays equal to the viewport while `#tableView` keeps its own horizontal scrolling area.

## v0.9.3

### Changed
- Redesigned the Update Manager inventory into a compact, collapsed-by-default layout so Compose stacks, standalone containers, and history entries show only the item name plus the new target version until expanded.
- Added smooth expand/collapse transitions and a shared chevron-driven interaction model across Projects, Containers, and History tabs for higher information density and better visual consistency.

### Testing
- Updated the end-to-end Update Manager coverage to validate the collapsed-by-default behavior, on-demand expansion, and update/rollback actions from the expanded details panel.

## v0.9.2

### Changed
- Split the main dashboard into properly tabbed `Compose Stacks` and `Containers` views so only one view is displayed at a time.
- Moved update manager history into its own modal tab and switched the update inventory from block cards to a clearer list layout with columns for name, type, versions, state, last check, and action.
- Aligned the clear-notifications flow with the notification settings UX by using a dedicated confirmation modal and matching icon-button styling.

### Fixed
- Disabled security advisory notifications by default across backend defaults, frontend defaults, and test fixtures to stop noisy startup alerts.
- Hardened notification settings modal opening so it opens reliably on the first interaction.
- Hardened update manager modal opening and removed duplicate first-load work so the first interaction is responsive.
- Reduced false `blocked` update candidates by reusing sampler-cached update details when building the update manager inventory.
- Improved mobile overlay cleanup when opening notification actions from the pending notifications panel.

### Testing
- Added and updated route, sampler, update manager, and end-to-end tests for tab exclusivity, notification default states, clear-notification confirmation flow, update manager tabbed history, and cached update candidate rendering.

## v0.9.1

### Fixed
- Fixed Docker image packaging so all top-level Python modules are copied into the container image, including `update_manager.py`.
- Prevented the `ModuleNotFoundError: No module named 'update_manager'` crash on startup in Docker deployments.

### Testing
- Added a regression test to ensure the Dockerfile keeps copying all root Python modules.

## v0.9.0

### Added
- Notification delivery via `ntfy.sh` and generic HTTP webhooks, including authentication, tags, Markdown support, and structured event payloads.
- Step-by-step README documentation for `ntfy` and generic webhook notification setup.
- Notification management modal from the top bar, with advanced rules for project/container targeting, cooldowns, silencing windows, and deduplication.
- Basic security advisories that can be toggled from the UI for privileged containers, publicly exposed ports, `latest` image usage, and `/var/run/docker.sock` mounts.
- Compose project dashboard cards with per-stack CPU, RAM, status, updates, and restart totals.
- Experimental update manager with dedicated top-bar entry, separate views for standalone containers and Compose projects, safe update planning, persisted update history, and rollback support.
- Persistent update history storage and backend safety checks for update/rollback flows.
- Expanded automated coverage for notifications, security advisories, update manager flows, persistence, and end-to-end UI behavior.

### Changed
- Notifications entry in the top bar now opens the pending list and exposes gear/broom actions instead of in-panel settings controls.
- Notification configuration moved into a centered modal and the clear action now uses an icon-first interaction with tooltip text.
- Dashboard layout simplified by removing the overview visibility controls so the top panels keep matching heights.
- Container update endpoints now delegate to the new guarded update manager logic instead of performing a direct image refresh.
- Release version defaults updated to `v0.9.0`.

### Fixed
- Rollback targeting now resolves the correct container by stable container name instead of transient container IDs.
- Update manager refresh behavior now forces synchronous availability checks so the UI reflects newly detected updates reliably.
- Update status messaging persists correctly after refresh, and the E2E mock server returns consistent notification/update responses.

## v0.8.2

- Fixed database path resolution on fresh Docker installs and legacy bind mounts.

## v0.8.1

- Minor fixes.

## v0.8.0

### Added
- New dashboard interface with operational summary, quick filters, refresh pause/resume control, and Docker/notifications status indicators.
- Notification test feature available directly from the UI.
- Diagnostic endpoints: `/api/system-status` and `/api/notification-test`.
- Automated test suite covering routes, user database, metrics utilities, and Pushover client (`tests/test_routes.py`, `tests/test_users_db.py`, `tests/test_metrics_utils.py`, `tests/test_pushover_client.py`).
- End-to-end browser tests using Playwright for dashboard table, filters, container actions, and settings/user modals (`tests/e2e/dashboard.spec.js`).
- Deterministic E2E test server (`tests/e2e_server.py`).
- Playwright configuration and JS test tooling (`playwright.config.mjs`, `package.json`).
- Persistent audit log system with `audit_log` table and helpers for tracking sensitive actions (`users_db.py`).
- Admin endpoint to query audit logs (`routes.py`).
- Server-Sent Events (SSE) stream for real-time dashboard updates and notifications.

### Changed
- Full modernization of the main dashboard UI and login interface (`templates/index.html`, `static/dashboard-modern.css`, `templates/login.html`, `static/login-modern.css`).
- Backend refactored to use an app factory and allow startup in degraded mode when Docker is unavailable (`app.py`, `docker_client.py`).
- Dashboard JavaScript refactored: logic extracted from the template and organized into ES modules under `static/js/dashboard`, with `app.js` as the entry point.
- `templates/index.html` now loads Bootstrap and the dashboard module with global configuration.
- Frontend updated to consume a real-time SSE stream instead of browser polling, with automatic reconnection.
- Sampler synchronized with SSE using sequence counters and `Condition` signaling (`sampler.py`).
- Application configuration centralized in `config.py`, including versioning, authentication, and secrets management.
- Deployment configuration updated (`docker-compose.yml`).
- NVML integration migrated from `pynvml` to `nvidia-ml-py` (`requirements.txt`, `sampler.py`).

### Fixed
- Resolved password change bug when `LOGIN_MODE=page`.
- Removed deprecated NVML warning by migrating to `nvidia-ml-py`.

### Security
- Removed dependency on default `admin/admin` credentials.
- Added support for secrets via files and explicit ephemeral fallback for `APP_SECRET_KEY`.
- Added CSRF validation to the login flow.
- Restricted user and notification management to admin role.
- Application startup validation when `AUTH_ENABLED=true` to ensure bootstrap or existing users are present.
- Sensitive actions (password changes, user management, container operations) now recorded in the audit log.
