# -*- coding: utf-8 -*-
"""External programmatic API (``/api/v1``).

This blueprint is intentionally isolated from the session-based UI routes:
``main_routes`` enforces cookie/basic auth via a blueprint ``before_request``
hook, which does NOT run for this blueprint. Instead, every endpoint here is
guarded by the :func:`require_api` decorator which performs bearer-token
authentication, scope authorization, per-key rate limiting and audit logging.

Security model
--------------
* A global master toggle (Settings → API access) must be ON, otherwise every
  endpoint returns ``403 api_disabled``.
* Tokens are presented as ``Authorization: Bearer <token>`` (or ``X-API-Key``)
  and are matched against a stored SHA-256 hash; the plaintext is never stored.
* Each key carries an explicit set of scopes; missing scope -> ``403``.
* Per-key rate limiting and per-IP auth-failure throttling mitigate abuse and
  token guessing even when exposed through a reverse proxy.
"""

import collections
import multiprocessing
import threading
import time
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request

import api_keys
import container_ops
import sampler
import users_db
from config import (
    EXTERNAL_API_AUTH_FAIL_MAX,
    EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS,
    EXTERNAL_API_RATE_LIMIT_MAX,
    EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS,
    EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE,
)
from docker_client import get_docker_client
from update_notifications import build_update_result_event

api_v1 = Blueprint('api_v1', __name__, url_prefix='/api/v1')

# Container fields considered "metadata" (containers:read) vs live "stats".
META_FIELDS = (
    'id', 'name', 'status', 'image', 'ports', 'restarts', 'uptime', 'uptime_sec',
    'update_available', 'compose_project', 'compose_service',
)

ACTION_SCOPES = {
    'start': 'containers:start',
    'stop': 'containers:stop',
    'restart': 'containers:restart',
    'update': 'containers:update',
}

# ---------------------------------------------------------------------------
# In-memory throttling (per-key request rate + per-IP auth failures)
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
_request_counts: dict = {}
_auth_failures: dict = {}


def _prune(timestamps, cutoff):
    while timestamps and timestamps[0] <= cutoff:
        timestamps.popleft()


def _is_rate_limited(key_id):
    if EXTERNAL_API_RATE_LIMIT_MAX <= 0:
        return False, 0
    now = time.monotonic()
    cutoff = now - EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        timestamps = _request_counts.get(key_id)
        if timestamps is None:
            return False, 0
        _prune(timestamps, cutoff)
        if len(timestamps) >= EXTERNAL_API_RATE_LIMIT_MAX:
            retry_after = int(timestamps[0] + EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS - now) + 1
            return True, max(retry_after, 1)
    return False, 0


def _record_request(key_id):
    if EXTERNAL_API_RATE_LIMIT_MAX <= 0:
        return
    now = time.monotonic()
    with _rate_lock:
        _request_counts.setdefault(key_id, collections.deque()).append(now)


def _is_auth_blocked(ip_addr):
    if EXTERNAL_API_AUTH_FAIL_MAX <= 0:
        return False, 0
    now = time.monotonic()
    cutoff = now - EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS
    with _rate_lock:
        timestamps = _auth_failures.get(ip_addr)
        if timestamps is None:
            return False, 0
        _prune(timestamps, cutoff)
        if len(timestamps) >= EXTERNAL_API_AUTH_FAIL_MAX:
            retry_after = int(timestamps[0] + EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS - now) + 1
            return True, max(retry_after, 1)
    return False, 0


def _record_auth_failure(ip_addr):
    if EXTERNAL_API_AUTH_FAIL_MAX <= 0:
        return
    now = time.monotonic()
    with _rate_lock:
        _auth_failures.setdefault(ip_addr, collections.deque()).append(now)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _remote_addr():
    return request.remote_addr or (request.access_route[0] if request.access_route else None)


def _extract_token():
    header = request.headers.get('Authorization', '')
    if header:
        parts = header.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            return parts[1].strip()
    api_key_header = request.headers.get('X-API-Key')
    if api_key_header:
        return api_key_header.strip()
    return None


def _error(code, message, status, **extra):
    body = {'error': code, 'message': message}
    body.update(extra)
    response = jsonify(body)
    response.status_code = status
    if status == 401:
        response.headers['WWW-Authenticate'] = 'Bearer'
    retry_after = extra.get('retry_after')
    if retry_after:
        response.headers['Retry-After'] = str(retry_after)
    return response


def _audit_api(action, status, record, details=None):
    actor = f"api:{record['name']}" if record else None
    users_db.record_audit_event(
        action=action,
        target_type='api',
        status=status,
        actor_username=actor,
        actor_role='api',
        target_id=str(record['id']) if record else None,
        remote_addr=_remote_addr(),
        details=details or {},
    )


def require_api(*scopes, write=False):
    """Authenticate the bearer token and enforce the given scopes."""

    def decorator(func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not users_db.is_external_api_enabled():
                return _error('api_disabled', 'The external API is disabled.', 403)

            ip_addr = _remote_addr()
            blocked, retry_after = _is_auth_blocked(ip_addr)
            if blocked:
                return _error('rate_limited', 'Too many failed attempts. Try again later.', 429, retry_after=retry_after)

            token = _extract_token()
            record = api_keys.authenticate(token)
            if not record:
                _record_auth_failure(ip_addr)
                _audit_api('api.auth', 'failure', None, {'reason': 'invalid_or_missing_token', 'path': request.path})
                return _error('unauthorized', 'Invalid or missing API key.', 401)

            limited, retry_after = _is_rate_limited(record['id'])
            if limited:
                return _error('rate_limited', 'Rate limit exceeded.', 429, retry_after=retry_after)
            _record_request(record['id'])

            for scope in scopes:
                if not api_keys.has_scope(record, scope):
                    _audit_api('api.denied', 'failure', record, {'scope': scope, 'path': request.path})
                    return _error('forbidden', f"This key is missing the required scope '{scope}'.", 403, required_scope=scope)

            if write and EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE and not request.is_secure:
                return _error('https_required', 'HTTPS is required for write operations.', 403)

            g.api_key = record
            users_db.touch_api_key_usage(record['id'], ip_addr)
            return func(*args, **kwargs)

        return wrapped

    return decorator


def _collect_rows():
    """Reuse the dashboard metrics pipeline, honoring query filters."""
    from routes import collect_metrics_rows, parse_metrics_request_args

    query = parse_metrics_request_args(request.args)
    rows = collect_metrics_rows(query)
    for row in rows:
        row.pop('_allowed_columns', None)
    return rows


def _meta_view(row):
    return {field: row.get(field) for field in META_FIELDS}


def _match_container(rows, identifier):
    identifier = (identifier or '').strip()
    if not identifier:
        return None
    for row in rows:
        if row.get('id') == identifier or row.get('name') == identifier:
            return row
    for row in rows:
        if str(row.get('id', '')).startswith(identifier):
            return row
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@api_v1.route('/ping')
@require_api()
def api_ping():
    return jsonify({'ok': True, 'pong': True, 'version': current_app.config.get('APP_VERSION', 'dev')})


@api_v1.route('/me')
@require_api()
def api_me():
    record = g.api_key
    return jsonify({
        'name': record['name'],
        'scopes': record['scopes'],
        'created_at': record['created_at'],
        'expires_at': record['expires_at'],
        'last_used_at': record['last_used_at'],
    })


@api_v1.route('/system')
@require_api('system:read')
def api_system():
    cores = multiprocessing.cpu_count()
    payload = {
        'cpu_cores': cores,
        'max_cpu_percent': cores * 100,
        'app_version': current_app.config.get('APP_VERSION', 'dev'),
    }
    try:
        info = get_docker_client().info()
        mem_total = int(info.get('MemTotal', 0) or 0)
        payload.update({
            'cpu_count_docker': info.get('NCPU'),
            'memory_total_bytes': mem_total,
            'memory_total_mb': round(mem_total / 1048576, 2) if mem_total else None,
            'memory_total_gb': round(mem_total / 1073741824, 2) if mem_total else None,
            'containers': info.get('Containers'),
            'containers_running': info.get('ContainersRunning'),
            'containers_paused': info.get('ContainersPaused'),
            'containers_stopped': info.get('ContainersStopped'),
            'images': info.get('Images'),
            'docker_version': info.get('ServerVersion'),
            'operating_system': info.get('OperatingSystem'),
            'os_type': info.get('OSType'),
            'architecture': info.get('Architecture'),
            'kernel_version': info.get('KernelVersion'),
            'hostname': info.get('Name'),
        })
    except Exception as exc:  # noqa: BLE001
        return _error('docker_unavailable', f'Unable to read Docker host info: {exc}', 502, **payload)
    return jsonify(payload)


@api_v1.route('/containers')
@require_api('containers:read')
def api_containers():
    try:
        rows = _collect_rows()
    except RuntimeError as exc:
        return _error('docker_unavailable', str(exc), 502)
    containers = [_meta_view(row) for row in rows]
    running = sum(1 for row in rows if row.get('status') == 'running')
    exited = sum(1 for row in rows if row.get('status') == 'exited')
    return jsonify({
        'count': len(containers),
        'running': running,
        'exited': exited,
        'containers': containers,
    })


@api_v1.route('/containers/<container_id>')
@require_api('containers:read')
def api_container(container_id):
    try:
        rows = _collect_rows()
    except RuntimeError as exc:
        return _error('docker_unavailable', str(exc), 502)
    row = _match_container(rows, container_id)
    if not row:
        return _error('not_found', f'Container {container_id} not found.', 404)
    return jsonify(_meta_view(row))


@api_v1.route('/stats')
@require_api('stats:read')
def api_stats():
    try:
        rows = _collect_rows()
    except RuntimeError as exc:
        return _error('docker_unavailable', str(exc), 502)
    return jsonify({'count': len(rows), 'containers': rows})


@api_v1.route('/containers/<container_id>/stats')
@require_api('stats:read')
def api_container_stats(container_id):
    try:
        rows = _collect_rows()
    except RuntimeError as exc:
        return _error('docker_unavailable', str(exc), 502)
    row = _match_container(rows, container_id)
    if not row:
        return _error('not_found', f'Container {container_id} not found.', 404)
    return jsonify(row)


def _run_action(container_id, action):
    record = g.api_key
    result = container_ops.execute_container_action(action, container_id, actor_username=f"api:{record['name']}")
    status = 'success' if result.get('ok') else 'failure'
    _audit_api(f'container.{action}', status, record, {
        'container_id': result.get('container_id') or container_id,
        'name': result.get('name'),
        'message': result.get('message'),
        'via': 'api',
    })

    if action == 'update' and result.get('name'):
        try:
            event = build_update_result_event(
                'container',
                result.get('container_id') or container_id,
                result.get('name'),
                bool(result.get('ok')),
                history_entry=result.get('history_entry'),
                fallback_message=result.get('message'),
            )
            sampler.emit_notification(event)
        except Exception as exc:  # noqa: BLE001
            print(f"WARN API UPDATE NOTIF: {exc}")

    body = {
        'ok': bool(result.get('ok')),
        'action': action,
        'container_id': result.get('container_id') or container_id,
        'name': result.get('name'),
        'message': result.get('message'),
    }
    if result.get('error'):
        body['error'] = result['error']
    if result.get('history_entry'):
        body['history_entry'] = result['history_entry']
    return jsonify(body), result.get('status_code', 200)


@api_v1.route('/containers/<container_id>/start', methods=['POST'])
@require_api(ACTION_SCOPES['start'], write=True)
def api_container_start(container_id):
    return _run_action(container_id, 'start')


@api_v1.route('/containers/<container_id>/stop', methods=['POST'])
@require_api(ACTION_SCOPES['stop'], write=True)
def api_container_stop(container_id):
    return _run_action(container_id, 'stop')


@api_v1.route('/containers/<container_id>/restart', methods=['POST'])
@require_api(ACTION_SCOPES['restart'], write=True)
def api_container_restart(container_id):
    return _run_action(container_id, 'restart')


@api_v1.route('/containers/<container_id>/update', methods=['POST'])
@require_api(ACTION_SCOPES['update'], write=True)
def api_container_update(container_id):
    return _run_action(container_id, 'update')
