# -*- coding: utf-8 -*-

import collections
import datetime
import hmac
import threading
import time  # Add time import
import requests  # Añadido para peticiones HTTP a cAdvisor
from flask import Blueprint, current_app, jsonify, request, render_template, Response, stream_with_context, session, redirect, url_for
from markupsafe import escape  # Añadido para compatibilidad Flask >=2.3
import docker
import json  # Add json import for embedding data
import secrets
import multiprocessing  # Add for CPU core detection
from functools import wraps
from update_notifications import build_update_result_event
from users_db import (
    validate_user, change_password, create_user_with_columns, list_users_with_columns,
    update_user_columns, delete_user, get_user_columns, get_user_role, user_exists,
    list_audit_events, record_audit_event,
    list_api_keys, get_api_key_by_id, set_api_key_enabled, delete_api_key,
    get_external_api_settings, set_external_api_settings
)
import api_keys as api_keys_service
import update_manager
errors = docker.errors

# Importar estado compartido y clientes/utilidades necesarias
import sampler
from sampler import history  # Solo importar history para uso local
from docker_client import get_api_client, get_docker_client, get_docker_status # Necesario para ambas APIs
from metrics_utils import parse_datetime, format_uptime # Necesario para /api/metrics
from pushover_client import get_configured_services, send as send_notification

# Crear un Blueprint para las rutas
main_routes = Blueprint('main_routes', __name__, template_folder='templates', static_folder='static')

# ---------------------------------------------------------------------------
# Login rate limiter (in-memory, per-IP)
# ---------------------------------------------------------------------------
_login_attempts_lock = threading.Lock()
_login_attempts: dict[str, collections.deque] = {}

# Upper bound on the number of distinct client IPs tracked simultaneously. The
# tracking dict is purged of stale buckets first; if a flood of spoofed/rotating
# source IPs still keeps it at capacity, the oldest buckets are evicted. This
# bounds memory so the limiter itself cannot be turned into a memory-exhaustion
# DoS vector (e.g. via attacker-controlled X-Forwarded-For behind a proxy).
_MAX_TRACKED_IPS = 10000


def _get_rate_limit_config():
    max_attempts = current_app.config.get('LOGIN_RATE_LIMIT_MAX_ATTEMPTS', 5)
    window = current_app.config.get('LOGIN_RATE_LIMIT_WINDOW_SECONDS', 300)
    return int(max_attempts), int(window)


def _prune_attempts(timestamps, cutoff):
    while timestamps and timestamps[0] <= cutoff:
        timestamps.popleft()


def _purge_stale_buckets_locked(now, window):
    """Drop empty/expired per-IP buckets. Caller must hold _login_attempts_lock."""
    cutoff = now - window
    for ip in list(_login_attempts.keys()):
        timestamps = _login_attempts[ip]
        _prune_attempts(timestamps, cutoff)
        if not timestamps:
            del _login_attempts[ip]


def is_login_rate_limited(ip_addr):
    max_attempts, window = _get_rate_limit_config()
    if max_attempts <= 0:
        return False, 0
    now = time.monotonic()
    cutoff = now - window
    with _login_attempts_lock:
        timestamps = _login_attempts.get(ip_addr)
        if timestamps is None:
            return False, 0
        _prune_attempts(timestamps, cutoff)
        if len(timestamps) >= max_attempts:
            retry_after = int(timestamps[0] + window - now) + 1
            return True, max(retry_after, 1)
        return False, 0


def record_failed_login(ip_addr):
    max_attempts, window = _get_rate_limit_config()
    if max_attempts <= 0:
        return
    now = time.monotonic()
    with _login_attempts_lock:
        if ip_addr not in _login_attempts and len(_login_attempts) >= _MAX_TRACKED_IPS:
            # At capacity with a new IP: reclaim space from expired buckets, then
            # evict oldest buckets if a genuine flood is still keeping us full.
            _purge_stale_buckets_locked(now, window)
            while len(_login_attempts) >= _MAX_TRACKED_IPS:
                _login_attempts.pop(next(iter(_login_attempts)), None)
        if ip_addr not in _login_attempts:
            _login_attempts[ip_addr] = collections.deque()
        _login_attempts[ip_addr].append(now)


def reset_login_attempts(ip_addr):
    with _login_attempts_lock:
        _login_attempts.pop(ip_addr, None)

def auth_enabled():
    return bool(current_app.config.get('AUTH_ENABLED', True))


def login_mode():
    return current_app.config.get('LOGIN_MODE', 'popup')

# --- Check if the user is authenticated for page-based login ---
def is_authenticated():
    return session.get('authenticated', False)


def get_request_username():
    return session.get('username') or (request.authorization.username if request.authorization else None)


def get_request_role():
    username = get_request_username()
    if not username:
        return None
    return get_user_role(username)


def get_request_remote_addr():
    return request.remote_addr or (request.access_route[0] if request.access_route else None)


def audit_event(action, target_type, status, target_id=None, details=None):
    record_audit_event(
        action=action,
        target_type=target_type,
        status=status,
        actor_username=get_request_username(),
        actor_role=get_request_role(),
        target_id=target_id,
        remote_addr=get_request_remote_addr(),
        details=details,
    )


def sse_event(event_name, payload):
    return f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"


def parse_positive_int_arg(value, default, *, minimum=0, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def parse_log_tail_arg():
    return parse_positive_int_arg(request.args.get('tail', 100), 100, minimum=1, maximum=10000)


def read_container_log_text(container, tail):
    raw_logs = container.logs(tail=tail, timestamps=True)
    if isinstance(raw_logs, bytes):
        return raw_logs.decode('utf-8', errors='replace')
    return str(raw_logs or '')


def sanitize_download_filename(value, fallback='container'):
    token = ''.join(ch if ch.isalnum() or ch in '-._' else '-' for ch in str(value or '').strip())
    cleaned = token.strip('.-_')
    return cleaned or fallback


def emit_update_result_notification(target_type, target_id, target_name, message, ok, history_entry=None):
    event = build_update_result_event(
        target_type,
        target_id,
        target_name,
        bool(ok),
        history_entry=history_entry,
        fallback_message=message,
    )
    try:
        sampler.emit_notification(event)
    except Exception as exc:
        print(f"WARN UPDATE NOTIF: Unable to emit {target_type} update notification for {target_id}: {exc}")

# --- CSRF Token Utilities ---
def generate_csrf_token():
    session.permanent = True
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def has_valid_csrf_token():
    token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
    expected = session.get('csrf_token')
    if not token or not expected:
        return False
    # Constant-time comparison so the token cannot be guessed via timing.
    return hmac.compare_digest(str(token), str(expected))


def validate_csrf():
    if not has_valid_csrf_token():
        return jsonify({'error': 'Invalid CSRF token'}), 403

# Decorator for CSRF protection
def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        result = validate_csrf()
        if result is not None:
            return result
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = get_request_username()
        if not username:
            return jsonify({'error': 'Authentication required'}), 401
        if get_request_role() != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Login Route for Page-Based Authentication ---
def _no_store_headers(extra=None):
    """Headers preventing the login page (and its CSRF token) from being cached."""
    headers = {'Cache-Control': 'no-store, max-age=0', 'Pragma': 'no-cache'}
    if extra:
        headers.update(extra)
    return headers


@main_routes.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login for page-based authentication"""
    # If no credentials are set or login mode is not 'page', redirect to index
    if not auth_enabled() or login_mode() != 'page':
        return redirect(url_for('main_routes.index'))
    
    # If already authenticated, redirect to index
    if is_authenticated():
        return redirect(url_for('main_routes.index'))
    
    # Generate CSRF token for the form
    csrf_token = generate_csrf_token()
    
    # Handle login form submission
    error = None
    if request.method == 'POST':
        if not has_valid_csrf_token():
            error = "Invalid or expired session. Reload the page and try again."
            return render_template('login.html', csrf_token=generate_csrf_token(), error=error), 403, _no_store_headers()

        client_ip = get_request_remote_addr()
        limited, retry_after = is_login_rate_limited(client_ip)
        if limited:
            error = f"Too many failed login attempts. Try again in {retry_after} seconds."
            record_audit_event(
                action='login',
                target_type='session',
                status='failure',
                actor_username=request.form.get('username'),
                actor_role=None,
                target_id=request.form.get('username'),
                remote_addr=client_ip,
                details={'mode': 'page', 'reason': 'rate_limited'},
            )
            response = render_template('login.html', csrf_token=generate_csrf_token(), error=error)
            return response, 429, _no_store_headers({'Retry-After': str(retry_after)})

        username = request.form.get('username')
        password = request.form.get('password')
        
        if validate_user(username, password):
            reset_login_attempts(client_ip)
            session.permanent = True
            session['authenticated'] = True
            session['username'] = username
            audit_event('login', 'session', 'success', target_id=username, details={'mode': 'page'})
            return redirect(url_for('main_routes.index'))
        else:
            record_failed_login(client_ip)
            record_audit_event(
                action='login',
                target_type='session',
                status='failure',
                actor_username=username,
                actor_role=get_user_role(username) if username and user_exists(username) else None,
                target_id=username,
                remote_addr=client_ip,
                details={'mode': 'page', 'reason': 'invalid_credentials'},
            )
            error = "Invalid username or password"

    return render_template('login.html', csrf_token=csrf_token, error=error), 200, _no_store_headers()

# --- Logout Route ---
@main_routes.route('/logout')
def logout():
    """Handle logout for page-based authentication"""
    username = get_request_username()
    # Clear the entire session instead of just removing 'authenticated'
    session.clear()
    
    # Create a response with redirect
    response = redirect(url_for('main_routes.login'))
    
    # Add cache control headers to prevent caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Add a cookie expiration header to force removal of the session cookie
    response.delete_cookie(
        current_app.config.get('SESSION_COOKIE_NAME', 'session'),
        secure=current_app.config.get('SESSION_COOKIE_SECURE', False),
        httponly=current_app.config.get('SESSION_COOKIE_HTTPONLY', True),
        samesite=current_app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'),
    )
    if username:
        record_audit_event(
            action='logout',
            target_type='session',
            status='success',
            actor_username=username,
            actor_role=get_user_role(username),
            target_id=username,
            remote_addr=get_request_remote_addr(),
            details={'mode': login_mode()},
        )
    
    return response

# --- Authentication Middleware ---
@main_routes.before_request
def require_auth():
    # Skip authentication for static files and login page
    if request.path.startswith('/static/') or request.path == '/login' or request.path == '/favicon.ico':
        return

    if auth_enabled() and login_mode() == 'page' and is_authenticated():
        session.permanent = True
        session.modified = True
        
    # If credentials are not set, skip authentication
    if not auth_enabled():
        return
        
    # Determine authentication method based on LOGIN_MODE
    if login_mode() == 'page':
        # For page-based auth, check if user is authenticated in the session
        if not is_authenticated():
            # If not authenticated and requesting API endpoint, return JSON 401 error
            if request.path.startswith('/api/'):
                return jsonify({"error": "auth", "message": "Authentication required"}), 401
            # Otherwise redirect to login page
            if request.path != '/login':
                return redirect(url_for('main_routes.login'))
    else:
        # For popup-based auth (HTTP Basic), check Authorization header
        client_ip = get_request_remote_addr()
        limited, retry_after = is_login_rate_limited(client_ip)
        if limited:
            if request.path.startswith('/api/'):
                payload = jsonify({"error": "rate_limited", "message": f"Too many failed login attempts. Try again in {retry_after} seconds."})
                return payload, 429, {'Retry-After': str(retry_after)}
            return Response(f'Too many failed login attempts. Try again in {retry_after} seconds.', 429, {'Retry-After': str(retry_after)})
        auth = request.authorization
        if not auth or not validate_user(auth.username, auth.password):
            if auth and auth.username:
                record_failed_login(client_ip)
            # If requesting API endpoint, return JSON 401 error
            if request.path.startswith('/api/'):
                return jsonify({"error": "auth", "message": "Authentication required"}), 401
            # Otherwise return standard HTTP 401 with Basic auth prompt
            return Response('Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        reset_login_attempts(client_ip)

# --- Ruta Index ---
@main_routes.route('/')
def index():
    """Sirve la página HTML principal."""
    print("DEBUG: Serving index.html")
    csrf_token = generate_csrf_token()
    # Detectar número de cores de CPU
    cpu_cores = multiprocessing.cpu_count()
    max_cpu_percent = cpu_cores * 100
    # Obtener RAM total del host usando Docker API
    try:
        from docker_client import get_docker_client
        info = get_docker_client().info()
        max_ram_mb = int(info.get('MemTotal', 0)) // (1024 * 1024)
    except Exception as e:
        print(f"WARN: Unable to read total host RAM from Docker API: {e}")
        max_ram_mb = None
    return render_template('index.html', csrf_token=csrf_token, cpu_cores=cpu_cores, max_cpu_percent=max_cpu_percent, max_ram_mb=max_ram_mb)


@main_routes.route('/api/system-status')
def api_system_status():
    """Expose backend connectivity and notification channel status for the UI."""
    username = get_request_username()
    return jsonify({
        'docker': get_docker_status(),
        'notifications': get_configured_services(),
        'auth': {
            'enabled': auth_enabled(),
            'mode': login_mode(),
            'username': username,
            'role': get_request_role(),
        },
        'app': {
            'version': current_app.config.get('APP_VERSION', 'dev'),
            'ephemeral_secret_key': bool(current_app.config.get('APP_SECRET_KEY_EPHEMERAL')),
        },
    })

def get_cadvisor_metrics():
    """Obtiene métricas de cAdvisor para todos los contenedores."""
    try:
        cadvisor_url = current_app.config.get('CADVISOR_URL', 'http://cadvisor:8080')
        resp = requests.get(f'{cadvisor_url}/api/v1.3/subcontainers', timeout=2)
        if resp.status_code != 200:
            print(f"WARN: cAdvisor responded with status {resp.status_code}")
            return {}
        data = resp.json()
        metrics = {}
        for entry in data:
            # cAdvisor usa el nombre completo del contenedor, buscar el ID al final
            if 'docker' in entry.get('aliases', []):
                # cAdvisor para el propio contenedor de Docker
                continue
            if 'docker' in entry.get('spec', {}).get('labels', {}):
                # cAdvisor para el propio contenedor de Docker
                continue
            # Buscar ID Docker
            docker_id = None
            for alias in entry.get('aliases', []):
                if len(alias) == 64:
                    docker_id = alias
                    break
            if not docker_id:
                # Buscar en labels
                docker_id = entry.get('spec', {}).get('labels', {}).get('io.kubernetes.docker.id')
            if not docker_id:
                continue
            metrics[docker_id] = entry
        return metrics
    except Exception as e:
        print(f"WARN: Unable to fetch cAdvisor metrics: {e}")
        return {}

# --- Global: Store last cAdvisor stats for delta CPU calculation ---
cadvisor_last_stats = {}

def parse_metrics_request_args(args):
    try:
        max_items = int(args.get('max', 0) or 0)
    except (TypeError, ValueError):
        max_items = 0
    try:
        stream_interval_ms = max(1000, int(args.get('stream_interval', 5000) or 5000))
    except (TypeError, ValueError):
        stream_interval_ms = 5000
    return {
        'project_filter': args.get('project', '').strip(),
        'name_filter': args.get('name', '').lower().strip(),
        'status_filter': args.get('status', '').strip(),
        'sort_by': args.get('sort', 'combined'),
        'sort_dir': args.get('dir', 'desc'),
        'max_items': max_items,
        'gpu_requested': args.get('gpu', '0') == '1',
        'force_update': args.get('force', 'false').lower() == 'true',
        'source': args.get('source', 'cadvisor').lower(),
        'stream_interval_ms': stream_interval_ms,
    }


def collect_metrics_rows(query):
    print("DEBUG: Collecting metrics")
    client = get_docker_client()
    get_api_client()

    project_filter = query['project_filter']
    name_filter = query['name_filter']
    status_filter = query['status_filter']
    sort_by = query['sort_by']
    sort_dir = query['sort_dir']
    max_items = query['max_items']
    gpu_requested = query['gpu_requested']
    force_update = query['force_update']
    source = query['source']

    if force_update:
        sampler.force_update_check_all = True

    cadvisor_metrics = get_cadvisor_metrics() if source == 'cadvisor' else {}

    rows = []
    current_history_keys = list(history.keys())
    print(f"DEBUG API: Processing {len(current_history_keys)} container IDs from history.")

    for cid in current_history_keys:
        if cid not in history:
            print(f"DEBUG API: Container ID {cid[:6]}.. not found in history (removed?).")
            continue

        dq = history[cid]
        latest_sample = None
        if dq:
            try:
                latest_sample = dq[-1]
                if len(latest_sample) == 15:
                    ts, cpu, mem, status_hist, name_hist, net_rx, net_tx, blk_r, blk_w, update_available, pid_count, mem_limit_mb, mem_usage_mib, gpu_stats, gpu_max = latest_sample
                elif len(latest_sample) == 14:
                    ts, cpu, mem, status_hist, name_hist, net_rx, net_tx, blk_r, blk_w, update_available, pid_count, mem_limit_mb, mem_usage_mib, gpu_stats = latest_sample
                    gpu_max = None
                elif len(latest_sample) == 13:
                    ts, cpu, mem, status_hist, name_hist, net_rx, net_tx, blk_r, blk_w, update_available, pid_count, mem_limit_mb, mem_usage_mib = latest_sample
                    gpu_stats = None
                    gpu_max = None
                elif len(latest_sample) == 12:
                    ts, cpu, mem, status_hist, name_hist, net_rx, net_tx, blk_r, blk_w, update_available, pid_count, mem_limit_mb = latest_sample
                    mem_usage_mib = None
                    gpu_stats = None
                    gpu_max = None
                elif len(latest_sample) == 10:
                    ts, cpu, mem, status_hist, name_hist, net_rx, net_tx, blk_r, blk_w, update_available = latest_sample
                    pid_count = None
                    mem_limit_mb = None
                    mem_usage_mib = None
                    gpu_stats = None
                    gpu_max = None
                else:
                    ts, cpu, mem, status_hist, name_hist, net_rx, net_tx, blk_r, blk_w = latest_sample
                    update_available = None
                    pid_count = None
                    mem_limit_mb = None
                    mem_usage_mib = None
                    gpu_stats = None
                    gpu_max = None

                cpu = float(cpu) if cpu is not None else None
                mem = float(mem) if mem is not None else None
            except (ValueError, IndexError, TypeError) as sample_err:
                print(f"DEBUG API: Error while processing the latest sample for {cid[:6]}..: {sample_err}")
                continue
        else:
            print(f"DEBUG API: Empty history deque for {cid[:6]}..")
            continue

        container_name = name_hist
        if name_filter and name_filter not in container_name.lower():
            continue

        image_name = "N/A"
        ports_str = "N/A"
        restart_count = 0
        uptime_sec = None
        formatted_uptime = "N/A"
        current_status = status_hist
        compose_project = None
        compose_service = None
        pid_count = None
        mem_limit_mb = None

        try:
            container = client.containers.get(cid)
            current_status = container.status
            attrs = container.attrs or {}
            labels = attrs.get('Config', {}).get('Labels', {}) or {}
            compose_project = labels.get('com.docker.compose.project')
            compose_service = labels.get('com.docker.compose.service')
            if project_filter and project_filter != compose_project:
                continue
            if status_filter and current_status != status_filter:
                continue

            state = attrs.get('State', {})
            try:
                pid_count = attrs.get('State', {}).get('Pid')
                mem_bytes = attrs.get('HostConfig', {}).get('Memory', 0)
                mem_limit_mb = round(mem_bytes / 1048576, 2) if mem_bytes else None
            except Exception:
                pid_count = None
                mem_limit_mb = None

            try:
                if container.image and container.image.tags:
                    image_name = container.image.tags[0]
                elif container.image:
                    image_name = str(container.image.id).replace("sha256:", "")[:12]
            except Exception:
                image_name = "Error"

            try:
                ports_list = []
                if container.ports:
                    for c_port, h_bind in sorted(container.ports.items()):
                        if h_bind:
                            h_info = [
                                f"{b.get('HostIp', '')}:{b.get('HostPort', '')}"
                                if b.get('HostIp') and b.get('HostIp') not in ['0.0.0.0', '::'] and b.get('HostPort')
                                else b.get('HostPort', '')
                                for b in h_bind if b.get('HostPort')
                            ]
                            if h_info:
                                ports_list.append(f"{', '.join(h_info)}->{c_port}")
                ports_str = ', '.join(ports_list) if ports_list else "None"
            except Exception:
                ports_str = "Error"

            restart_count = attrs.get('RestartCount', 0)
            started_at_str = state.get('StartedAt')
            if current_status == 'running' and started_at_str:
                started_dt = parse_datetime(started_at_str)
                if started_dt:
                    now_utc = datetime.datetime.now(datetime.timezone.utc)
                    if started_dt.tzinfo is None:
                        started_dt = started_dt.replace(tzinfo=datetime.timezone.utc)
                    uptime_sec = max(0, int((now_utc - started_dt).total_seconds()))
                    formatted_uptime = format_uptime(uptime_sec)
                else:
                    formatted_uptime = "Error Parse Start"
                    uptime_sec = None
            elif current_status == 'exited':
                formatted_uptime = "N/A (Exited)"
                uptime_sec = None
            else:
                formatted_uptime = "N/A"
                uptime_sec = None

        except errors.NotFound:
            if project_filter:
                continue
            if status_filter and status_hist != status_filter:
                continue
            current_status = status_hist
            formatted_uptime = "N/A (Removed)"
            uptime_sec = None
        except errors.DockerException as exc:
            print(f"WARN API: Docker error while fetching details for {cid[:6]}.. ({container_name}): {exc}")
            if status_filter and status_hist != status_filter:
                continue
            current_status = status_hist
            formatted_uptime = "Error Fetching"
            uptime_sec = None
        except Exception as exc:
            print(f"ERROR API: Unexpected error while processing {cid[:6]}.. ({container_name}): {exc}")
            if status_filter and status_hist != status_filter:
                continue
            current_status = status_hist
            formatted_uptime = "Error"
            uptime_sec = None

        if source == 'cadvisor' and cid in cadvisor_metrics:
            cad = cadvisor_metrics[cid]
            try:
                stats = cad.get('stats', [])
                if len(stats) >= 2:
                    prev, last = stats[-2], stats[-1]
                    try:
                        last_ts = datetime.datetime.fromisoformat(last['timestamp'].rstrip('Z'))
                        prev_ts = datetime.datetime.fromisoformat(prev['timestamp'].rstrip('Z'))
                        interval_ns = (last_ts - prev_ts).total_seconds() * 1e9
                        delta_total = last['cpu']['usage']['total'] - prev['cpu']['usage']['total']
                        if interval_ns > 0 and delta_total >= 0:
                            cpu = (delta_total / interval_ns) * 100
                        else:
                            cpu = 0.0
                        cpu = round(cpu, 2)
                    except Exception:
                        pass
                    try:
                        mem = (last['memory']['usage'] / last['memory']['limit']) * 100 if last['memory']['limit'] else None
                        if mem is not None:
                            mem = round(mem, 2)
                    except Exception:
                        pass
                    try:
                        net_rx = sum(i.get('rx_bytes', 0) for i in last.get('network', {}).get('interfaces', [])) / (1024 * 1024)
                        net_tx = sum(i.get('tx_bytes', 0) for i in last.get('network', {}).get('interfaces', [])) / (1024 * 1024)
                        net_rx = round(net_rx, 2)
                        net_tx = round(net_tx, 2)
                    except Exception:
                        net_rx = net_tx = None
                    try:
                        blk_r = blk_w = None
                        for entry in last.get('diskio', {}).get('io_service_bytes', []):
                            if entry.get('op') == 'Read':
                                blk_r = entry.get('value', 0) / (1024 * 1024)
                            elif entry.get('op') == 'Write':
                                blk_w = entry.get('value', 0) / (1024 * 1024)
                        if blk_r is not None:
                            blk_r = round(blk_r, 2)
                        if blk_w is not None:
                            blk_w = round(blk_w, 2)
                    except Exception:
                        blk_r = blk_w = None
                    row_data = {
                        'id': cid,
                        'name': container_name,
                        'pid_count': pid_count,
                        'mem_limit': mem_limit_mb,
                        'mem_usage': mem_usage_mib,
                        'cpu': cpu,
                        'mem': mem,
                        'combined': (cpu or 0) + (mem or 0),
                        'status': current_status,
                        'uptime_sec': uptime_sec,
                        'uptime': formatted_uptime,
                        'net_io_rx': net_rx,
                        'net_io_tx': net_tx,
                        'block_io_r': blk_r,
                        'block_io_w': blk_w,
                        'image': image_name,
                        'ports': ports_str,
                        'restarts': restart_count,
                        'update_available': update_available,
                        'compose_project': compose_project,
                        'compose_service': compose_service,
                    }
                    if gpu_requested:
                        row_data['gpu'] = gpu_stats
                        row_data['gpu_max'] = gpu_max
                    rows.append(row_data)
                    continue
            except Exception as exc:
                print(f"WARN: Error while processing cAdvisor metrics for {cid[:12]}: {exc}")

        row_data = {
            'id': cid,
            'name': container_name,
            'pid_count': pid_count,
            'mem_limit': mem_limit_mb,
            'mem_usage': mem_usage_mib,
            'cpu': cpu,
            'mem': mem,
            'combined': (cpu or 0) + (mem or 0),
            'status': current_status,
            'uptime_sec': uptime_sec,
            'uptime': formatted_uptime,
            'net_io_rx': net_rx,
            'net_io_tx': net_tx,
            'block_io_r': blk_r,
            'block_io_w': blk_w,
            'image': image_name,
            'ports': ports_str,
            'restarts': restart_count,
            'update_available': update_available,
            'compose_project': compose_project,
            'compose_service': compose_service,
        }
        if gpu_requested:
            row_data['gpu'] = gpu_stats
            row_data['gpu_max'] = gpu_max
        rows.append(row_data)

    username = get_request_username()
    allowed_columns = None
    if username and get_user_role(username) != 'admin':
        allowed_columns = set(get_user_columns(username))
        allowed_columns.add('id')
        allowed_columns.add('name')

    if allowed_columns is not None:
        for row in rows:
            row['_allowed_columns'] = list(allowed_columns)

    reverse_sort = (sort_dir == 'desc')
    numeric_keys = ['cpu', 'mem', 'combined', 'uptime_sec', 'restarts', 'net_io_rx', 'net_io_tx', 'block_io_r', 'block_io_w', 'pid_count', 'mem_limit', 'update_available', 'gpu_max', 'mem_usage_limit']
    string_keys = ['name', 'status', 'image', 'ports', 'uptime']

    def sort_key(item):
        key_value = item.get(sort_by)
        if sort_by == 'mem_usage_limit':
            mem_percentage = item.get('mem')
            return mem_percentage if mem_percentage is not None else float('-inf')
        if sort_by in numeric_keys:
            if isinstance(key_value, bool):
                return int(key_value)
            if sort_by == 'update_available' and key_value is None:
                return -1
            return key_value if key_value is not None else float('-inf')
        if sort_by in string_keys:
            return str(key_value) if key_value is not None else ''
        return key_value if key_value is not None else ''

    try:
        rows.sort(key=sort_key, reverse=reverse_sort)
    except TypeError as exc:
        print(f"WARN API: Sorting error (key '{sort_by}', type: {type(exc)}): {exc}. Falling back to name sorting.")
        rows.sort(key=lambda x: str(x.get('name', '')).lower(), reverse=False)

    if max_items > 0:
        rows = rows[:max_items]

    return rows


def build_project_summaries(rows):
    projects = {}

    for row in rows:
        project = row.get('compose_project')
        if not project:
            continue

        bucket = projects.setdefault(project, {
            'project': project,
            'container_count': 0,
            'running_count': 0,
            'exited_count': 0,
            'other_count': 0,
            'update_count': 0,
            'restart_count': 0,
            'cpu_total': 0.0,
            'mem_usage_total': 0.0,
            'mem_limit_total': 0.0,
            'mem_avg_percent': 0.0,
            '_mem_samples': 0,
        })

        bucket['container_count'] += 1
        status = str(row.get('status') or '').lower()
        if status == 'running':
            bucket['running_count'] += 1
        elif status == 'exited':
            bucket['exited_count'] += 1
        else:
            bucket['other_count'] += 1

        if row.get('update_available') is True:
            bucket['update_count'] += 1

        try:
            bucket['restart_count'] += int(row.get('restarts') or 0)
        except (TypeError, ValueError):
            pass

        try:
            cpu_value = float(row.get('cpu'))
            bucket['cpu_total'] += cpu_value
        except (TypeError, ValueError):
            pass

        try:
            mem_usage = float(row.get('mem_usage'))
            bucket['mem_usage_total'] += mem_usage
        except (TypeError, ValueError):
            pass

        try:
            mem_limit = float(row.get('mem_limit'))
            if mem_limit > 0:
                bucket['mem_limit_total'] += mem_limit
        except (TypeError, ValueError):
            pass

        try:
            mem_percent = float(row.get('mem'))
            bucket['mem_avg_percent'] += mem_percent
            bucket['_mem_samples'] += 1
        except (TypeError, ValueError):
            pass

    summaries = []
    for project, bucket in sorted(projects.items()):
        mem_samples = bucket.pop('_mem_samples', 0)
        mem_avg_percent = (bucket['mem_avg_percent'] / mem_samples) if mem_samples else 0.0
        if bucket['container_count'] and bucket['running_count'] == bucket['container_count'] and bucket['other_count'] == 0:
            status = 'healthy'
        elif bucket['running_count'] == 0 and bucket['exited_count'] == bucket['container_count']:
            status = 'stopped'
        else:
            status = 'degraded'

        mem_pressure_percent = None
        if bucket['mem_limit_total'] > 0:
            mem_pressure_percent = (bucket['mem_usage_total'] / bucket['mem_limit_total']) * 100

        summaries.append({
            **bucket,
            'status': status,
            'cpu_total': round(bucket['cpu_total'], 2),
            'mem_usage_total': round(bucket['mem_usage_total'], 2),
            'mem_limit_total': round(bucket['mem_limit_total'], 2),
            'mem_avg_percent': round(mem_avg_percent, 2),
            'mem_pressure_percent': round(mem_pressure_percent, 2) if mem_pressure_percent is not None else None,
        })

    return summaries


def build_metrics_payload(query):
    full_query = dict(query)
    full_query['max_items'] = 0
    full_rows = collect_metrics_rows(full_query)
    max_items = query.get('max_items', 0)
    rows = full_rows[:max_items] if max_items and max_items > 0 else full_rows
    return {
        'rows': rows,
        'project_summaries': build_project_summaries(full_rows),
    }


# --- Ruta API Metrics ---
@main_routes.route('/api/metrics')
def api_metrics():
    """Endpoint API para obtener métricas de contenedores filtradas y ordenadas."""
    print("DEBUG: Request received at /api/metrics")
    try:
        query = parse_metrics_request_args(request.args)
        if request.args.get('summary', '0') == '1':
            return jsonify(build_metrics_payload(query))
        rows = collect_metrics_rows(query)
    except RuntimeError as exc:
        print(f"ERROR API: /api/metrics called before the Docker client was initialized: {exc}")
        return jsonify({"error": "Docker client not initialized"}), 500
    print(f"DEBUG API: Returning {len(rows)} rows.")
    return jsonify(rows)


@main_routes.route('/api/stream')
def api_stream():
    """SSE stream for metrics snapshots and backend notifications."""
    query = parse_metrics_request_args(request.args)
    send_once = request.args.get('once', '0') == '1'
    heartbeat_seconds = max(5, int(current_app.config.get('STREAM_HEARTBEAT_SECONDS', 15)))
    try:
        initial_notif_ts = float(request.args.get('since', 0) or 0)
    except (TypeError, ValueError):
        initial_notif_ts = 0.0

    def generate():
        last_notif_ts = initial_notif_ts
        last_metrics_seq = sampler.get_metrics_sequence()
        last_notification_seq = sampler.get_notification_sequence()
        last_metrics_emit_at = 0.0

        try:
            payload = build_metrics_payload(query)
            yield sse_event('connected', {'transport': 'sse', 'version': current_app.config.get('APP_VERSION', 'dev')})
            yield sse_event('metrics', {**payload, 'timestamp': time.time()})
            last_metrics_emit_at = time.time()
            backlog = sampler.get_notifications(since_ts=last_notif_ts, max_items=200)
            if backlog:
                last_notif_ts = max(item.get('timestamp', 0) for item in backlog)
                yield sse_event('notifications', {'items': backlog})
        except RuntimeError as exc:
            yield sse_event('error', {'message': f'Docker client not initialized: {exc}'})
            return

        if send_once:
            return

        while True:
            metrics_seq, notification_seq, timed_out = sampler.wait_for_stream_event(
                last_metrics_seq,
                last_notification_seq,
                timeout=heartbeat_seconds,
            )
            now = time.time()

            if metrics_seq != last_metrics_seq:
                last_metrics_seq = metrics_seq
                min_emit_seconds = query['stream_interval_ms'] / 1000.0
                if (now - last_metrics_emit_at) >= min_emit_seconds:
                    try:
                        payload = build_metrics_payload(query)
                        yield sse_event('metrics', {**payload, 'timestamp': now})
                        last_metrics_emit_at = now
                    except RuntimeError as exc:
                        yield sse_event('error', {'message': f'Docker client not initialized: {exc}'})
                        return

            if notification_seq != last_notification_seq:
                last_notification_seq = notification_seq
                items = sampler.get_notifications(since_ts=last_notif_ts, max_items=200)
                if items:
                    last_notif_ts = max(item.get('timestamp', 0) for item in items)
                    yield sse_event('notifications', {'items': items})

            if timed_out:
                yield sse_event('heartbeat', {'timestamp': now})

    response = Response(stream_with_context(generate()), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response

# --- Ruta API para proyectos de Compose ---
@main_routes.route('/api/projects')
def api_projects():
    """Devuelve la lista de proyectos de Compose activos."""
    try:
        client = get_docker_client()
    except RuntimeError as e:
        print(f"ERROR API: /api/projects called before the Docker client was initialized: {e}")
        return jsonify([]), 500
    projects = set()
    for c in client.containers.list(all=True):
        lbls = c.attrs.get('Config', {}).get('Labels', {}) or {}
        proj = lbls.get('com.docker.compose.project')
        if proj:
            projects.add(proj)
    return jsonify(sorted(projects))

# --- Ruta API para Historial del Contenedor (para Gráficos) ---
@main_routes.route('/api/history/<container_id>')
def api_container_history(container_id):
    """Devuelve datos históricos de CPU y RAM para un contenedor específico."""
    print(f"DEBUG HISTORY: History request received for {container_id[:12]}")
    try:
        get_docker_client()
    except RuntimeError as e:
         print(f"ERROR API: /api/history called before the Docker client was initialized: {e}")
         return jsonify({"error": "Docker client not initialized"}), 500

    try:
        range_seconds = int(request.args.get('range', 86400))
        if range_seconds <= 0: range_seconds = 86400
    except ValueError:
        range_seconds = 86400

    print(f"DEBUG HISTORY: Requested range: {range_seconds} seconds for {container_id[:12]}")

    if container_id not in history:
        print(f"WARN HISTORY: No history found for {container_id[:12]}")
        return jsonify({"error": "No history found for this container ID"}), 404

    dq = history[container_id]
    now = time.time()
    cutoff_time = now - range_seconds

    timestamps = []
    cpu_usage = []
    ram_usage = []

    try:
        dq_copy = list(dq)
        print(f"DEBUG HISTORY: Processing {len(dq_copy)} samples for {container_id[:12]}")
        for sample in dq_copy:
            try:
                ts, cpu, mem = sample[0], sample[1], sample[2]
                if ts >= cutoff_time:
                    timestamps.append(ts)
                    cpu_usage.append(float(cpu) if cpu is not None else 0)
                    ram_usage.append(float(mem) if mem is not None else 0)
            except (ValueError, TypeError, IndexError) as sample_err:
                print(f"WARN HISTORY: Skipping invalid sample for {container_id[:12]}: {sample_err} - Sample: {sample}")
                continue

        print(f"DEBUG HISTORY: Found {len(timestamps)} samples within range for {container_id[:12]}")

        response_data = {
            "container_id": container_id,
            "range_seconds": range_seconds,
            "timestamps": timestamps,
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage
        }
        return jsonify(response_data)

    except Exception as e:
        print(f"ERROR HISTORY: Unexpected error while processing history for {container_id[:12]}: {e}")
        return jsonify({"error": "Internal server error processing history"}), 500

# --- Ruta API para Logs del Contenedor ---
@main_routes.route('/api/logs/<container_id>')
def api_container_logs(container_id):
    print(f"DEBUG LOGS: Snapshot request received for {container_id[:12]}")
    tail = parse_log_tail_arg()
    download = request.args.get('download', '0') == '1'
    try:
        client = get_docker_client()
        container = client.containers.get(container_id)
        logs = read_container_log_text(container, tail)
    except errors.NotFound:
        return jsonify({'error': f"Container '{container_id}' not found."}), 404
    except Exception as e:
        print(f"ERROR LOGS: Error while reading logs for {container_id[:12]}: {e}")
        return jsonify({'error': f'Error accessing container logs: {str(e)}'}), 500

    response = Response(logs, mimetype='text/plain; charset=utf-8')
    if download:
        filename = sanitize_download_filename(getattr(container, 'name', container_id))
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}-{container_id[:12]}-logs.txt"'
    return response


@main_routes.route('/api/logs/<container_id>/stream')
def stream_container_logs(container_id):
    print(f"DEBUG LOGS: Stream request received for {container_id[:12]}")
    tail = parse_log_tail_arg()
    try:
        client = get_docker_client()
        container = client.containers.get(container_id)
        container_name = str(container.name)
    except errors.NotFound:
        return jsonify({'error': f"Container '{container_id}' not found."}), 404
    except Exception as e:
        print(f"ERROR LOGS: Error while accessing container {container_id[:12]}: {e}")
        return jsonify({'error': f'Error accessing container: {str(e)}'}), 500

    def generate_logs():
        log_stream = None
        try:
            snapshot_lines = read_container_log_text(container, tail).splitlines()
            yield sse_event('connected', {
                'container_id': container_id,
                'container_name': container_name,
                'tail': tail,
            })
            yield sse_event('snapshot', {
                'container_id': container_id,
                'container_name': container_name,
                'tail': tail,
                'lines': snapshot_lines,
            })

            log_stream = container.logs(stream=True, follow=True, tail=0, timestamps=True)
            buffer = ''
            for chunk in log_stream:
                buffer += chunk.decode('utf-8', errors='replace')
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    yield sse_event('line', {'text': line})

            if buffer:
                yield sse_event('line', {'text': buffer})
        except errors.APIError as api_e:
            print(f"ERROR LOGS: Docker API error while streaming logs for {container_id[:12]}: {api_e}")
            yield sse_event('error', {'message': f'Docker API error while streaming logs: {str(api_e)}'})
        except GeneratorExit:
            pass
        except Exception as log_e:
            print(f"ERROR LOGS: Unexpected error while streaming logs for {container_id[:12]}: {log_e}")
            yield sse_event('error', {'message': f'Error streaming logs: {str(log_e)}'})
        finally:
            if hasattr(log_stream, 'close'):
                try:
                    log_stream.close()
                except Exception:
                    pass
            print(f"DEBUG LOGS: Log stream closed for {container_id[:12]}")

    response = Response(stream_with_context(generate_logs()), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response

# --- Ruta para obtener logs de un contenedor ---
@main_routes.route('/logs/<container_id>')
def get_container_logs(container_id):
    try:
        client = get_docker_client()
        container = client.containers.get(container_id)
        logs = container.logs(tail=1000).decode('utf-8')
        return render_template('logs.html', logs=logs, container_name=container.name)
    except Exception as e:
        return f"Error while retrieving logs: {str(e)}", 500

# --- Ruta para la página de comparación ---
@main_routes.route('/compare/<compare_type>')
def compare_page(compare_type):
    try:
        top_n = int(request.args.get('topN', 5))
        if top_n <= 0: top_n = 5
    except ValueError:
        top_n = 5

    valid_types = {
        "cpu": "CPU Usage",
        "ram": "RAM Usage",
        "uptime": "Uptime"
    }
    if compare_type not in valid_types:
        return "Invalid comparison type", 404

    title = valid_types[compare_type]
    print(f"DEBUG COMPARE PAGE: Serving comparison page for '{title}' (Top {top_n}) with embedded data.")

    comparison_data = []
    try:
        client = get_docker_client()
        get_api_client()

        rows = []
        current_history_keys = list(history.keys())

        for cid in current_history_keys:
            if cid not in history: continue
            dq = history[cid]
            latest_sample = None
            if dq:
                try:
                    latest_sample = dq[-1]
                    sample_len = len(latest_sample)
                    ts = latest_sample[0] if sample_len > 0 else None
                    cpu = float(latest_sample[1]) if sample_len > 1 and latest_sample[1] is not None else None
                    mem = float(latest_sample[2]) if sample_len > 2 and latest_sample[2] is not None else None
                    status_hist = latest_sample[3] if sample_len > 3 else "unknown"
                    name_hist = latest_sample[4] if sample_len > 4 else f"container_{cid[:6]}"
                except (ValueError, IndexError, TypeError): continue
            else: continue

            container_name = name_hist
            uptime_sec = None
            formatted_uptime = "N/A"
            current_status = status_hist

            if compare_type == "uptime":
                try:
                    container = client.containers.get(cid)
                    current_status = container.status
                    attrs = container.attrs or {}
                    state = attrs.get('State', {})

                    started_at_str = state.get('StartedAt')
                    if current_status == 'running' and started_at_str:
                        started_dt = parse_datetime(started_at_str)
                        if started_dt:
                            now_utc = datetime.datetime.now(datetime.timezone.utc)
                            if started_dt.tzinfo is None: started_dt = started_dt.replace(tzinfo=datetime.timezone.utc)
                            uptime_sec = max(0, int((now_utc - started_dt).total_seconds()))
                            formatted_uptime = format_uptime(uptime_sec)
                        else: uptime_sec = None; formatted_uptime = "Error Parse"
                    else: uptime_sec = None; formatted_uptime = "N/A"

                except errors.NotFound:
                    uptime_sec = None; formatted_uptime = "N/A (Removed)"; current_status = status_hist
                except Exception as e:
                    print(f"WARN COMPARE PAGE: Error while fetching details for {cid[:6]}..: {e}")
                    uptime_sec = None; formatted_uptime = "Error Fetching"; current_status = status_hist

            row_data = {
                'id': cid,
                'name': container_name,
                'cpu': cpu,
                'mem': mem,
                'uptime_sec': uptime_sec,
                'uptime': formatted_uptime,
                'status': current_status
            }
            keys_to_keep = {'id', 'name'}
            if compare_type == 'cpu':
                keys_to_keep.update({'cpu'})
            elif compare_type == 'ram':
                keys_to_keep.update({'mem'})
            elif compare_type == 'uptime':
                keys_to_keep.update({'uptime_sec', 'uptime'})

            filtered_row_data = {k: v for k, v in row_data.items() if k in keys_to_keep}
            rows.append(filtered_row_data)

        sort_key_map = {
            "cpu": "cpu",
            "ram": "mem",
            "uptime": "uptime_sec"
        }
        primary_sort_field = sort_key_map.get(compare_type)

        def compare_sort_key(item):
            primary_value = item.get(primary_sort_field) if primary_sort_field else None
            name_value = item.get('name', '')

            numeric_primary = primary_value if primary_value is not None else float('-inf')

            return (-numeric_primary, name_value.lower())

        try:
             rows.sort(key=compare_sort_key, reverse=False)
        except TypeError as e:
            print(f"WARN COMPARE PAGE: Sorting error (key '{primary_sort_field}'): {e}. Falling back to name sorting.")
            rows.sort(key=lambda x: str(x.get('name', '')).lower(), reverse=False)

        comparison_data = rows[:top_n]
        print(f"DEBUG COMPARE PAGE: Prepared data for {len(comparison_data)} containers.")

    except RuntimeError as e:
         print(f"ERROR COMPARE PAGE: Docker client not initialized: {e}")
         comparison_data = []
    except Exception as e:
        print(f"ERROR COMPARE PAGE: Unexpected error while preparing data: {e}")
        comparison_data = []

    return render_template('compare.html',
                           compare_type=compare_type,
                           top_n=top_n,
                           title=title,
                           comparison_data=comparison_data)

# --- Ruta API para datos de comparación ---
@main_routes.route('/api/compare/<compare_type>')
def api_compare_data(compare_type):
    print(f"DEBUG COMPARE API: Request received for /api/compare/{compare_type}")
    try:
        client = get_docker_client()
        get_api_client()
    except RuntimeError as e:
         print(f"ERROR API: /api/compare called before the Docker client was initialized: {e}")
         return jsonify({"error": "Docker client not initialized"}), 500

    try:
        top_n = int(request.args.get('topN', 5))
        if top_n <= 0: top_n = 5
    except ValueError:
        top_n = 5

    valid_types = ["cpu", "ram", "uptime"]
    if compare_type not in valid_types:
        return jsonify({"error": "Invalid comparison type"}), 400

    rows = []
    current_history_keys = list(history.keys())
    print(f"DEBUG COMPARE API: Processing {len(current_history_keys)} container IDs for '{compare_type}' comparison (Top {top_n})")

    for cid in current_history_keys:
        if cid not in history: continue
        dq = history[cid]
        latest_sample = None
        if dq:
            try:
                latest_sample = dq[-1]
                ts = latest_sample[0] if len(latest_sample) > 0 else None
                cpu = float(latest_sample[1]) if len(latest_sample) > 1 and latest_sample[1] is not None else None
                mem = float(latest_sample[2]) if len(latest_sample) > 2 and latest_sample[2] is not None else None
                status_hist = latest_sample[3] if len(latest_sample) > 3 else "unknown"
                name_hist = latest_sample[4] if len(latest_sample) > 4 else f"container_{cid[:6]}"
            except (ValueError, IndexError, TypeError): continue
        else: continue

        container_name = name_hist
        uptime_sec = None
        formatted_uptime = "N/A"
        current_status = status_hist

        if compare_type == "uptime":
            try:
                container = client.containers.get(cid)
                current_status = container.status
                attrs = container.attrs or {}
                state = attrs.get('State', {})

                started_at_str = state.get('StartedAt')
                if current_status == 'running' and started_at_str:
                    started_dt = parse_datetime(started_at_str)
                    if started_dt:
                        now_utc = datetime.datetime.now(datetime.timezone.utc)
                        if started_dt.tzinfo is None: started_dt = started_dt.replace(tzinfo=datetime.timezone.utc)
                        uptime_sec = max(0, int((now_utc - started_dt).total_seconds()))
                        formatted_uptime = format_uptime(uptime_sec)
                    else: uptime_sec = None; formatted_uptime = "Error Parse"
                else: uptime_sec = None; formatted_uptime = "N/A"

            except errors.NotFound:
                uptime_sec = None
                formatted_uptime = "N/A (Removed)"
                current_status = status_hist
            except Exception as e:
                print(f"WARN COMPARE API: Error while fetching details for {cid[:6]}..: {e}")
                uptime_sec = None
                formatted_uptime = "Error Fetching"
                current_status = status_hist

        rows.append({
            'id': cid,
            'name': container_name,
            'cpu': cpu,
            'mem': mem,
            'uptime_sec': uptime_sec,
            'uptime': formatted_uptime,
            'status': current_status
        })

    sort_key_map = {
        "cpu": "cpu",
        "ram": "mem",
        "uptime": "uptime_sec"
    }
    sort_field = sort_key_map.get(compare_type, "combined")

    def compare_sort_key(item):
        key_value = item.get(sort_field)
        return key_value if key_value is not None else float('-inf')

    try:
        rows.sort(key=compare_sort_key, reverse=True)
    except TypeError as e:
        print(f"WARN COMPARE API: Sorting error (key '{sort_field}'): {e}. Falling back to name sorting.")
        rows.sort(key=lambda x: str(x.get('name', '')).lower(), reverse=False)

    top_rows = rows[:top_n]

    print(f"DEBUG COMPARE API: Returning {len(top_rows)} rows for '{compare_type}' comparison.")
    return jsonify(top_rows)

# --- CSV Export Endpoint ---
@main_routes.route('/api/export/csv', methods=['POST'])
@csrf_protect
def export_csv():
    data = request.get_json() or {}
    metrics = data.get('metrics', [])
    import csv, io
    si = io.StringIO()
    writer = csv.writer(si)
    if metrics:
        headers = list(metrics[0].keys())
        writer.writerow(headers)
        for row in metrics:
            writer.writerow([row.get(h) for h in headers])
    output = si.getvalue()
    return Response(output, mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=metrics.csv'
    })

# --- Container Control Endpoints ---
@main_routes.route('/api/containers/<container_id>/<action>', methods=['POST'])
@csrf_protect
def container_action(container_id, action):
    """Start, stop, restart or update a Docker container"""
    try:
        client = get_docker_client()
        container = client.containers.get(container_id)
        container_name = str(container.name)
        container_name_safe = escape(container_name)

        if action == 'start':
            container.start()
            audit_event('container.start', 'container', 'success', target_id=container_id, details={'name': container_name})
            return jsonify({'status': f'Container {container_name_safe} started'})
        elif action == 'stop':
            container.stop()
            audit_event('container.stop', 'container', 'success', target_id=container_id, details={'name': container_name})
            return jsonify({'status': f'Container {container_name_safe} stopped'})
        elif action == 'restart':
            container.restart()
            audit_event('container.restart', 'container', 'success', target_id=container_id, details={'name': container_name})
            return jsonify({'status': f'Container {container_name_safe} restarted'})
        elif action == 'update':
            result = update_manager.update_container_target(container_id, actor_username=get_request_username())
            emit_update_result_notification(
                'container',
                container_id,
                container_name,
                result.get('message') or (
                    f"Container {container_name} updated successfully."
                    if result.get('ok')
                    else f"Container {container_name} update failed."
                ),
                bool(result.get('ok')),
                history_entry=result.get('history_entry'),
            )
            audit_event(
                'container.update',
                'container',
                'success' if result.get('ok') else 'failure',
                target_id=container_id,
                details={
                    'name': container_name,
                    'message': result.get('message'),
                    'history_entry_id': (result.get('history_entry') or {}).get('id'),
                },
            )
            return (
                jsonify({
                    'ok': bool(result.get('ok')),
                    'status': result.get('message'),
                    'history_entry': result.get('history_entry'),
                }),
                200 if result.get('ok') else 409,
            )
        else:
            audit_event(f'container.{action}', 'container', 'failure', target_id=container_id, details={'error': 'invalid_action'})
            return jsonify({'error': 'Invalid action'}), 400

    except errors.NotFound:
        audit_event(f'container.{action}', 'container', 'failure', target_id=container_id, details={'error': 'not_found'})
        return jsonify({'error': f'Container {container_id} not found'}), 404
    except Exception as e:
        print(f"ERROR in container_action ({action} for {container_id[:12]}): {e}")
        audit_event(f'container.{action}', 'container', 'failure', target_id=container_id, details={'error': str(e)})
        return jsonify({'error': f'An unexpected error occurred: {escape(str(e))}'}), 500

# --- Ruta API para notificaciones ---
@main_routes.route('/api/notifications')
def api_notifications():
    """Devuelve notificaciones recientes. Permite filtrar por timestamp (?since=TIMESTAMP) y limitar cantidad."""
    from sampler import get_notifications
    try:
        since = request.args.get('since', None)
        max_items = int(request.args.get('max', 50))
        since_ts = float(since) if since else None
    except Exception:
        since_ts = None
        max_items = 50
    notifs = get_notifications(since_ts=since_ts, max_items=max_items)
    return jsonify(notifs)

# --- Ruta API para configuración de notificaciones ---
@main_routes.route('/api/notification-settings', methods=['GET', 'POST'])
@admin_required
def api_notification_settings():
    """Obtiene o guarda la configuración de notificaciones."""
    from sampler import apply_notification_settings, notification_settings
    if request.method == 'GET':
        return jsonify(notification_settings)
    # POST
    result = validate_csrf()
    if result is not None:
        return result
    data = request.get_json(force=True)
    allowed = {
        'cpu_enabled', 'ram_enabled', 'status_enabled', 'update_enabled', 'security_enabled',
        'security_privileged_enabled', 'security_public_ports_enabled',
        'security_latest_enabled', 'security_docker_socket_enabled',
        'cpu_threshold', 'ram_threshold', 'window_seconds', 'cooldown_seconds',
        'project_rule_mode', 'project_rules', 'container_rule_mode', 'container_rules',
        'silence_enabled', 'silence_start', 'silence_end',
        'dedupe_enabled', 'dedupe_window_seconds',
    }
    filtered = {key: value for key, value in data.items() if key in allowed}
    settings = apply_notification_settings({**notification_settings, **filtered})
    return jsonify({'ok': True, 'settings': settings})


@main_routes.route('/api/notification-test', methods=['POST'])
@admin_required
@csrf_protect
def api_notification_test():
    """Send a test notification and return per-channel diagnostics."""
    data = request.get_json(silent=True) or {}
    username = get_request_username() or 'admin'
    try:
        priority = int(data.get('priority', 0))
    except (TypeError, ValueError):
        priority = 0
    result = send_notification(
        data.get('message') or f'Test notification from statainer for {username}',
        title=data.get('title') or 'statainer Test',
        priority=priority,
    )

    if result['ok']:
        status_code = 200
    elif result['configured_any']:
        status_code = 502
    else:
        status_code = 400

    return jsonify(result), status_code


@main_routes.route('/api/update-manager')
@admin_required
def api_update_manager():
    """Return update-ready projects/containers and persistent update history."""
    refresh = request.args.get('refresh', '0') == '1'
    try:
        history_limit = max(1, min(int(request.args.get('history_limit', 20) or 20), 100))
    except (TypeError, ValueError):
        history_limit = 20
    payload = update_manager.list_update_targets(history_limit=history_limit, force_refresh=refresh)
    return jsonify(payload)


@main_routes.route('/api/update-manager/update', methods=['POST'])
@admin_required
@csrf_protect
def api_update_manager_update():
    """Execute a safe update for a container or Compose project."""
    data = request.get_json(force=True) or {}
    target_type = str(data.get('target_type') or '').strip().lower()
    target_id = str(data.get('target_id') or '').strip()
    if target_type not in {'container', 'project'} or not target_id:
        return jsonify({'ok': False, 'message': 'target_type and target_id are required.'}), 400

    result = update_manager.update_target(target_type, target_id, actor_username=get_request_username())
    emit_update_result_notification(
        target_type,
        target_id,
        (result.get('history_entry') or {}).get('target_name') or target_id,
        result.get('message') or (
            f"{target_type.title()} {target_id} updated successfully."
            if result.get('ok')
            else f"{target_type.title()} {target_id} update failed."
        ),
        bool(result.get('ok')),
        history_entry=result.get('history_entry'),
    )
    audit_event(
        'update-manager.update',
        target_type,
        'success' if result.get('ok') else 'failure',
        target_id=target_id,
        details={
            'message': result.get('message'),
            'history_entry_id': (result.get('history_entry') or {}).get('id'),
        },
    )
    return jsonify(result), 200 if result.get('ok') else 409


@main_routes.route('/api/update-manager/auto-update', methods=['POST'])
@admin_required
@csrf_protect
def api_update_manager_auto_update():
    """Enable or disable automatic updates for a supported target."""
    data = request.get_json(force=True) or {}
    target_type = str(data.get('target_type') or '').strip().lower()
    target_name = str(data.get('target_name') or '').strip()
    enabled = bool(data.get('enabled'))
    if target_type not in {'container', 'project'} or not target_name:
        return jsonify({'ok': False, 'message': 'target_type and target_name are required.'}), 400

    result = update_manager.configure_auto_update_target(target_type, target_name, enabled)
    return jsonify(result), 200 if result.get('ok') else 409


@main_routes.route('/api/update-manager/rollback', methods=['POST'])
@admin_required
@csrf_protect
def api_update_manager_rollback():
    """Rollback a recent successful update using persistent history metadata."""
    data = request.get_json(force=True) or {}
    try:
        history_id = int(data.get('history_id'))
    except (TypeError, ValueError):
        return jsonify({'ok': False, 'message': 'history_id is required.'}), 400

    result = update_manager.rollback_update(history_id, actor_username=get_request_username())
    audit_event(
        'update-manager.rollback',
        'update-history',
        'success' if result.get('ok') else 'failure',
        target_id=str(history_id),
        details={
            'message': result.get('message'),
            'history_entry_id': (result.get('history_entry') or {}).get('id'),
        },
    )
    return jsonify(result), 200 if result.get('ok') else 409

# --- Cambiar contraseña desde ajustes ---
@main_routes.route('/api/change-password', methods=['POST'])
@csrf_protect
def api_change_password():
    """Permite cambiar la contraseña del usuario autenticado."""
    data = request.get_json(force=True)
    current = data.get('current_password', '')
    new = data.get('new_password', '')
    username = get_request_username()
    if not username:
        audit_event('user.password_change', 'user', 'failure', details={'reason': 'not_authenticated'})
        return jsonify({'ok': False, 'error': 'Not authenticated.'}), 401
    if not current or not new:
        audit_event('user.password_change', 'user', 'failure', target_id=username, details={'reason': 'missing_fields'})
        return jsonify({'ok': False, 'error': 'All fields are required.'}), 400
    if not validate_user(username, current):
        audit_event('user.password_change', 'user', 'failure', target_id=username, details={'reason': 'invalid_current_password'})
        return jsonify({'ok': False, 'error': 'Current password is incorrect.'}), 403
    try:
        if not change_password(username, new):
            audit_event('user.password_change', 'user', 'failure', target_id=username, details={'reason': 'user_not_found'})
            return jsonify({'ok': False, 'error': 'User not found.'}), 404
        audit_event('user.password_change', 'user', 'success', target_id=username)
        return jsonify({'ok': True})
    except Exception as e:
        audit_event('user.password_change', 'user', 'failure', target_id=username, details={'error': str(e)})
        return jsonify({'ok': False, 'error': f'Error saving password: {str(e)}'}), 500

# --- API: User Management ---
@main_routes.route('/api/users', methods=['GET'])
@admin_required
def api_list_users():
    """Devuelve la lista de usuarios y sus permisos de columnas."""
    users = list_users_with_columns()
    return jsonify(users)


@main_routes.route('/api/audit', methods=['GET'])
@admin_required
def api_audit_log():
    try:
        limit = max(1, min(500, int(request.args.get('limit', 100) or 100)))
    except (TypeError, ValueError):
        limit = 100
    return jsonify(list_audit_events(limit=limit))

@main_routes.route('/api/users', methods=['POST'])
@admin_required
@csrf_protect
def api_create_user():
    data = request.get_json(force=True)
    username = data.get('username', '').strip()
    password = data.get('password', '')
    columns = data.get('columns', [])
    if not username or not password or not isinstance(columns, list):
        audit_event('user.create', 'user', 'failure', target_id=username or None, details={'reason': 'missing_fields'})
        return jsonify({'error': 'Missing fields'}), 400
    if username == 'admin':
        audit_event('user.create', 'user', 'failure', target_id=username, details={'reason': 'reserved_username'})
        return jsonify({'error': 'Cannot create another admin'}), 403
    if user_exists(username):
        audit_event('user.create', 'user', 'failure', target_id=username, details={'reason': 'already_exists'})
        return jsonify({'error': 'User already exists'}), 409
    ok = create_user_with_columns(username, password, columns, role='user')
    if not ok:
        audit_event('user.create', 'user', 'failure', target_id=username, details={'reason': 'storage_error'})
        return jsonify({'error': 'Could not create user'}), 500
    audit_event('user.create', 'user', 'success', target_id=username, details={'columns': columns})
    return jsonify({'ok': True})

@main_routes.route('/api/users/<username>', methods=['PUT'])
@admin_required
@csrf_protect
def api_update_user_columns(username):
    if username == 'admin':
        audit_event('user.update_columns', 'user', 'failure', target_id=username, details={'reason': 'reserved_username'})
        return jsonify({'error': 'Cannot edit admin'}), 403
    data = request.get_json(force=True)
    columns = data.get('columns', [])
    if not isinstance(columns, list):
        audit_event('user.update_columns', 'user', 'failure', target_id=username, details={'reason': 'invalid_columns'})
        return jsonify({'error': 'Invalid columns'}), 400
    if not user_exists(username):
        audit_event('user.update_columns', 'user', 'failure', target_id=username, details={'reason': 'not_found'})
        return jsonify({'error': 'User not found'}), 404
    update_user_columns(username, columns)
    audit_event('user.update_columns', 'user', 'success', target_id=username, details={'columns': columns})
    return jsonify({'ok': True})

@main_routes.route('/api/users/<username>', methods=['DELETE'])
@admin_required
@csrf_protect
def api_delete_user(username):
    if username == 'admin':
        audit_event('user.delete', 'user', 'failure', target_id=username, details={'reason': 'reserved_username'})
        return jsonify({'error': 'Cannot delete admin'}), 403
    if not user_exists(username):
        audit_event('user.delete', 'user', 'failure', target_id=username, details={'reason': 'not_found'})
        return jsonify({'error': 'User not found'}), 404
    delete_user(username)
    audit_event('user.delete', 'user', 'success', target_id=username)
    return jsonify({'ok': True})

# --- External API key management (admin only) ---
@main_routes.route('/api/api-keys', methods=['GET'])
@admin_required
def api_list_api_keys():
    """Return the master toggle, scope catalog and existing keys (no secrets)."""
    return jsonify({
        'enabled': bool(get_external_api_settings().get('enabled')),
        'scopes': api_keys_service.scopes_catalog(),
        'keys': list_api_keys(),
    })


@main_routes.route('/api/api-keys/settings', methods=['POST'])
@admin_required
@csrf_protect
def api_set_api_settings():
    data = request.get_json(force=True) or {}
    enabled = bool(data.get('enabled'))
    settings = set_external_api_settings({'enabled': enabled})
    audit_event('api.settings_update', 'api', 'success', details={'enabled': enabled})
    return jsonify({'ok': True, 'settings': settings})


@main_routes.route('/api/api-keys', methods=['POST'])
@admin_required
@csrf_protect
def api_create_api_key():
    data = request.get_json(force=True) or {}
    name = (data.get('name') or '').strip()
    scopes = data.get('scopes', [])
    if not isinstance(scopes, list):
        scopes = []

    expires_at = data.get('expires_at')
    expires_in_days = data.get('expires_in_days')
    if not expires_at and expires_in_days:
        try:
            days = float(expires_in_days)
            if days > 0:
                expires_at = time.time() + days * 86400
        except (TypeError, ValueError):
            audit_event('api.key_create', 'api', 'failure', details={'reason': 'invalid_expiry'})
            return jsonify({'error': 'Invalid expiration.'}), 400

    try:
        token, record = api_keys_service.create_key(
            name=name,
            scopes=scopes,
            created_by=get_request_username(),
            expires_at=expires_at,
        )
    except ValueError as exc:
        audit_event('api.key_create', 'api', 'failure', details={'reason': str(exc)})
        return jsonify({'error': str(exc)}), 400

    audit_event(
        'api.key_create', 'api', 'success',
        target_id=str(record['id']),
        details={'name': record['name'], 'scopes': record['scopes'], 'expires_at': record['expires_at']},
    )
    # The plaintext token is returned exactly once and never stored.
    return jsonify({'ok': True, 'token': token, 'key': record}), 201


@main_routes.route('/api/api-keys/<int:key_id>', methods=['PUT'])
@admin_required
@csrf_protect
def api_update_api_key(key_id):
    data = request.get_json(force=True) or {}
    if 'enabled' not in data:
        return jsonify({'error': 'Nothing to update.'}), 400
    record = get_api_key_by_id(key_id)
    if not record:
        audit_event('api.key_update', 'api', 'failure', target_id=str(key_id), details={'reason': 'not_found'})
        return jsonify({'error': 'API key not found.'}), 404
    enabled = bool(data.get('enabled'))
    set_api_key_enabled(key_id, enabled)
    audit_event('api.key_update', 'api', 'success', target_id=str(key_id), details={'enabled': enabled, 'name': record['name']})
    return jsonify({'ok': True, 'key': get_api_key_by_id(key_id)})


@main_routes.route('/api/api-keys/<int:key_id>', methods=['DELETE'])
@admin_required
@csrf_protect
def api_delete_api_key(key_id):
    record = get_api_key_by_id(key_id)
    if not record:
        audit_event('api.key_delete', 'api', 'failure', target_id=str(key_id), details={'reason': 'not_found'})
        return jsonify({'error': 'API key not found.'}), 404
    delete_api_key(key_id)
    audit_event('api.key_delete', 'api', 'success', target_id=str(key_id), details={'name': record['name']})
    return jsonify({'ok': True})


@main_routes.route('/whoami')
def whoami():
    """Devuelve el usuario autenticado y su rol."""
    username = get_request_username()
    if not username:
        return jsonify({'username': None, 'role': None})
    return jsonify({'username': username, 'role': get_request_role()})
