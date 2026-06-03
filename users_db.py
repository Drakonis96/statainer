import json
import logging
import os
import sqlite3
import time
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = os.path.dirname(__file__)
DEFAULT_DB_PATH = os.path.join(APP_DIR, 'data', 'users.db')
LEGACY_DB_PATH = os.path.join(APP_DIR, 'users.db')
UPDATE_HISTORY_RETENTION_DAYS = 15
UPDATE_HISTORY_RETENTION_SECONDS = UPDATE_HISTORY_RETENTION_DAYS * 24 * 60 * 60
AUTO_UPDATE_SETTINGS_KEY = 'auto_update_settings'


def _normalize_db_path(path):
    if os.path.isdir(path):
        resolved_path = os.path.join(path, 'users.db')
        logging.warning("Database path %s is a directory; using %s instead.", path, resolved_path)
        return resolved_path
    return path


def get_db_path():
    configured_path = os.environ.get('USERS_DB_PATH', '').strip()
    if configured_path:
        return _normalize_db_path(configured_path)
    if os.path.isfile(LEGACY_DB_PATH) or os.path.isdir(LEGACY_DB_PATH):
        return _normalize_db_path(LEGACY_DB_PATH)
    return DEFAULT_DB_PATH


def get_db():
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def migrate_add_columns_and_role_and_settings():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            columns TEXT,
            role TEXT
        )
        '''
    )
    # Add columns field if not exists
    try:
        c.execute('ALTER TABLE users ADD COLUMN columns TEXT')
    except sqlite3.OperationalError:
        pass  # Already exists
    # Add role field if not exists
    try:
        c.execute('ALTER TABLE users ADD COLUMN role TEXT')
    except sqlite3.OperationalError:
        pass  # Already exists

    # Create global settings table if missing
    try:
        c.execute('CREATE TABLE IF NOT EXISTS global_settings (key TEXT PRIMARY KEY, value TEXT)')
    except sqlite3.OperationalError:
        pass
    try:
        c.execute(
            '''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                actor_username TEXT,
                actor_role TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                status TEXT NOT NULL,
                remote_addr TEXT,
                details TEXT
            )
            '''
        )
    except sqlite3.OperationalError:
        pass
    try:
        c.execute(
            '''
            CREATE TABLE IF NOT EXISTS update_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                actor_username TEXT,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_name TEXT NOT NULL,
                previous_version TEXT,
                new_version TEXT,
                result TEXT NOT NULL,
                notes TEXT,
                metadata TEXT,
                rollback_of INTEGER
            )
            '''
        )
    except sqlite3.OperationalError:
        pass
    try:
        c.execute(
            '''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                created_by TEXT,
                expires_at REAL,
                last_used_at REAL,
                last_used_ip TEXT
            )
            '''
        )
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()

# Call migration at import
migrate_add_columns_and_role_and_settings()

def init_db(default_user, default_password):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username=?', (default_user,))
    if default_user and default_password and not c.fetchone():
        c.execute('INSERT INTO users (username, password_hash, role, columns) VALUES (?, ?, ?, ?)',
                  (default_user, generate_password_hash(default_password), 'admin', None))
        conn.commit()
    conn.close()

def count_users():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT COUNT(*) AS count FROM users')
    row = c.fetchone()
    conn.close()
    return int(row['count'] or 0)

def validate_user(username, password):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if row and check_password_hash(row['password_hash'], password):
        return True
    return False

def change_password(username, new_password):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE users SET password_hash=? WHERE username=?',
              (generate_password_hash(new_password), username))
    conn.commit()
    changed = c.rowcount > 0
    conn.close()
    return changed

def user_exists(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT 1 FROM users WHERE username=?', (username,))
    exists = c.fetchone() is not None
    conn.close()
    return exists

def create_user_with_columns(username, password, columns, role="user"):
    conn = get_db()
    c = conn.cursor()
    columns_json = json.dumps(list(columns))
    try:
        c.execute('INSERT INTO users (username, password_hash, columns, role) VALUES (?, ?, ?, ?)',
                  (username, generate_password_hash(password), columns_json, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def list_users_with_columns():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT username, columns, role FROM users')
    users = []
    for row in c.fetchall():
        try:
            cols = json.loads(row['columns']) if row['columns'] else []
        except Exception:
            cols = []
        users.append({
            'username': row['username'],
            'columns': cols,
            'role': row['role'] or ('admin' if row['username'] == 'admin' else 'user')
        })
    conn.close()
    return users

def update_user_columns(username, columns):
    conn = get_db()
    c = conn.cursor()
    columns_json = json.dumps(list(columns))
    c.execute('UPDATE users SET columns=? WHERE username=?', (columns_json, username))
    conn.commit()
    conn.close()

def delete_user(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username=?', (username,))
    conn.commit()
    conn.close()

def get_user_columns(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT columns FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if row and row['columns']:
        try:
            return json.loads(row['columns'])
        except Exception:
            return []
    return []

def get_user_role(username):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT role FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if row and row['role']:
        return row['role']
    return 'admin' if username == 'admin' else 'user'


def record_audit_event(action, target_type, status, actor_username=None, actor_role=None, target_id=None, remote_addr=None, details=None):
    conn = get_db()
    c = conn.cursor()
    details_json = json.dumps(details or {}, sort_keys=True)
    c.execute(
        '''
        INSERT INTO audit_log (
            created_at, actor_username, actor_role, action, target_type, target_id, status, remote_addr, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (time.time(), actor_username, actor_role, action, target_type, target_id, status, remote_addr, details_json),
    )
    conn.commit()
    event_id = c.lastrowid
    conn.close()
    return event_id


def list_audit_events(limit=100):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, created_at, actor_username, actor_role, action, target_type, target_id, status, remote_addr, details
        FROM audit_log
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        ''',
        (int(limit),),
    )
    rows = []
    for row in c.fetchall():
        try:
            details = json.loads(row['details']) if row['details'] else {}
        except Exception:
            details = {}
        rows.append({
            'id': row['id'],
            'created_at': row['created_at'],
            'actor_username': row['actor_username'],
            'actor_role': row['actor_role'],
            'action': row['action'],
            'target_type': row['target_type'],
            'target_id': row['target_id'],
            'status': row['status'],
            'remote_addr': row['remote_addr'],
            'details': details,
        })
    conn.close()
    return rows

# --- Global Settings Helpers ---
def set_global_setting(key, value):
    conn = get_db()
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)',
              (key, json.dumps(value)))
    conn.commit()
    conn.close()

def get_global_setting(key, default=None):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT value FROM global_settings WHERE key=?', (key,))
    row = c.fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row['value'])
        except Exception:
            return row['value']
    return default

def get_notification_settings(default=None):
    return get_global_setting('notification_settings', default)

def set_notification_settings(settings):
    set_global_setting('notification_settings', settings)


# --- External API settings & API key storage ---
EXTERNAL_API_SETTINGS_KEY = 'external_api_settings'
DEFAULT_EXTERNAL_API_SETTINGS = {'enabled': False}


def get_external_api_settings():
    stored = get_global_setting(EXTERNAL_API_SETTINGS_KEY, {})
    settings = dict(DEFAULT_EXTERNAL_API_SETTINGS)
    if isinstance(stored, dict):
        settings['enabled'] = bool(stored.get('enabled', False))
    return settings


def set_external_api_settings(settings):
    normalized = {'enabled': bool((settings or {}).get('enabled', False))}
    set_global_setting(EXTERNAL_API_SETTINGS_KEY, normalized)
    return normalized


def is_external_api_enabled():
    return bool(get_external_api_settings().get('enabled'))


def _row_to_api_key(row, include_sensitive=False):
    try:
        scopes = json.loads(row['scopes']) if row['scopes'] else []
    except Exception:
        scopes = []
    record = {
        'id': row['id'],
        'name': row['name'],
        'key_prefix': row['key_prefix'],
        'scopes': scopes,
        'enabled': bool(row['enabled']),
        'created_at': row['created_at'],
        'created_by': row['created_by'],
        'expires_at': row['expires_at'],
        'last_used_at': row['last_used_at'],
        'last_used_ip': row['last_used_ip'],
    }
    if include_sensitive:
        record['key_hash'] = row['key_hash']
    return record


def create_api_key(name, key_prefix, key_hash, scopes, created_by=None, expires_at=None):
    conn = get_db()
    c = conn.cursor()
    scopes_json = json.dumps(list(scopes))
    try:
        c.execute(
            '''
            INSERT INTO api_keys (
                name, key_prefix, key_hash, scopes, enabled, created_at, created_by, expires_at
            ) VALUES (?, ?, ?, ?, 1, ?, ?, ?)
            ''',
            (name, key_prefix, key_hash, scopes_json, time.time(), created_by, expires_at),
        )
        conn.commit()
        return c.lastrowid
    finally:
        conn.close()


def list_api_keys():
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, name, key_prefix, key_hash, scopes, enabled, created_at, created_by,
               expires_at, last_used_at, last_used_ip
        FROM api_keys
        ORDER BY created_at DESC, id DESC
        '''
    )
    keys = [_row_to_api_key(row) for row in c.fetchall()]
    conn.close()
    return keys


def get_api_key_by_id(key_id):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, name, key_prefix, key_hash, scopes, enabled, created_at, created_by,
               expires_at, last_used_at, last_used_ip
        FROM api_keys WHERE id=?
        ''',
        (int(key_id),),
    )
    row = c.fetchone()
    conn.close()
    return _row_to_api_key(row) if row else None


def get_api_key_by_hash(key_hash):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, name, key_prefix, key_hash, scopes, enabled, created_at, created_by,
               expires_at, last_used_at, last_used_ip
        FROM api_keys WHERE key_hash=?
        ''',
        (key_hash,),
    )
    row = c.fetchone()
    conn.close()
    return _row_to_api_key(row, include_sensitive=True) if row else None


def set_api_key_enabled(key_id, enabled):
    conn = get_db()
    c = conn.cursor()
    c.execute('UPDATE api_keys SET enabled=? WHERE id=?', (1 if enabled else 0, int(key_id)))
    conn.commit()
    changed = c.rowcount > 0
    conn.close()
    return changed


def delete_api_key(key_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id=?', (int(key_id),))
    conn.commit()
    deleted = c.rowcount > 0
    conn.close()
    return deleted


def touch_api_key_usage(key_id, remote_addr=None, now_ts=None):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        'UPDATE api_keys SET last_used_at=?, last_used_ip=? WHERE id=?',
        (float(now_ts if now_ts is not None else time.time()), remote_addr, int(key_id)),
    )
    conn.commit()
    conn.close()


def normalize_auto_update_settings(settings=None):
    raw = settings if isinstance(settings, dict) else {}
    normalized = {
        'containers': {},
        'projects': {},
    }

    for key, bucket_name in (('containers', 'containers'), ('projects', 'projects')):
        bucket = raw.get(key)
        if not isinstance(bucket, dict):
            continue
        for target_name, enabled in bucket.items():
            normalized_name = str(target_name or '').strip()
            if not normalized_name:
                continue
            if isinstance(enabled, dict):
                enabled_value = bool(enabled.get('enabled'))
            else:
                enabled_value = bool(enabled)
            if enabled_value:
                normalized[bucket_name][normalized_name] = True

    return normalized


def get_auto_update_settings(default=None):
    baseline = normalize_auto_update_settings(default or {'containers': {}, 'projects': {}})
    return normalize_auto_update_settings(get_global_setting(AUTO_UPDATE_SETTINGS_KEY, baseline))


def set_auto_update_settings(settings):
    normalized = normalize_auto_update_settings(settings)
    set_global_setting(AUTO_UPDATE_SETTINGS_KEY, normalized)
    return normalized


def set_auto_update_target(target_type, target_name, enabled):
    normalized_type = 'projects' if str(target_type or '').strip().lower() == 'project' else 'containers'
    normalized_name = str(target_name or '').strip()
    settings = get_auto_update_settings()
    if not normalized_name:
        return settings
    if enabled:
        settings[normalized_type][normalized_name] = True
    else:
        settings[normalized_type].pop(normalized_name, None)
    return set_auto_update_settings(settings)


def purge_expired_update_history(now_ts=None, retention_seconds=UPDATE_HISTORY_RETENTION_SECONDS):
    effective_now = float(now_ts if now_ts is not None else time.time())
    cutoff = effective_now - max(0, int(retention_seconds))
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM update_history WHERE created_at < ?', (cutoff,))
    conn.commit()
    deleted = c.rowcount
    conn.close()
    return deleted


def record_update_history(
    action,
    target_type,
    target_id,
    target_name,
    previous_version=None,
    new_version=None,
    result='success',
    notes=None,
    metadata=None,
    rollback_of=None,
    actor_username=None,
):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        INSERT INTO update_history (
            created_at, actor_username, action, target_type, target_id, target_name,
            previous_version, new_version, result, notes, metadata, rollback_of
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            time.time(),
            actor_username,
            action,
            target_type,
            target_id,
            target_name,
            previous_version,
            new_version,
            result,
            notes,
            json.dumps(metadata or {}, sort_keys=True),
            rollback_of,
        ),
    )
    conn.commit()
    event_id = c.lastrowid
    conn.close()
    return event_id


def get_update_history_entry(entry_id):
    purge_expired_update_history()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, created_at, actor_username, action, target_type, target_id, target_name,
               previous_version, new_version, result, notes, metadata, rollback_of
        FROM update_history
        WHERE id=?
        ''',
        (int(entry_id),),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    try:
        metadata = json.loads(row['metadata']) if row['metadata'] else {}
    except Exception:
        metadata = {}
    return {
        'id': row['id'],
        'created_at': row['created_at'],
        'actor_username': row['actor_username'],
        'action': row['action'],
        'target_type': row['target_type'],
        'target_id': row['target_id'],
        'target_name': row['target_name'],
        'previous_version': row['previous_version'],
        'new_version': row['new_version'],
        'result': row['result'],
        'notes': row['notes'],
        'metadata': metadata,
        'rollback_of': row['rollback_of'],
    }


def list_update_history(limit=100):
    purge_expired_update_history()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT id, created_at, actor_username, action, target_type, target_id, target_name,
               previous_version, new_version, result, notes, metadata, rollback_of
        FROM update_history
        ORDER BY created_at DESC, id DESC
        LIMIT ?
        ''',
        (int(limit),),
    )
    rows = []
    for row in c.fetchall():
        try:
            metadata = json.loads(row['metadata']) if row['metadata'] else {}
        except Exception:
            metadata = {}
        rows.append({
            'id': row['id'],
            'created_at': row['created_at'],
            'actor_username': row['actor_username'],
            'action': row['action'],
            'target_type': row['target_type'],
            'target_id': row['target_id'],
            'target_name': row['target_name'],
            'previous_version': row['previous_version'],
            'new_version': row['new_version'],
            'result': row['result'],
            'notes': row['notes'],
            'metadata': metadata,
            'rollback_of': row['rollback_of'],
        })
    conn.close()
    return rows


def list_latest_successful_update_timestamps():
    purge_expired_update_history()
    conn = get_db()
    c = conn.cursor()
    c.execute(
        '''
        SELECT target_type, target_name, MAX(created_at) AS last_updated_at
        FROM update_history
        WHERE action='update' AND result='success'
        GROUP BY target_type, target_name
        '''
    )
    rows = {
        (row['target_type'], row['target_name']): row['last_updated_at']
        for row in c.fetchall()
    }
    conn.close()
    return rows
