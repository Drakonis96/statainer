# -*- coding: utf-8 -*-
"""External API key management.

This module is the single source of truth for API key scopes, secure token
generation/hashing and authentication. The plaintext token is shown to the
operator only once at creation time; only a SHA-256 hash is ever persisted.

Tokens are high-entropy random strings (``stnr_`` + 32 url-safe random bytes),
so a plain SHA-256 hash with a constant-time/indexed lookup is sufficient and
does not require a slow password KDF.
"""

import hashlib
import hmac
import secrets
import time

import users_db

# Catalog of available scopes. The dict order is the order shown in the UI.
# Read scopes expose data; action scopes allow mutating containers.
API_SCOPES = {
    'system:read': 'Read host info (CPU cores, max RAM, Docker version, counts)',
    'containers:read': 'List containers and read their metadata',
    'stats:read': 'Read live per-container statistics (CPU, RAM, network, disk I/O)',
    'containers:start': 'Start containers',
    'containers:stop': 'Stop containers',
    'containers:restart': 'Restart containers',
    'containers:update': 'Update containers to their latest image',
}

# Scopes that allow state-changing operations (used to enforce HTTPS, etc.).
WRITE_SCOPES = frozenset({
    'containers:start',
    'containers:stop',
    'containers:restart',
    'containers:update',
})

TOKEN_PREFIX = 'stnr_'
# Number of leading characters stored in clear text purely for identification
# in the UI (e.g. "stnr_Ab12…"). This is NOT enough to reconstruct the key.
PREFIX_DISPLAY_LEN = len(TOKEN_PREFIX) + 6


def scopes_catalog():
    """Return the scope catalog as a serialisable list of {id, description}."""
    return [{'id': scope, 'description': description} for scope, description in API_SCOPES.items()]


def normalize_scopes(scopes):
    """Keep only known scopes, de-duplicated and in canonical catalog order."""
    if not isinstance(scopes, (list, tuple, set)):
        return []
    requested = {str(scope).strip() for scope in scopes}
    return [scope for scope in API_SCOPES if scope in requested]


def generate_token():
    """Generate a fresh, high-entropy API token."""
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token):
    """Return the stable SHA-256 hex digest used to look up / store a token."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def token_display_prefix(token):
    return token[:PREFIX_DISPLAY_LEN]


def create_key(name, scopes, created_by=None, expires_at=None):
    """Create a new API key.

    Returns ``(token, record)`` where ``token`` is the plaintext key (shown
    once) and ``record`` is the stored metadata (without the secret).
    """
    clean_name = (name or '').strip()
    if not clean_name:
        raise ValueError('A name is required.')
    clean_scopes = normalize_scopes(scopes)
    if not clean_scopes:
        raise ValueError('At least one valid scope is required.')

    normalized_expiry = None
    if expires_at not in (None, ''):
        normalized_expiry = float(expires_at)
        if normalized_expiry <= time.time():
            raise ValueError('Expiration must be in the future.')

    token = generate_token()
    key_id = users_db.create_api_key(
        name=clean_name,
        key_prefix=token_display_prefix(token),
        key_hash=hash_token(token),
        scopes=clean_scopes,
        created_by=created_by,
        expires_at=normalized_expiry,
    )
    record = users_db.get_api_key_by_id(key_id)
    return token, record


def is_expired(record, now_ts=None):
    expires_at = record.get('expires_at')
    if not expires_at:
        return False
    return float(expires_at) <= float(now_ts if now_ts is not None else time.time())


def authenticate(token, now_ts=None):
    """Resolve a plaintext token to an active key record, or ``None``.

    A constant-time comparison guards against the (already negligible) timing
    side-channel on the looked-up hash. Disabled or expired keys are rejected.
    """
    if not token or not isinstance(token, str):
        return None
    token = token.strip()
    if not token:
        return None

    digest = hash_token(token)
    record = users_db.get_api_key_by_hash(digest)
    if not record:
        return None
    # Defensive constant-time check on the stored hash.
    if not hmac.compare_digest(str(record.get('key_hash', '')), digest):
        return None
    if not record.get('enabled'):
        return None
    if is_expired(record, now_ts=now_ts):
        return None
    return record


def has_scope(record, scope):
    return scope in (record.get('scopes') or [])
