# -*- coding: utf-8 -*-
import os
import secrets


APP_DIR = os.path.dirname(__file__)
VERSION_FILE = os.path.join(APP_DIR, "VERSION")


def _get_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name, default):
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def _read_secret(env_name, file_env_name=None, default=""):
    file_path = os.environ.get(file_env_name or f"{env_name}_FILE", "").strip()
    if file_path:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    return os.environ.get(env_name, default).strip()


def _read_default_app_version(default="dev"):
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
            if value:
                return value
    except OSError:
        pass
    return default


DEFAULT_APP_VERSION = _read_default_app_version()
APP_VERSION = os.environ.get("APP_VERSION", DEFAULT_APP_VERSION).strip() or DEFAULT_APP_VERSION
APP_ENV = os.environ.get("APP_ENV", os.environ.get("FLASK_ENV", "development")).strip().lower() or "development"
IS_PRODUCTION = APP_ENV == "production"
APP_HOST = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT = _get_int("APP_PORT", 5000)
WAITRESS_THREADS = _get_int("WAITRESS_THREADS", 8)

DOCKER_SOCKET_URL = os.environ.get("DOCKER_SOCKET_URL", "unix:///var/run/docker.sock")
CADVISOR_URL = os.environ.get("CADVISOR_URL", "http://cadvisor:8080")
SAMPLE_INTERVAL = _get_int("SAMPLE_INTERVAL", 5)
MAX_SECONDS = _get_int("MAX_SECONDS", 86400)
STREAM_HEARTBEAT_SECONDS = _get_int("STREAM_HEARTBEAT_SECONDS", 15)

AUTH_ENABLED = _get_bool("AUTH_ENABLED", True)
LOGIN_MODE = os.environ.get("LOGIN_MODE", "popup").strip().lower() or "popup"
AUTH_USER = os.environ.get("AUTH_USER", "").strip()
AUTH_PASSWORD = _read_secret("AUTH_PASSWORD", "AUTH_PASSWORD_FILE", default="")

REQUIRE_EXPLICIT_SECRET_KEY = _get_bool("REQUIRE_EXPLICIT_SECRET_KEY", IS_PRODUCTION)
SESSION_IDLE_MINUTES = _get_int("SESSION_IDLE_MINUTES", 30)
SESSION_COOKIE_SECURE = _get_bool("SESSION_COOKIE_SECURE", IS_PRODUCTION)
SESSION_COOKIE_HTTPONLY = _get_bool("SESSION_COOKIE_HTTPONLY", True)
SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax").strip() or "Lax"

LOGIN_RATE_LIMIT_MAX_ATTEMPTS = _get_int("LOGIN_RATE_LIMIT_MAX_ATTEMPTS", 5)
LOGIN_RATE_LIMIT_WINDOW_SECONDS = _get_int("LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300)

# External programmatic API (API keys). Per-key rate limiting protects the
# endpoints from brute force and abuse even when exposed behind a reverse proxy.
EXTERNAL_API_RATE_LIMIT_MAX = _get_int("EXTERNAL_API_RATE_LIMIT_MAX", 120)
EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS = _get_int("EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS", 60)
# Reject unauthenticated bearer tokens this many times per IP within the window
# before temporarily blocking the IP (mitigates token guessing).
EXTERNAL_API_AUTH_FAIL_MAX = _get_int("EXTERNAL_API_AUTH_FAIL_MAX", 10)
EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS = _get_int("EXTERNAL_API_AUTH_FAIL_WINDOW_SECONDS", 60)
# When true, container-mutating endpoints require an HTTPS request.
EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE = _get_bool("EXTERNAL_API_REQUIRE_HTTPS_FOR_WRITE", False)

TRUSTED_PROXY_HOPS = _get_int("TRUSTED_PROXY_HOPS", 0)
ENABLE_PROXY_FIX = _get_bool("ENABLE_PROXY_FIX", TRUSTED_PROXY_HOPS > 0)
PROXY_FIX_X_FOR = _get_int("PROXY_FIX_X_FOR", TRUSTED_PROXY_HOPS)
PROXY_FIX_X_PROTO = _get_int("PROXY_FIX_X_PROTO", 1 if TRUSTED_PROXY_HOPS > 0 else 0)
PROXY_FIX_X_HOST = _get_int("PROXY_FIX_X_HOST", 1 if TRUSTED_PROXY_HOPS > 0 else 0)
PROXY_FIX_X_PORT = _get_int("PROXY_FIX_X_PORT", 0)
PROXY_FIX_X_PREFIX = _get_int("PROXY_FIX_X_PREFIX", 0)

SECURITY_HEADERS_ENABLED = _get_bool("SECURITY_HEADERS_ENABLED", True)
SECURITY_CSP_ENABLED = _get_bool("SECURITY_CSP_ENABLED", True)
SECURITY_HSTS_MAX_AGE = _get_int("SECURITY_HSTS_MAX_AGE", 31536000)
SECURITY_HSTS_INCLUDE_SUBDOMAINS = _get_bool("SECURITY_HSTS_INCLUDE_SUBDOMAINS", False)
SECURITY_HSTS_PRELOAD = _get_bool("SECURITY_HSTS_PRELOAD", False)
SECURITY_REFERRER_POLICY = os.environ.get(
    "SECURITY_REFERRER_POLICY",
    "strict-origin-when-cross-origin",
).strip() or "strict-origin-when-cross-origin"

APP_SECRET_KEY = _read_secret("APP_SECRET_KEY", "APP_SECRET_KEY_FILE", default="")
APP_SECRET_KEY_EPHEMERAL = False
if not APP_SECRET_KEY:
    APP_SECRET_KEY = secrets.token_urlsafe(32)
    APP_SECRET_KEY_EPHEMERAL = True
