#!/usr/bin/env python
# -*- coding: utf-8 -*-

print("***********************************")
print("*** statainer APP STARTING ***")
print("***********************************")

import threading
import time
import warnings
from datetime import timedelta

from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    from waitress import serve

    HAS_WAITRESS = True
except ImportError:  # waitress not installed
    serve = None
    HAS_WAITRESS = False

from config import (
    APP_HOST,
    APP_PORT,
    APP_ENV,
    APP_SECRET_KEY,
    APP_SECRET_KEY_EPHEMERAL,
    APP_VERSION,
    AUTH_ENABLED,
    AUTH_PASSWORD,
    AUTH_USER,
    CADVISOR_URL,
    DOCKER_SOCKET_URL,
    ENABLE_PROXY_FIX,
    LOGIN_MODE,
    MAX_SECONDS,
    PROXY_FIX_X_FOR,
    PROXY_FIX_X_HOST,
    PROXY_FIX_X_PORT,
    PROXY_FIX_X_PREFIX,
    PROXY_FIX_X_PROTO,
    REQUIRE_EXPLICIT_SECRET_KEY,
    SAMPLE_INTERVAL,
    SECURITY_CSP_ENABLED,
    SECURITY_HEADERS_ENABLED,
    SECURITY_HSTS_INCLUDE_SUBDOMAINS,
    SECURITY_HSTS_MAX_AGE,
    SECURITY_HSTS_PRELOAD,
    SECURITY_REFERRER_POLICY,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE,
    SESSION_IDLE_MINUTES,
    STREAM_HEARTBEAT_SECONDS,
    WAITRESS_THREADS,
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    LOGIN_RATE_LIMIT_WINDOW_SECONDS,
)
from api_routes import api_v1
from docker_client import get_docker_status, initialize_docker_clients
from routes import main_routes
from sampler import sample_metrics
from users_db import count_users, init_db


def build_content_security_policy():
    directives = {
        "default-src": ["'self'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'none'"],
        "object-src": ["'none'"],
        "img-src": ["'self'", "data:"],
        "font-src": ["'self'", "data:", "https://cdn.jsdelivr.net", "https://fonts.gstatic.com"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "connect-src": ["'self'"],
    }
    return "; ".join(
        f"{directive} {' '.join(sources)}"
        for directive, sources in directives.items()
    )


def build_hsts_header(config):
    value = f"max-age={int(config.get('SECURITY_HSTS_MAX_AGE', 31536000))}"
    if config.get("SECURITY_HSTS_INCLUDE_SUBDOMAINS"):
        value += "; includeSubDomains"
    if config.get("SECURITY_HSTS_PRELOAD"):
        value += "; preload"
    return value


def apply_proxy_fix(flask_app):
    if not flask_app.config.get("ENABLE_PROXY_FIX"):
        return
    proxy_args = {
        "x_for": int(flask_app.config.get("PROXY_FIX_X_FOR", 0)),
        "x_proto": int(flask_app.config.get("PROXY_FIX_X_PROTO", 0)),
        "x_host": int(flask_app.config.get("PROXY_FIX_X_HOST", 0)),
        "x_port": int(flask_app.config.get("PROXY_FIX_X_PORT", 0)),
        "x_prefix": int(flask_app.config.get("PROXY_FIX_X_PREFIX", 0)),
    }
    if not any(proxy_args.values()):
        return
    flask_app.wsgi_app = ProxyFix(flask_app.wsgi_app, **proxy_args)


def configure_security(flask_app):
    if flask_app.config.get("REQUIRE_EXPLICIT_SECRET_KEY") and flask_app.config.get("APP_SECRET_KEY_EPHEMERAL"):
        raise RuntimeError(
            "APP_SECRET_KEY or APP_SECRET_KEY_FILE is required when APP_ENV=production. "
            "Set REQUIRE_EXPLICIT_SECRET_KEY=false only if you intentionally accept ephemeral sessions."
        )

    flask_app.config.update(
        SESSION_COOKIE_SECURE=bool(flask_app.config.get("SESSION_COOKIE_SECURE", False)),
        SESSION_COOKIE_HTTPONLY=bool(flask_app.config.get("SESSION_COOKIE_HTTPONLY", True)),
        SESSION_COOKIE_SAMESITE=flask_app.config.get("SESSION_COOKIE_SAMESITE", "Lax"),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(flask_app.config.get("SESSION_IDLE_MINUTES", 30))),
        SESSION_REFRESH_EACH_REQUEST=True,
    )


def create_app(test_config=None):
    """Application factory used by runtime and tests."""
    flask_app = Flask(__name__, static_url_path='/static', static_folder='static')
    flask_app.config.from_mapping(
        SECRET_KEY=APP_SECRET_KEY,
        APP_VERSION=APP_VERSION,
        APP_ENV=APP_ENV,
        APP_SECRET_KEY_EPHEMERAL=APP_SECRET_KEY_EPHEMERAL,
        AUTH_ENABLED=AUTH_ENABLED,
        AUTH_USER=AUTH_USER,
        AUTH_PASSWORD=AUTH_PASSWORD,
        CADVISOR_URL=CADVISOR_URL,
        DOCKER_SOCKET_URL=DOCKER_SOCKET_URL,
        ENABLE_PROXY_FIX=ENABLE_PROXY_FIX,
        LOGIN_MODE=LOGIN_MODE,
        SAMPLE_INTERVAL=SAMPLE_INTERVAL,
        MAX_SECONDS=MAX_SECONDS,
        PROXY_FIX_X_FOR=PROXY_FIX_X_FOR,
        PROXY_FIX_X_PROTO=PROXY_FIX_X_PROTO,
        PROXY_FIX_X_HOST=PROXY_FIX_X_HOST,
        PROXY_FIX_X_PORT=PROXY_FIX_X_PORT,
        PROXY_FIX_X_PREFIX=PROXY_FIX_X_PREFIX,
        REQUIRE_EXPLICIT_SECRET_KEY=REQUIRE_EXPLICIT_SECRET_KEY,
        SECURITY_HEADERS_ENABLED=SECURITY_HEADERS_ENABLED,
        SECURITY_CSP_ENABLED=SECURITY_CSP_ENABLED,
        SECURITY_HSTS_MAX_AGE=SECURITY_HSTS_MAX_AGE,
        SECURITY_HSTS_INCLUDE_SUBDOMAINS=SECURITY_HSTS_INCLUDE_SUBDOMAINS,
        SECURITY_HSTS_PRELOAD=SECURITY_HSTS_PRELOAD,
        SECURITY_REFERRER_POLICY=SECURITY_REFERRER_POLICY,
        SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
        SESSION_COOKIE_HTTPONLY=SESSION_COOKIE_HTTPONLY,
        SESSION_COOKIE_SAMESITE=SESSION_COOKIE_SAMESITE,
        SESSION_IDLE_MINUTES=SESSION_IDLE_MINUTES,
        STREAM_HEARTBEAT_SECONDS=STREAM_HEARTBEAT_SECONDS,
        LOGIN_RATE_LIMIT_MAX_ATTEMPTS=LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    )
    if test_config:
        flask_app.config.update(test_config)

    if test_config and test_config.get("SECRET_KEY"):
        flask_app.config["APP_SECRET_KEY_EPHEMERAL"] = False

    configure_security(flask_app)
    apply_proxy_fix(flask_app)

    flask_app.secret_key = flask_app.config["SECRET_KEY"]
    flask_app.register_blueprint(main_routes)
    flask_app.register_blueprint(api_v1)

    @flask_app.after_request
    def add_security_headers(response):
        if not flask_app.config.get("SECURITY_HEADERS_ENABLED", True):
            return response

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Referrer-Policy",
            flask_app.config.get("SECURITY_REFERRER_POLICY", "strict-origin-when-cross-origin"),
        )
        response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=()")

        if flask_app.config.get("SECURITY_CSP_ENABLED", True):
            response.headers.setdefault("Content-Security-Policy", build_content_security_policy())

        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", build_hsts_header(flask_app.config))

        return response

    @flask_app.context_processor
    def inject_template_globals():
        return {
            "app_version": flask_app.config.get("APP_VERSION", "dev"),
        }

    return flask_app


app = create_app()


def start_sampler_thread():
    print("Starting metrics sampling thread...")
    sampler_thread = threading.Thread(target=sample_metrics, daemon=True)
    sampler_thread.start()
    print("Sampling thread started.")


def initialize_runtime():
    """Prepare auth DB and Docker connectivity without failing the whole app."""
    bootstrap_user = app.config.get("AUTH_USER", "")
    bootstrap_password = app.config.get("AUTH_PASSWORD", "")
    auth_enabled = bool(app.config.get("AUTH_ENABLED", True))

    if bootstrap_user and bootstrap_password:
        init_db(bootstrap_user, bootstrap_password)

    user_count = count_users()
    if auth_enabled and user_count == 0:
        raise RuntimeError(
            "AUTH_ENABLED is true but no users exist. Set AUTH_USER/AUTH_PASSWORD (or *_FILE) for the first startup."
        )

    if app.config.get("APP_SECRET_KEY_EPHEMERAL"):
        warnings.warn(
            "APP_SECRET_KEY is not set. A temporary secret key was generated for this process; sessions will be reset on restart.",
            RuntimeWarning,
        )

    docker_ready = initialize_docker_clients(force=True)
    docker_status = get_docker_status()

    if docker_ready:
        print(f"Docker connection established via: {DOCKER_SOCKET_URL}")
    else:
        print("WARN: Docker client not available at startup. The UI will run in degraded mode.")
        if docker_status.get("error"):
            print(f"      {docker_status['error']}")

    print(f"Sampler interval: {SAMPLE_INTERVAL} seconds")
    print(f"History retention: {MAX_SECONDS / 3600} hours")
    print(f"App version: {app.config.get('APP_VERSION')}")
    return docker_ready


if __name__ == '__main__':
    print("-------------------------------------")
    print(" statainer ")
    print("-------------------------------------")
    print("Starting Flask server...")

    docker_ready = initialize_runtime()
    start_sampler_thread()

    if docker_ready:
        time.sleep(1)

    print(f"Access the monitor at: http://{APP_HOST}:{APP_PORT} (or your machine's IP:{APP_PORT})")
    print("-------------------------------------")

    if HAS_WAITRESS:
        print(f"Using Waitress server with {WAITRESS_THREADS} threads...")
        serve(app, host=APP_HOST, port=APP_PORT, threads=WAITRESS_THREADS)
    else:
        print("Waitress not found, using Flask development server (WARNING: Not recommended for production).")
        app.run(host=APP_HOST, port=APP_PORT, debug=False)
