import base64
import collections
import time

import app as app_module
import pytest
import routes
import sampler
import users_db


def set_page_session(client, username="admin", csrf_token="test-csrf"):
    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["username"] = username
        sess["csrf_token"] = csrf_token
    return csrf_token


def basic_auth_header(username, password):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def set_auth_mode(client, mode="page", enabled=True):
    client.application.config["AUTH_ENABLED"] = enabled
    client.application.config["LOGIN_MODE"] = mode


def make_test_client(**overrides):
    test_app = app_module.create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "APP_SECRET_KEY_EPHEMERAL": False,
        "APP_VERSION": "test-version",
        "AUTH_ENABLED": True,
        "AUTH_USER": "admin",
        "AUTH_PASSWORD": "adminpass",
        "LOGIN_MODE": "page",
        **overrides,
    })
    return test_app.test_client()


def test_change_password_works_with_page_login_session(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    response = client.post(
        "/api/change-password",
        json={"current_password": "adminpass", "new_password": "better-pass"},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert users_db.validate_user("admin", "better-pass") is True


def test_login_and_index_pages_render(client, monkeypatch):
    set_auth_mode(client, "page")

    login_response = client.get("/login")
    assert login_response.status_code == 200
    assert b"statainer" in login_response.data
    assert b"test-version" in login_response.data

    set_page_session(client)
    index_response = client.get("/")
    assert index_response.status_code == 200
    assert b"One cockpit for containers, updates and alerts." in index_response.data
    assert b"test-version" in index_response.data


def test_login_sets_secure_cookie_attributes_and_session_expiry(temp_db):
    client = make_test_client(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_IDLE_MINUTES=15,
    )

    response = client.get("/login")

    assert response.status_code == 200
    cookie_header = response.headers["Set-Cookie"]
    assert "Secure" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header
    assert "Expires=" in cookie_header
    assert client.application.config["PERMANENT_SESSION_LIFETIME"].total_seconds() == 900


def test_security_headers_add_hsts_only_when_proxy_fix_marks_request_secure(temp_db):
    insecure_client = make_test_client(AUTH_ENABLED=False, ENABLE_PROXY_FIX=False)
    secure_client = make_test_client(
        AUTH_ENABLED=False,
        ENABLE_PROXY_FIX=True,
        PROXY_FIX_X_PROTO=1,
        PROXY_FIX_X_HOST=1,
    )

    insecure_response = insecure_client.get(
        "/api/system-status",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "statainer.example.com"},
    )
    secure_response = secure_client.get(
        "/api/system-status",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "statainer.example.com"},
    )

    assert insecure_response.status_code == 200
    assert secure_response.status_code == 200
    assert insecure_response.headers.get("Strict-Transport-Security") is None
    assert secure_response.headers["Strict-Transport-Security"].startswith("max-age=31536000")
    assert secure_response.headers["X-Content-Type-Options"] == "nosniff"
    assert secure_response.headers["X-Frame-Options"] == "DENY"
    assert secure_response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in secure_response.headers["Content-Security-Policy"]


def test_production_requires_explicit_secret_key():
    with pytest.raises(RuntimeError, match="APP_SECRET_KEY or APP_SECRET_KEY_FILE is required"):
        app_module.create_app({
            "TESTING": True,
            "APP_ENV": "production",
            "REQUIRE_EXPLICIT_SECRET_KEY": True,
            "APP_SECRET_KEY_EPHEMERAL": True,
        })


def test_logout_clears_session_and_redirects_to_login(client):
    set_auth_mode(client, "page")
    set_page_session(client, username="admin")

    response = client.get("/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")
    assert "no-cache" in response.headers["Cache-Control"]
    with client.session_transaction() as sess:
        assert "authenticated" not in sess
        assert "username" not in sess


def test_whoami_returns_authenticated_user_context(client):
    set_auth_mode(client, "page")
    set_page_session(client, username="admin")

    response = client.get("/whoami")

    assert response.status_code == 200
    assert response.get_json() == {"username": "admin", "role": "admin"}


def test_change_password_supports_basic_auth(client, monkeypatch):
    set_auth_mode(client, "popup")
    with client.session_transaction() as sess:
        sess["csrf_token"] = "popup-csrf"
    csrf_token = "popup-csrf"

    response = client.post(
        "/api/change-password",
        json={"current_password": "adminpass", "new_password": "popup-pass"},
        headers={
            "X-CSRFToken": csrf_token,
            **basic_auth_header("admin", "adminpass"),
        },
    )

    assert response.status_code == 200
    assert response.get_json()["ok"] is True
    assert users_db.validate_user("admin", "popup-pass") is True


def test_user_management_requires_admin(client, monkeypatch):
    users_db.create_user_with_columns("alice", "alice-pass", ["cpu"])
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client, username="alice")

    response = client.get("/api/users")
    assert response.status_code == 403

    delete_response = client.delete(
        "/api/users/alice",
        headers={"X-CSRFToken": csrf_token},
    )
    assert delete_response.status_code == 403


def test_notification_settings_roundtrip_for_admin(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    response = client.post(
        "/api/notification-settings",
        json={
            "cpu_enabled": False,
            "ram_enabled": True,
            "status_enabled": True,
            "update_enabled": False,
            "security_enabled": True,
            "security_privileged_enabled": True,
            "security_public_ports_enabled": False,
            "security_latest_enabled": False,
            "security_docker_socket_enabled": True,
            "cpu_threshold": 55,
            "ram_threshold": 65,
            "window_seconds": 25,
            "cooldown_seconds": 90,
            "project_rule_mode": "include",
            "project_rules": "demo\njobs-*",
            "container_rule_mode": "exclude",
            "container_rules": "db\nworker-*",
            "silence_enabled": True,
            "silence_start": "23:00",
            "silence_end": "06:30",
            "dedupe_enabled": True,
            "dedupe_window_seconds": 300,
        },
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["settings"]["cpu_threshold"] == 55
    assert payload["settings"]["cooldown_seconds"] == 90
    assert payload["settings"]["project_rule_mode"] == "include"
    assert payload["settings"]["container_rule_mode"] == "exclude"
    assert payload["settings"]["security_public_ports_enabled"] is False
    assert payload["settings"]["security_latest_enabled"] is False
    assert payload["settings"]["silence_enabled"] is True
    assert payload["settings"]["dedupe_window_seconds"] == 300

    get_response = client.get("/api/notification-settings")
    assert get_response.status_code == 200
    assert get_response.get_json()["window_seconds"] == 25
    assert get_response.get_json()["project_rules"] == "demo\njobs-*"
    assert get_response.get_json()["security_public_ports_enabled"] is False


def test_notification_settings_defaults_disable_security_advisories(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    response = client.get("/api/notification-settings")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["security_enabled"] is False
    assert payload["security_privileged_enabled"] is False
    assert payload["security_public_ports_enabled"] is False
    assert payload["security_latest_enabled"] is False
    assert payload["security_docker_socket_enabled"] is False


def test_notification_test_reports_missing_configuration(client, monkeypatch):
    set_auth_mode(client, "page")
    monkeypatch.setattr(routes, "send_notification", lambda *args, **kwargs: {
        "ok": False,
        "configured_any": False,
        "successful_channels": [],
        "channels": {
            "pushover": {"configured": False, "ok": False, "skipped": "missing env vars"},
            "ntfy": {"configured": False, "ok": False, "skipped": "missing env vars"},
            "webhook": {"configured": False, "ok": False, "skipped": "missing env vars"},
        },
    })
    csrf_token = set_page_session(client)

    response = client.post(
        "/api/notification-test",
        json={"message": "hello"},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["configured_any"] is False


def test_update_manager_list_endpoint_returns_inventory_for_admin(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    monkeypatch.setattr(routes.update_manager, "list_update_targets", lambda history_limit=20, force_refresh=False: {
        "experimental_notice": "Experimental feature.",
        "projects": [{"target_id": "demo", "name": "demo", "type": "project"}],
        "containers": [{"target_id": "cache", "name": "cache", "type": "container"}],
        "history": [],
        "history_limit": history_limit,
        "force_refresh": force_refresh,
    })

    response = client.get("/api/update-manager?history_limit=15&refresh=1")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["projects"][0]["name"] == "demo"
    assert payload["containers"][0]["name"] == "cache"
    assert payload["force_refresh"] is True


def test_update_manager_update_endpoint_executes_target(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    monkeypatch.setattr(routes.update_manager, "update_target", lambda target_type, target_id, actor_username=None: {
        "ok": True,
        "message": f"{target_type}:{target_id} updated",
        "history_entry": {"id": 7, "target_type": target_type, "target_id": target_id},
    })

    response = client.post(
        "/api/update-manager/update",
        json={"target_type": "project", "target_id": "demo"},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["history_entry"]["id"] == 7


def test_update_manager_update_endpoint_emits_success_notification(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)
    emitted = []

    monkeypatch.setattr(routes.update_manager, "update_target", lambda target_type, target_id, actor_username=None: {
        "ok": True,
        "message": f"{target_type}:{target_id} updated",
        "history_entry": {
            "id": 11,
            "target_type": target_type,
            "target_id": target_id,
            "target_name": "demo",
            "previous_version": "web=nginx:1.25.3",
            "new_version": "web=nginx:1.25.4",
        },
    })
    monkeypatch.setattr(routes.sampler, "emit_notification", lambda event: emitted.append(event))

    response = client.post(
        "/api/update-manager/update",
        json={"target_type": "project", "target_id": "demo"},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    assert emitted == [{
        "type": "update",
        "scope": "update_success",
        "timestamp": emitted[0]["timestamp"],
        "cid": None,
        "container": "",
        "project": "demo",
        "target_type": "project",
        "target_name": "demo",
        "previous_version": "web=nginx:1.25.3",
        "new_version": "web=nginx:1.25.4",
        "msg": 'Stack "demo" updated from web=nginx:1.25.3 -> web=nginx:1.25.4',
    }]


def test_update_manager_update_endpoint_emits_failure_notification(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)
    emitted = []

    monkeypatch.setattr(routes.update_manager, "update_target", lambda target_type, target_id, actor_username=None: {
        "ok": False,
        "message": f"{target_type}:{target_id} failed",
        "history_entry": {"id": 12, "target_type": target_type, "target_id": target_id, "target_name": "cache"},
    })
    monkeypatch.setattr(routes.sampler, "emit_notification", lambda event: emitted.append(event))

    response = client.post(
        "/api/update-manager/update",
        json={"target_type": "container", "target_id": "cache-standalone"},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 409
    assert emitted == [{
        "type": "update",
        "scope": "update_failure",
        "timestamp": emitted[0]["timestamp"],
        "cid": "cache-standalone",
        "container": "cache",
        "project": "",
        "target_type": "container",
        "target_name": "cache",
        "previous_version": None,
        "new_version": None,
        "msg": 'Container "cache" failed to update. container:cache-standalone failed',
    }]


def test_update_manager_auto_update_endpoint_updates_target(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    monkeypatch.setattr(routes.update_manager, "configure_auto_update_target", lambda target_type, target_name, enabled: {
        "ok": True,
        "message": f"Auto-update {'enabled' if enabled else 'disabled'} for {target_type} {target_name}",
        "item": {
            "type": target_type,
            "name": target_name,
            "auto_update_enabled": enabled,
        },
    })

    response = client.post(
        "/api/update-manager/auto-update",
        json={"target_type": "project", "target_name": "demo", "enabled": True},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["item"]["auto_update_enabled"] is True


def test_update_manager_rollback_endpoint_reports_failure_state(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    monkeypatch.setattr(routes.update_manager, "rollback_update", lambda history_id, actor_username=None: {
        "ok": False,
        "message": f"Rollback {history_id} failed",
        "history_entry": {"id": 9, "result": "failure"},
    })

    response = client.post(
        "/api/update-manager/rollback",
        json={"history_id": 9},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 409
    payload = response.get_json()
    assert payload["ok"] is False
    assert payload["message"] == "Rollback 9 failed"


def test_system_status_exposes_backend_diagnostics(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client, username="admin")
    monkeypatch.setattr(routes, "get_configured_services", lambda: {
        "pushover": {"configured": True},
        "slack": {"configured": False},
        "telegram": {"configured": False},
        "discord": {"configured": False},
        "ntfy": {"configured": False},
        "webhook": {"configured": False},
    })
    monkeypatch.setattr(routes, "get_docker_status", lambda: {
        "connected": False,
        "base_url": "unix:///var/run/docker.sock",
        "error": "daemon unavailable",
    })

    response = client.get("/api/system-status")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["docker"]["connected"] is False
    assert payload["notifications"]["pushover"]["configured"] is True
    assert payload["auth"]["role"] == "admin"
    assert payload["app"]["version"] == "test-version"


def test_projects_endpoint_returns_sorted_unique_compose_projects(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    class DummyContainer:
        def __init__(self, project):
            self.attrs = {
                "Config": {
                    "Labels": {"com.docker.compose.project": project} if project else {},
                },
            }

    class DummyContainers:
        def list(self, all=True):
            assert all is True
            return [
                DummyContainer("demo"),
                DummyContainer("jobs"),
                DummyContainer("demo"),
                DummyContainer(None),
            ]

    class DummyClient:
        containers = DummyContainers()

    monkeypatch.setattr(routes, "get_docker_client", lambda: DummyClient())

    response = client.get("/api/projects")

    assert response.status_code == 200
    assert response.get_json() == ["demo", "jobs"]


def test_metrics_summary_mode_returns_project_dashboard_payload(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    rows = [
        {
            "id": "web123",
            "name": "web",
            "status": "running",
            "cpu": 72.5,
            "mem": 64.2,
            "mem_usage": 657.4,
            "mem_limit": 1024.0,
            "restarts": 1,
            "update_available": False,
            "compose_project": "demo",
        },
        {
            "id": "db123",
            "name": "db",
            "status": "running",
            "cpu": 24.0,
            "mem": 52.0,
            "mem_usage": 1102.2,
            "mem_limit": 2048.0,
            "restarts": 0,
            "update_available": True,
            "compose_project": "demo",
        },
        {
            "id": "worker123",
            "name": "worker",
            "status": "exited",
            "cpu": 0.0,
            "mem": 0.0,
            "mem_usage": 0.0,
            "mem_limit": 512.0,
            "restarts": 2,
            "update_available": False,
            "compose_project": "jobs",
        },
    ]

    def fake_collect_metrics_rows(query):
        assert query["max_items"] == 0
        return rows

    monkeypatch.setattr(routes, "collect_metrics_rows", fake_collect_metrics_rows)

    response = client.get("/api/metrics?summary=1&max=1")

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["rows"]) == 1
    assert payload["rows"][0]["id"] == "web123"
    assert len(payload["project_summaries"]) == 2
    assert payload["project_summaries"][0]["project"] == "demo"
    assert payload["project_summaries"][0]["container_count"] == 2
    assert payload["project_summaries"][0]["running_count"] == 2
    assert payload["project_summaries"][0]["update_count"] == 1
    assert payload["project_summaries"][0]["status"] == "healthy"
    assert payload["project_summaries"][1]["project"] == "jobs"
    assert payload["project_summaries"][1]["status"] == "stopped"


def test_notifications_endpoint_supports_since_and_limit(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    def fake_get_notifications(since_ts=None, max_items=50):
        assert since_ts == 10.0
        assert max_items == 5
        return [{"timestamp": 12.5, "msg": "worker restarted", "type": "status"}]

    monkeypatch.setattr(sampler, "get_notifications", fake_get_notifications)

    response = client.get("/api/notifications?since=10&max=5")

    assert response.status_code == 200
    assert response.get_json() == [{"timestamp": 12.5, "msg": "worker restarted", "type": "status"}]


def test_audit_log_records_password_and_user_management_actions(client):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    password_response = client.post(
        "/api/change-password",
        json={"current_password": "adminpass", "new_password": "new-pass"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert password_response.status_code == 200

    create_response = client.post(
        "/api/users",
        json={"username": "bob", "password": "bob-pass", "columns": ["cpu"]},
        headers={"X-CSRFToken": csrf_token},
    )
    assert create_response.status_code == 200

    audit_response = client.get("/api/audit?limit=10")
    assert audit_response.status_code == 200
    events = audit_response.get_json()
    assert any(event["action"] == "user.password_change" and event["status"] == "success" for event in events)
    assert any(event["action"] == "user.create" and event["target_id"] == "bob" for event in events)


def test_container_actions_are_audited(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    class DummyContainer:
        name = "web"

        def start(self):
            return None

    class DummyContainers:
        def get(self, container_id):
            assert container_id == "abc123"
            return DummyContainer()

    class DummyClient:
        containers = DummyContainers()

    monkeypatch.setattr(routes, "get_docker_client", lambda: DummyClient())

    response = client.post(
        "/api/containers/abc123/start",
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    audit_events = users_db.list_audit_events(limit=10)
    assert any(event["action"] == "container.start" and event["target_id"] == "abc123" for event in audit_events)


def test_container_update_action_emits_update_notification(client, monkeypatch):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)
    emitted = []

    class DummyContainer:
        name = "cache"

    class DummyContainers:
        def get(self, container_id):
            assert container_id == "abc123"
            return DummyContainer()

    class DummyClient:
        containers = DummyContainers()

    monkeypatch.setattr(routes, "get_docker_client", lambda: DummyClient())
    monkeypatch.setattr(routes.update_manager, "update_container_target", lambda container_id, actor_username=None: {
        "ok": True,
        "message": "Container cache updated safely.",
        "history_entry": {
            "id": 14,
            "target_type": "container",
            "target_id": container_id,
            "target_name": "cache",
            "previous_version": "redis:7 @ cache-old",
            "new_version": "redis:7 @ cache-new",
        },
    })
    monkeypatch.setattr(routes.sampler, "emit_notification", lambda event: emitted.append(event))

    response = client.post(
        "/api/containers/abc123/update",
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    assert emitted == [{
        "type": "update",
        "scope": "update_success",
        "timestamp": emitted[0]["timestamp"],
        "cid": "abc123",
        "container": "cache",
        "project": "",
        "target_type": "container",
        "target_name": "cache",
        "previous_version": "redis:7 @ cache-old",
        "new_version": "redis:7 @ cache-new",
        "msg": 'Container "cache" updated from redis:7 @ cache-old -> redis:7 @ cache-new',
    }]


def test_metrics_stream_can_emit_single_snapshot(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)
    monkeypatch.setattr(routes, "collect_metrics_rows", lambda query: [{"id": "abc", "name": "web", "status": "running"}])
    monkeypatch.setattr(routes.sampler, "get_metrics_sequence", lambda: 1)
    monkeypatch.setattr(routes.sampler, "get_notification_sequence", lambda: 0)
    monkeypatch.setattr(routes.sampler, "get_notifications", lambda since_ts=None, max_items=200: [])

    response = client.get("/api/stream?once=1")

    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "event: connected" in body
    assert "event: metrics" in body
    assert '"name": "web"' in body


def test_logs_snapshot_returns_downloadable_text_file(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    class DummyContainer:
        name = "db primary"

        def logs(self, tail=100, timestamps=True):
            assert tail == 2
            assert timestamps is True
            return b"log line 1\nlog line 2\n"

    class DummyContainers:
        def get(self, container_id):
            assert container_id == "abc123"
            return DummyContainer()

    class DummyClient:
        containers = DummyContainers()

    monkeypatch.setattr(routes, "get_docker_client", lambda: DummyClient())

    response = client.get("/api/logs/abc123?tail=2&download=1")

    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    assert response.get_data(as_text=True) == "log line 1\nlog line 2\n"
    assert response.headers["Content-Disposition"] == 'attachment; filename="db-primary-abc123-logs.txt"'


def test_logs_stream_emits_connected_snapshot_and_live_lines(client, monkeypatch):
    set_auth_mode(client, "page")
    set_page_session(client)

    class DummyContainer:
        name = "db"

        def logs(self, tail=100, timestamps=True, stream=False, follow=False):
            assert timestamps is True
            if stream:
                assert tail == 0
                assert follow is True
                return iter([
                    b"2026-01-01T10:00:20.000000000Z db | live line 1\n",
                    b"2026-01-01T10:00:21.000000000Z db | live line 2\n",
                ])
            assert tail == 2
            return b"2026-01-01T10:00:00.000000000Z db | snapshot line 1\n2026-01-01T10:00:10.000000000Z db | snapshot line 2\n"

    class DummyContainers:
        def get(self, container_id):
            assert container_id == "abc123"
            return DummyContainer()

    class DummyClient:
        containers = DummyContainers()

    monkeypatch.setattr(routes, "get_docker_client", lambda: DummyClient())

    response = client.get("/api/logs/abc123/stream?tail=2")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    assert "event: connected" in body
    assert "event: snapshot" in body
    assert "event: line" in body
    assert '"container_name": "db"' in body
    assert "snapshot line 1" in body
    assert "live line 2" in body


def test_export_csv_returns_downloadable_csv(client):
    set_auth_mode(client, "page")
    csrf_token = set_page_session(client)

    response = client.post(
        "/api/export/csv",
        json={"metrics": [{"name": "web", "cpu": 12.5}, {"name": "db", "cpu": 8.0}]},
        headers={"X-CSRFToken": csrf_token},
    )

    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert "attachment; filename=metrics.csv" == response.headers["Content-Disposition"]
    body = response.get_data(as_text=True).splitlines()
    assert body[0] in {"name,cpu", "cpu,name"}
    assert set(body[1:]) == {"web,12.5", "db,8.0"} or set(body[1:]) == {"12.5,web", "8.0,db"}


# ---------------------------------------------------------------------------
# Login rate limiting
# ---------------------------------------------------------------------------

def _clear_rate_limiter():
    """Reset the in-memory rate limiter state between tests."""
    with routes._login_attempts_lock:
        routes._login_attempts.clear()


def _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3, window=300, login_mode="page"):
    db_path = tmp_path / "ratelimit_users.db"
    monkeypatch.setenv("USERS_DB_PATH", str(db_path))
    users_db.migrate_add_columns_and_role_and_settings()
    users_db.init_db("admin", "adminpass")
    return make_test_client(
        LOGIN_RATE_LIMIT_MAX_ATTEMPTS=max_attempts,
        LOGIN_RATE_LIMIT_WINDOW_SECONDS=window,
        LOGIN_MODE=login_mode,
    )


def test_page_login_rate_limit_blocks_after_max_failures(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3)

    # Set a CSRF token in the session
    with client.session_transaction() as sess:
        sess["csrf_token"] = "rate-csrf"

    # 3 failed attempts should be accepted (returns 200 with error message)
    for i in range(3):
        resp = client.post("/login", data={
            "username": "admin",
            "password": "wrong",
            "csrf_token": "rate-csrf",
        })
        assert resp.status_code == 200, f"Attempt {i+1} should return 200"

    # 4th attempt should be rate limited (429)
    resp = client.post("/login", data={
        "username": "admin",
        "password": "wrong",
        "csrf_token": "rate-csrf",
    })
    assert resp.status_code == 429
    assert b"Too many failed login attempts" in resp.data
    _clear_rate_limiter()


def test_page_login_successful_login_resets_rate_limiter(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3)

    with client.session_transaction() as sess:
        sess["csrf_token"] = "rate-csrf"

    # 2 failed attempts
    for _ in range(2):
        client.post("/login", data={
            "username": "admin",
            "password": "wrong",
            "csrf_token": "rate-csrf",
        })

    # Successful login should reset counter
    resp = client.post("/login", data={
        "username": "admin",
        "password": "adminpass",
        "csrf_token": "rate-csrf",
    }, follow_redirects=False)
    assert resp.status_code == 302  # redirect on success

    # After reset, further failed attempts should be allowed again
    with client.session_transaction() as sess:
        sess.pop("authenticated", None)
        sess["csrf_token"] = "rate-csrf"

    for _ in range(3):
        resp = client.post("/login", data={
            "username": "admin",
            "password": "wrong",
            "csrf_token": "rate-csrf",
        })
        assert resp.status_code == 200
    _clear_rate_limiter()


def test_popup_basic_auth_rate_limit_blocks_after_max_failures(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3, login_mode="popup")

    # 3 failed attempts (with bad credentials)
    for i in range(3):
        resp = client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))
        assert resp.status_code == 401, f"Attempt {i+1} should return 401"

    # 4th attempt should be rate limited
    resp = client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))
    assert resp.status_code == 429
    _clear_rate_limiter()


def test_popup_basic_auth_successful_login_resets_limiter(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3, login_mode="popup")

    # 2 failed attempts
    for _ in range(2):
        client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))

    # Successful request should reset
    resp = client.get("/api/system-status", headers=basic_auth_header("admin", "adminpass"))
    assert resp.status_code == 200

    # Counter reset – 3 more failures allowed
    for _ in range(3):
        resp = client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))
        assert resp.status_code == 401
    _clear_rate_limiter()


def test_rate_limit_disabled_when_max_attempts_zero(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=0, login_mode="popup")

    # Should never block, even after many failures
    for _ in range(20):
        resp = client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))
        assert resp.status_code == 401
    _clear_rate_limiter()


def test_page_login_rate_limit_sets_retry_after_header(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=2)

    with client.session_transaction() as sess:
        sess["csrf_token"] = "rate-csrf"

    for _ in range(2):
        client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": "rate-csrf"})

    resp = client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": "rate-csrf"})
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1
    assert "no-store" in resp.headers.get("Cache-Control", "")
    _clear_rate_limiter()


def test_popup_rate_limit_sets_retry_after_header(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=2, login_mode="popup")

    for _ in range(2):
        client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))

    resp = client.get("/api/system-status", headers=basic_auth_header("admin", "wrong"))
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1
    _clear_rate_limiter()


def test_login_page_is_not_cacheable(client, monkeypatch):
    set_auth_mode(client, "page")
    resp = client.get("/login")
    assert resp.status_code == 200
    assert "no-store" in resp.headers.get("Cache-Control", "")


def test_login_rejects_mismatched_csrf_token(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=5)

    with client.session_transaction() as sess:
        sess["csrf_token"] = "the-real-token"

    # A wrong CSRF token must be rejected (403) regardless of valid credentials.
    resp = client.post("/login", data={
        "username": "admin",
        "password": "adminpass",
        "csrf_token": "an-attacker-guess",
    })
    assert resp.status_code == 403
    with client.session_transaction() as sess:
        assert sess.get("authenticated") is not True
    _clear_rate_limiter()


def test_csrf_helper_uses_constant_time_comparison(client):
    with client.application.test_request_context(
        "/api/x", method="POST", headers={"X-CSRFToken": "abc123"}
    ):
        from flask import session as flask_session
        flask_session["csrf_token"] = "abc123"
        assert routes.has_valid_csrf_token() is True
        flask_session["csrf_token"] = "different"
        assert routes.has_valid_csrf_token() is False
        flask_session.pop("csrf_token", None)
        assert routes.has_valid_csrf_token() is False


def test_rate_limiter_purges_stale_buckets(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3, window=1)

    with client.application.app_context():
        # Insert an expired bucket and a fresh one, then trigger a purge.
        now = time.monotonic()
        with routes._login_attempts_lock:
            routes._login_attempts["1.1.1.1"] = collections.deque([now - 100])
            routes._login_attempts["2.2.2.2"] = collections.deque([now])
            routes._purge_stale_buckets_locked(now, window=1)
        assert "1.1.1.1" not in routes._login_attempts  # expired -> dropped
        assert "2.2.2.2" in routes._login_attempts       # fresh -> kept
    _clear_rate_limiter()


def test_rate_limiter_caps_tracked_ip_count(tmp_path, monkeypatch):
    _clear_rate_limiter()
    client = _make_rate_limit_client(tmp_path, monkeypatch, max_attempts=3, window=300)

    original_cap = routes._MAX_TRACKED_IPS
    monkeypatch.setattr(routes, "_MAX_TRACKED_IPS", 5)
    try:
        with client.application.app_context():
            for i in range(50):
                routes.record_failed_login(f"10.0.0.{i}")
            assert len(routes._login_attempts) <= 5
    finally:
        routes._MAX_TRACKED_IPS = original_cap
    _clear_rate_limiter()
