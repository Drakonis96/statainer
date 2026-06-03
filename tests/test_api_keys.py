import time

import pytest

import api_keys as api_keys_service
import api_routes
import routes
import users_db


def set_admin_session(client, username="admin", csrf_token="test-csrf"):
    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["username"] = username
        sess["csrf_token"] = csrf_token
    return csrf_token


@pytest.fixture(autouse=True)
def reset_api_rate_limits():
    api_routes._request_counts.clear()
    api_routes._auth_failures.clear()
    yield
    api_routes._request_counts.clear()
    api_routes._auth_failures.clear()


# ---------------------------------------------------------------------------
# Storage + service layer
# ---------------------------------------------------------------------------
def test_create_key_stores_only_hash_and_returns_plaintext_once(temp_db):
    token, record = api_keys_service.create_key("ci-bot", ["system:read"], created_by="admin")
    assert token.startswith("stnr_")
    assert record["name"] == "ci-bot"
    assert record["scopes"] == ["system:read"]

    stored = users_db.get_api_key_by_hash(api_keys_service.hash_token(token))
    assert stored is not None
    assert stored["key_hash"] != token  # plaintext is never persisted
    # Listing never exposes the hash.
    assert "key_hash" not in users_db.list_api_keys()[0]


def test_authenticate_rejects_invalid_disabled_and_expired_keys(temp_db):
    token, record = api_keys_service.create_key("k", ["system:read"], created_by="admin")
    assert api_keys_service.authenticate(token) is not None
    assert api_keys_service.authenticate("stnr_wrong") is None
    assert api_keys_service.authenticate("") is None

    users_db.set_api_key_enabled(record["id"], False)
    assert api_keys_service.authenticate(token) is None
    users_db.set_api_key_enabled(record["id"], True)
    assert api_keys_service.authenticate(token) is not None

    # Expired keys are rejected.
    expired_token, _ = api_keys_service.create_key(
        "exp", ["system:read"], created_by="admin", expires_at=time.time() + 5
    )
    assert api_keys_service.authenticate(expired_token, now_ts=time.time() + 10) is None


def test_create_key_validates_input(temp_db):
    with pytest.raises(ValueError):
        api_keys_service.create_key("", ["system:read"])
    with pytest.raises(ValueError):
        api_keys_service.create_key("no-scopes", [])
    with pytest.raises(ValueError):
        api_keys_service.create_key("only-bad", ["nope:read"])
    with pytest.raises(ValueError):
        api_keys_service.create_key("past", ["system:read"], expires_at=time.time() - 100)


def test_normalize_scopes_filters_and_orders():
    assert api_keys_service.normalize_scopes(["containers:read", "bogus", "system:read", "system:read"]) == [
        "system:read",
        "containers:read",
    ]


# ---------------------------------------------------------------------------
# Admin management endpoints
# ---------------------------------------------------------------------------
def test_admin_can_manage_api_keys_lifecycle(client):
    csrf = set_admin_session(client)

    listing = client.get("/api/api-keys").get_json()
    assert listing["enabled"] is False
    assert listing["keys"] == []
    assert any(s["id"] == "containers:start" for s in listing["scopes"])

    # Enable the master toggle.
    toggle = client.post("/api/api-keys/settings", json={"enabled": True}, headers={"X-CSRFToken": csrf})
    assert toggle.status_code == 200
    assert users_db.is_external_api_enabled() is True

    # Create a key.
    created = client.post(
        "/api/api-keys",
        json={"name": "deployer", "scopes": ["containers:read", "containers:restart"], "expires_in_days": 30},
        headers={"X-CSRFToken": csrf},
    )
    assert created.status_code == 201
    body = created.get_json()
    assert body["token"].startswith("stnr_")
    key_id = body["key"]["id"]
    assert body["key"]["expires_at"] is not None

    # Pause (reversible revoke), then resume.
    paused = client.put(f"/api/api-keys/{key_id}", json={"enabled": False}, headers={"X-CSRFToken": csrf})
    assert paused.status_code == 200
    assert paused.get_json()["key"]["enabled"] is False

    # Delete.
    deleted = client.delete(f"/api/api-keys/{key_id}", headers={"X-CSRFToken": csrf})
    assert deleted.status_code == 200
    assert users_db.list_api_keys() == []

    events = users_db.list_audit_events(limit=20)
    assert any(e["action"] == "api.key_create" and e["status"] == "success" for e in events)
    assert any(e["action"] == "api.key_delete" and e["status"] == "success" for e in events)


def test_non_admin_cannot_manage_api_keys(client, monkeypatch):
    users_db.create_user_with_columns("viewer", "pw", [], role="user")
    set_admin_session(client, username="viewer")
    assert client.get("/api/api-keys").status_code == 403


def test_create_api_key_rejects_empty_name(client):
    csrf = set_admin_session(client)
    resp = client.post("/api/api-keys", json={"name": "  ", "scopes": ["system:read"]}, headers={"X-CSRFToken": csrf})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# External /api/v1 surface
# ---------------------------------------------------------------------------
def _new_key(scopes):
    token, record = api_keys_service.create_key("ext", scopes, created_by="admin")
    return token


def test_external_api_requires_master_toggle(client):
    token = _new_key(["system:read"])
    users_db.set_external_api_settings({"enabled": False})
    resp = client.get("/api/v1/ping", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.get_json()["error"] == "api_disabled"


def test_external_api_rejects_missing_and_invalid_tokens(client):
    users_db.set_external_api_settings({"enabled": True})
    assert client.get("/api/v1/ping").status_code == 401
    assert client.get("/api/v1/ping", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_external_api_ping_and_me(client):
    users_db.set_external_api_settings({"enabled": True})
    token = _new_key(["system:read", "containers:read"])
    headers = {"Authorization": f"Bearer {token}"}

    ping = client.get("/api/v1/ping", headers=headers)
    assert ping.status_code == 200 and ping.get_json()["pong"] is True

    me = client.get("/api/v1/me", headers=headers)
    assert set(me.get_json()["scopes"]) == {"system:read", "containers:read"}


def test_external_api_enforces_scopes(client):
    users_db.set_external_api_settings({"enabled": True})
    token = _new_key(["system:read"])  # no stats scope
    resp = client.get("/api/v1/stats", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403
    assert resp.get_json()["required_scope"] == "stats:read"


def test_external_api_system_endpoint(client, monkeypatch):
    users_db.set_external_api_settings({"enabled": True})
    token = _new_key(["system:read"])

    class DummyClient:
        def info(self):
            return {"MemTotal": 8 * 1024 * 1024 * 1024, "NCPU": 4, "ContainersRunning": 3, "ServerVersion": "27.0"}

    monkeypatch.setattr(api_routes, "get_docker_client", lambda: DummyClient())
    resp = client.get("/api/v1/system", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["cpu_cores"] >= 1
    assert payload["memory_total_gb"] == 8.0
    assert payload["containers_running"] == 3


def test_external_api_containers_and_stats(client, monkeypatch):
    users_db.set_external_api_settings({"enabled": True})
    token = _new_key(["containers:read", "stats:read"])
    headers = {"Authorization": f"Bearer {token}"}

    rows = [
        {"id": "a" * 64, "name": "web", "status": "running", "image": "nginx", "ports": "80",
         "restarts": 0, "uptime": "1h", "uptime_sec": 3600, "update_available": 0,
         "compose_project": "demo", "compose_service": "web", "cpu": 12.5, "mem": 30.0,
         "_allowed_columns": ["id", "name"]},
        {"id": "b" * 64, "name": "db", "status": "exited", "image": "postgres", "ports": "",
         "restarts": 2, "uptime": "N/A", "uptime_sec": None, "update_available": 1,
         "compose_project": "demo", "compose_service": "db", "cpu": 0.0, "mem": 0.0},
    ]
    monkeypatch.setattr(routes, "collect_metrics_rows", lambda query: [dict(r) for r in rows])

    containers = client.get("/api/v1/containers", headers=headers).get_json()
    assert containers["count"] == 2
    assert containers["running"] == 1 and containers["exited"] == 1
    # Metadata view excludes live stats and internal fields.
    assert "cpu" not in containers["containers"][0]
    assert "_allowed_columns" not in containers["containers"][0]

    one = client.get("/api/v1/containers/web", headers=headers).get_json()
    assert one["name"] == "web"

    stats = client.get("/api/v1/stats", headers=headers).get_json()
    assert stats["count"] == 2
    assert stats["containers"][0]["cpu"] == 12.5
    assert "_allowed_columns" not in stats["containers"][0]

    missing = client.get("/api/v1/containers/ghost/stats", headers=headers)
    assert missing.status_code == 404


def test_external_api_container_actions(client, monkeypatch):
    users_db.set_external_api_settings({"enabled": True})
    token = _new_key(["containers:restart"])

    class DummyContainer:
        name = "web"
        id = "a" * 64

        def restart(self):
            return None

    class DummyContainers:
        def get(self, cid):
            return DummyContainer()

    class DummyClient:
        containers = DummyContainers()

    import container_ops
    monkeypatch.setattr(container_ops, "get_docker_client", lambda: DummyClient())

    resp = client.post("/api/v1/containers/abc/restart", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True

    # Without the start scope the same key is forbidden.
    forbidden = client.post("/api/v1/containers/abc/start", headers={"Authorization": f"Bearer {token}"})
    assert forbidden.status_code == 403

    events = users_db.list_audit_events(limit=20)
    assert any(e["action"] == "container.restart" and e["status"] == "success" for e in events)
