import os
import time

import users_db


def test_get_db_path_defaults_to_data_dir(monkeypatch):
    monkeypatch.delenv("USERS_DB_PATH", raising=False)
    monkeypatch.delenv("DATA_DIR", raising=False)
    assert users_db.get_db_path() == os.path.join(users_db.DEFAULT_DATA_DIR, "users.db")


def test_data_dir_env_controls_db_location(tmp_path, monkeypatch):
    monkeypatch.delenv("USERS_DB_PATH", raising=False)
    data_dir = tmp_path / "mydata"
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    assert users_db.get_db_path() == str(data_dir / "users.db")

    users_db.migrate_add_columns_and_role_and_settings()
    users_db.init_db("admin", "adminpass")
    assert (data_dir / "users.db").exists()
    assert users_db.validate_user("admin", "adminpass") is True


def test_users_db_path_takes_precedence_over_data_dir(tmp_path, monkeypatch):
    explicit = tmp_path / "explicit.db"
    monkeypatch.setenv("USERS_DB_PATH", str(explicit))
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "ignored"))

    assert users_db.get_db_path() == str(explicit)


def test_migrate_legacy_db_location_moves_existing_db(tmp_path, monkeypatch):
    legacy = tmp_path / "users.db"
    data_dir = tmp_path / "data"
    monkeypatch.setattr(users_db, "LEGACY_DB_PATH", str(legacy))

    # Create a legacy database (old location) with a user account.
    monkeypatch.setenv("USERS_DB_PATH", str(legacy))
    users_db.migrate_add_columns_and_role_and_settings()
    users_db.init_db("legacyuser", "legacypass")
    assert legacy.exists()

    # Switch to the new directory-based configuration and run the migration.
    monkeypatch.delenv("USERS_DB_PATH", raising=False)
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    users_db.migrate_legacy_db_location()

    target = data_dir / "users.db"
    assert target.exists()
    assert not legacy.exists()
    assert users_db.get_db_path() == str(target)
    assert users_db.validate_user("legacyuser", "legacypass") is True


def test_migrate_legacy_db_location_noop_when_target_exists(tmp_path, monkeypatch):
    legacy = tmp_path / "users.db"
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    target = data_dir / "users.db"
    monkeypatch.setattr(users_db, "LEGACY_DB_PATH", str(legacy))
    monkeypatch.delenv("USERS_DB_PATH", raising=False)
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    # Both a legacy file and a current database exist: the current one must win.
    legacy.write_text("legacy-do-not-use")
    target.write_text("current-db")

    users_db.migrate_legacy_db_location()

    assert target.read_text() == "current-db"
    assert legacy.exists()  # untouched


def test_validate_user_rejects_unknown_user_and_wrong_password(temp_db):
    assert users_db.validate_user("admin", "adminpass") is True
    assert users_db.validate_user("admin", "wrong") is False
    assert users_db.validate_user("ghost", "whatever") is False
    assert users_db.validate_user("admin", None) is False
    assert users_db.validate_user(None, None) is False


def test_validate_user_runs_hash_check_even_for_unknown_user(temp_db, monkeypatch):
    """Guards against user enumeration: a missing username must still trigger a
    password hash comparison so its timing matches an existing user."""
    calls = []
    real_check = users_db.check_password_hash

    def counting_check(stored_hash, password):
        calls.append(stored_hash)
        return real_check(stored_hash, password)

    monkeypatch.setattr(users_db, "check_password_hash", counting_check)

    users_db.validate_user("definitely-not-a-user", "irrelevant")

    assert len(calls) == 1, "check_password_hash must run even when the user is absent"
    assert calls[0] == users_db._DECOY_PASSWORD_HASH


def test_user_crud_and_password_change(temp_db):
    assert users_db.validate_user("admin", "adminpass") is True
    assert users_db.change_password("admin", "new-admin-pass") is True
    assert users_db.validate_user("admin", "new-admin-pass") is True

    created = users_db.create_user_with_columns("alice", "alice-pass", ["cpu", "ram"])
    assert created is True
    assert users_db.user_exists("alice") is True

    users = users_db.list_users_with_columns()
    alice = next(user for user in users if user["username"] == "alice")
    assert alice["columns"] == ["cpu", "ram"]
    assert alice["role"] == "user"

    users_db.update_user_columns("alice", ["cpu", "status"])
    assert users_db.get_user_columns("alice") == ["cpu", "status"]

    users_db.delete_user("alice")
    assert users_db.user_exists("alice") is False


def test_directory_db_path_is_resolved_to_file(tmp_path, monkeypatch):
    db_dir = tmp_path / "users.db"
    db_dir.mkdir()
    monkeypatch.setenv("USERS_DB_PATH", str(db_dir))

    users_db.migrate_add_columns_and_role_and_settings()
    users_db.init_db("admin", "adminpass")

    resolved_path = users_db.get_db_path()
    assert resolved_path == str(db_dir / "users.db")
    assert (db_dir / "users.db").exists()
    assert users_db.validate_user("admin", "adminpass") is True


def test_notification_settings_are_persisted(temp_db):
    settings = {
        "cpu_enabled": False,
        "ram_enabled": True,
        "status_enabled": False,
        "update_enabled": True,
        "cpu_threshold": 65.0,
        "ram_threshold": 75.0,
        "window_seconds": 30,
    }

    users_db.set_notification_settings(settings)
    stored = users_db.get_notification_settings()

    assert stored == settings


def test_audit_events_are_persisted(temp_db):
    event_id = users_db.record_audit_event(
        action="user.create",
        target_type="user",
        status="success",
        actor_username="admin",
        actor_role="admin",
        target_id="alice",
        remote_addr="127.0.0.1",
        details={"columns": ["cpu", "ram"]},
    )

    events = users_db.list_audit_events(limit=5)

    assert event_id > 0
    assert events[0]["action"] == "user.create"
    assert events[0]["details"]["columns"] == ["cpu", "ram"]


def test_update_history_is_persisted_across_reopen(temp_db):
    entry_id = users_db.record_update_history(
        action="update",
        target_type="project",
        target_id="demo",
        target_name="demo",
        previous_version="db=postgres:16",
        new_version="db=postgres:17",
        result="success",
        notes="compose pull/up completed",
        metadata={"rollback_ready": True, "services": [{"service": "db", "previous_image_id": "sha256:old"}]},
        actor_username="admin",
    )

    users_db.migrate_add_columns_and_role_and_settings()
    entry = users_db.get_update_history_entry(entry_id)
    rows = users_db.list_update_history(limit=5)

    assert entry["target_name"] == "demo"
    assert entry["metadata"]["rollback_ready"] is True
    assert rows[0]["id"] == entry_id
    assert rows[0]["previous_version"] == "db=postgres:16"


def test_update_history_auto_cleanup_removes_entries_older_than_retention(temp_db):
    stale_entry_id = users_db.record_update_history(
        action="update",
        target_type="container",
        target_id="stale",
        target_name="stale",
        result="success",
        actor_username="admin",
    )
    fresh_entry_id = users_db.record_update_history(
        action="update",
        target_type="container",
        target_id="fresh",
        target_name="fresh",
        result="success",
        actor_username="admin",
    )

    now_ts = time.time()
    conn = users_db.get_db()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE update_history SET created_at=? WHERE id=?",
        (now_ts - users_db.UPDATE_HISTORY_RETENTION_SECONDS - 60, stale_entry_id),
    )
    cursor.execute(
        "UPDATE update_history SET created_at=? WHERE id=?",
        (now_ts - users_db.UPDATE_HISTORY_RETENTION_SECONDS + 60, fresh_entry_id),
    )
    conn.commit()
    conn.close()

    rows = users_db.list_update_history(limit=10)

    assert [row["id"] for row in rows] == [fresh_entry_id]
    assert users_db.get_update_history_entry(stale_entry_id) is None
    assert users_db.get_update_history_entry(fresh_entry_id)["target_name"] == "fresh"
