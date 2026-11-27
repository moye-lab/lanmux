"""Threading regression tests for the 2026-11-24 N1 login outage.

Root cause: ``get_db`` was a yield dependency holding
``app.state.db_lock`` (a threading RLock) across the request.
FastAPI runs a sync dependency's setup and teardown in worker
threads that may differ, and releasing an RLock from another thread
raises ``RuntimeError: cannot release un-acquired lock`` — while the
lock stays acquired forever. The first unlucky concurrent burst
(the login + 5 parallel loadAll requests) poisoned the lock and
every later request hung, /health included. The fix moves locking
into :class:`app.database.Database` (per operation, same thread),
and ``get_db`` is a plain function again. These tests pin that.
"""

import inspect
import threading

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.database import Database
from app.deps import get_db
from app.main import create_app

ADMIN_PASSWORD = "threading-test-admin"

SS_URI = "ss://YWVzLTEyOC1nY206ZmFrZS1wYXNzd29yZA@example.com:8388#NodeOne"

THREADS = 8
OPS_PER_THREAD = 20
JOIN_TIMEOUT = 30


def _run_threads(workers):
    """Start daemon threads, join with a timeout, fail on a hang.

    A deadlock must fail the test, not hang the whole suite.
    """
    threads = [threading.Thread(target=w, daemon=True) for w in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=JOIN_TIMEOUT)
    hung = [t for t in threads if t.is_alive()]
    assert not hung, f"{len(hung)} thread(s) still running after {JOIN_TIMEOUT}s"


def test_get_db_is_not_a_generator():
    """get_db must not hold a lock across a yield (see module docstring)."""
    assert not inspect.isgeneratorfunction(get_db)


def test_concurrent_database_access(tmp_path):
    """Mixed reads/writes from many threads must not deadlock or corrupt."""
    db = Database(tmp_path / "lanmux.db")
    errors: list[BaseException] = []

    def worker(index: int):
        try:
            for step in range(OPS_PER_THREAD):
                db.set_setting(f"worker-{index}", str(step))
                assert db.get_setting(f"worker-{index}") == str(step)
                db.list_nodes()
            for _ in range(5):
                db.add_node(
                    f"node-{index}", SS_URI, {"type": "ss"}, enabled=True
                )
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            errors.append(exc)

    _run_threads([lambda i=i: worker(i) for i in range(THREADS)])
    assert not errors, f"worker errors: {errors!r}"
    assert len(db.list_nodes()) == THREADS * 5
    for index in range(THREADS):
        assert db.get_setting(f"worker-{index}") == str(OPS_PER_THREAD - 1)
    db.close()


def test_lock_released_when_method_raises(tmp_path):
    """A method that raises must not leave the lock held."""
    db = Database(tmp_path / "lanmux.db")
    db.add_node("n1", SS_URI, {"type": "ss"})
    with pytest.raises(ValueError, match="unknown node field"):
        db.update_node(1, bogus_field="x")
    # If the lock leaked, this call would block forever.
    assert db.get_node(1)["name"] == "n1"
    db.close()


@pytest.fixture
def app(tmp_path):
    app = create_app(
        db_path=tmp_path / "lanmux.db",
        config_path=tmp_path / "mihomo" / "config.yaml",
    )
    app.state.db.set_setting(
        "admin_password_hash", hash_password(ADMIN_PASSWORD)
    )
    return app


def test_concurrent_api_requests(app):
    """The N1 outage, replayed: concurrent panel requests must all answer.

    One shared TestClient (its portal serializes calls onto the app's
    event loop); each worker thread fires real HTTP requests through
    the thread pool, the way the login burst did.
    """
    with TestClient(app) as client:
        login = client.post(
            "/api/auth/login", json={"password": ADMIN_PASSWORD}
        )
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['token']}"}
        errors: list[BaseException] = []
        statuses: list[int] = []

        def worker():
            try:
                for _ in range(4):
                    response = client.get("/api/nodes", headers=headers)
                    statuses.append(response.status_code)
                    response = client.get(
                        "/api/rules/bindings", headers=headers
                    )
                    statuses.append(response.status_code)
            except BaseException as exc:  # noqa: BLE001 - re-raised below
                errors.append(exc)

        _run_threads([worker] * THREADS)
        assert not errors, f"worker errors: {errors!r}"
        assert len(statuses) == THREADS * 8
        assert all(status == 200 for status in statuses)
