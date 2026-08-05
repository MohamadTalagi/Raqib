"""Regression tests for id_generation.py - the shared, concurrency-safe
sequential-id generator (see the module's own docstring for why this exists:
every one of the 7 call sites that used to run its own unguarded
COUNT(*)+1 could collide under concurrency)."""

import threading

import pytest

from db import get_connection
from id_generation import next_sequential_id

# evidence.device_id has no foreign key to devices - a scratch id here never
# needs a real registered device to exist.
_INSERT_EVIDENCE = """
    INSERT INTO evidence (
        evidence_id, device_id, test_id, tool, tool_version, command,
        timestamp, finding, observations, raw_output_path, confidence, sha256
    ) VALUES (%s, %s, %s, %s, %s, %s, now(), %s, %s, %s, %s, %s)
"""


def test_next_sequential_id_returns_the_next_number_in_sequence(client):
    conn = get_connection()
    try:
        first = next_sequential_id(conn, "TESTSEQ", "evidence", "evidence_id")
        conn.execute(
            _INSERT_EVIDENCE,
            (first, "scratch-device", "TEST-X", "curl", "1.0", "curl x", "f1", "{}", "path", "high", "0" * 64),
        )
        second = next_sequential_id(conn, "TESTSEQ", "evidence", "evidence_id")
        conn.commit()
    finally:
        conn.close()

    assert first != second
    assert first.endswith("-0001")
    assert second.endswith("-0002")


def test_next_sequential_id_is_safe_under_concurrent_callers(client):
    """Reproduces the exact race every call site is exposed to: read a
    count, then (after some real work) insert a row keyed on it. Without
    id_generation's advisory lock, two threads racing this pattern can read
    the same count and collide on INSERT with a UniqueViolation. With the
    lock, the second caller simply waits for the first to commit and sees
    an updated count."""
    errors: list[Exception] = []
    generated_ids: list[str] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        conn = get_connection()
        try:
            new_id = next_sequential_id(conn, "TESTRACE", "evidence", "evidence_id")
            conn.execute(
                _INSERT_EVIDENCE,
                (new_id, "scratch-device", "TEST-X", "curl", "1.0", "curl x", f"f{i}", "{}", "path", "high", "0" * 64),
            )
            conn.commit()
            with lock:
                generated_ids.append(new_id)
        except Exception as exc:  # noqa: BLE001 - captured for the assertion below, not swallowed
            with lock:
                errors.append(exc)
        finally:
            conn.close()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent id generation raised: {errors}"
    assert len(generated_ids) == 8
    assert len(set(generated_ids)) == 8, f"duplicate ids generated under concurrency: {generated_ids}"


def test_lock_id_sequence_serializes_two_connections_on_the_same_table(client):
    """Direct proof of the serialization itself: a second connection's
    lock acquisition on the same table key must block until the first
    connection commits (releasing its transaction-scoped lock), not
    proceed immediately in parallel."""
    from id_generation import lock_id_sequence

    order: list[str] = []
    holder_ready = threading.Event()
    release_holder = threading.Event()

    def holder() -> None:
        conn = get_connection()
        try:
            lock_id_sequence(conn, "TESTLOCK")
            order.append("holder-acquired")
            holder_ready.set()
            release_holder.wait(timeout=5)
            conn.commit()  # releases the advisory lock
        finally:
            conn.close()

    def waiter() -> None:
        holder_ready.wait(timeout=5)
        conn = get_connection()
        try:
            lock_id_sequence(conn, "TESTLOCK")
            order.append("waiter-acquired")
            conn.commit()
        finally:
            conn.close()

    t_holder = threading.Thread(target=holder)
    t_waiter = threading.Thread(target=waiter)
    t_holder.start()
    t_waiter.start()

    holder_ready.wait(timeout=5)
    # The waiter should still be blocked at this point - give it a moment
    # to prove it hasn't raced ahead before releasing the holder.
    import time

    time.sleep(0.2)
    assert order == ["holder-acquired"], "waiter acquired the lock before the holder released it"

    release_holder.set()
    t_holder.join(timeout=5)
    t_waiter.join(timeout=5)

    assert order == ["holder-acquired", "waiter-acquired"]


@pytest.fixture
def client(postgres_url, monkeypatch):
    """Not an HTTP client here - these tests talk to the DB directly via
    db.get_connection(). Only sets DATABASE_URL (the same
    postgres_url + monkeypatch pattern every other test file in this
    package uses) so get_connection() resolves to the real ephemeral test
    Postgres conftest.py spins up."""
    monkeypatch.setenv("DATABASE_URL", postgres_url)
