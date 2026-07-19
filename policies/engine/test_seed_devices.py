import psycopg
import pytest

from policies.engine.seed_devices import SEED_DEVICES, seed

TEST_DB_URL = "postgresql://auditor:auditor-lab-pw@localhost:55432/auditor"


@pytest.fixture
def conn():
    connection = psycopg.connect(TEST_DB_URL)
    connection.execute("TRUNCATE device_services, devices RESTART IDENTITY CASCADE")
    connection.commit()
    yield connection
    connection.close()


def test_seeds_all_six_devices(conn):
    assert seed(conn) == 6
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    assert count == 6


def test_second_run_is_a_noop(conn):
    seed(conn)
    assert seed(conn) == 0
    count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    assert count == 6


def test_all_seeded_devices_marked_seeded(conn):
    seed(conn)
    rows = conn.execute("SELECT source FROM devices").fetchall()
    assert all(r[0] == "seeded" for r in rows)


def test_published_ports_match_dev_overlay(conn):
    seed(conn)
    row = conn.execute(
        """
        SELECT port, published_port FROM device_services
        WHERE device_id = 'device-partial'
        """
    ).fetchone()
    assert row == (443, 8082)


def test_telnet_sim_seeded_with_port_23(conn):
    seed(conn)
    row = conn.execute(
        "SELECT service_type, port FROM device_services WHERE device_id = 'telnet-sim'"
    ).fetchone()
    assert row == ("telnet", 23)


def test_device_ids_are_exactly_the_committed_strings():
    # These strings are referenced byte-for-byte by committed Day-2 evidence.
    assert {d["device_id"] for d in SEED_DEVICES} == {
        "device-insecure", "device-partial", "device-hardened",
        "mqtt-broker-insecure", "mqtt-broker-secure", "telnet-sim",
    }
