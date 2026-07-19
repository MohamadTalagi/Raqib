import psycopg
import pytest

from policies.engine.seed_devices import SEED_DEVICES, seed

TEST_DB_URL = "postgresql://auditor:auditor-lab-pw@localhost:55432/auditor"


@pytest.fixture(scope="session")
def db_available():
    """Probe database availability once per test session.

    Avoids paying a 2-second connect_timeout for every test. If the database
    is unavailable, skip the entire session with a helpful message.
    """
    try:
        connection = psycopg.connect(TEST_DB_URL, connect_timeout=2)
        connection.close()
    except psycopg.OperationalError as e:
        pytest.skip(
            f"Seed tests require a Postgres database on port 55432: {e}\n"
            "Start it with:\n"
            "  docker run -d --rm --name auditor-seed-test-db \\\n"
            "    -e POSTGRES_DB=auditor -e POSTGRES_USER=auditor "
            "-e POSTGRES_PASSWORD=auditor-lab-pw \\\n"
            "    -p 55432:5432 postgres:16-alpine\n"
            "Then apply migrations:\n"
            "  docker exec -i auditor-seed-test-db psql -U auditor -d auditor < "
            "lab/auditor/db/migrations/001-devices.sql"
        )


@pytest.fixture
def conn(db_available):
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


@pytest.mark.parametrize(
    "device_id,tier,service_type,port,published_port",
    [
        ("device-insecure", "insecure", "http", 80, 8081),
        ("device-partial", "partial", "https", 443, 8082),
        ("device-hardened", "hardened", "https", 443, 8083),
        ("mqtt-broker-insecure", "insecure", "mqtt", 1883, 18830),
        ("mqtt-broker-secure", "hardened", "mqtts", 8883, None),
        ("telnet-sim", "insecure", "telnet", 23, None),
    ],
)
def test_seed_data_is_complete_and_correct(
    conn, device_id, tier, service_type, port, published_port
):
    """Verify all six seeded devices have correct (tier, service_type, port, published_port).

    This test ensures the seed data is the single source of truth for device identity
    before the frontend modules are deleted in a later task. NULL published_port values
    must genuinely come back as None from the database round-trip.
    """
    seed(conn)

    device_row = conn.execute(
        "SELECT tier FROM devices WHERE device_id = %s",
        (device_id,),
    ).fetchone()
    assert device_row is not None
    assert device_row[0] == tier

    service_row = conn.execute(
        """
        SELECT service_type, port, published_port FROM device_services
        WHERE device_id = %s AND service_type = %s
        """,
        (device_id, service_type),
    ).fetchone()
    assert service_row is not None
    assert service_row == (service_type, port, published_port)
