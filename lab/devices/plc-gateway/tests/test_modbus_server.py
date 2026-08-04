import time

from pymodbus.client import ModbusTcpClient

from app.config import Settings
from app.modbus_server import start_modbus_server


def test_modbus_server_serves_unauthenticated_holding_registers_and_coils():
    settings = Settings(modbus_port=15020)
    start_modbus_server(settings)
    time.sleep(0.3)  # let the TCP server bind before connecting

    client = ModbusTcpClient("127.0.0.1", port=15020)
    try:
        assert client.connect()

        # No credentials of any kind offered - Modbus TCP has none - and the
        # server still answers, which is the exact insecure-by-default
        # posture this fixture models.
        registers = client.read_holding_registers(0, count=2)
        assert not registers.isError()
        assert registers.registers == [235, 412]

        coils = client.read_coils(0, count=1)
        assert not coils.isError()
        assert coils.bits[0] is True
    finally:
        client.close()


def test_modbus_server_answers_read_device_identification_unauthenticated():
    # Real Modicon PLCs answer Modbus function code 0x2B (Read Device
    # Identification) with no authentication - same insecure-by-default
    # posture as the register/coil access above, now also giving
    # modbus-discover-class tools real vendor/model data instead of "open
    # but no data".
    settings = Settings(
        modbus_port=15021,
        device_vendor="Schneider Electric",
        device_model="Modicon M221",
        firmware_version="SV3.8.1",
    )
    start_modbus_server(settings)
    time.sleep(0.3)

    client = ModbusTcpClient("127.0.0.1", port=15021)
    try:
        assert client.connect()
        resp = client.read_device_information()
        assert not resp.isError()
        assert resp.information[0] == b"Schneider Electric"
        assert resp.information[1] == b"Modicon M221"
        assert resp.information[2] == b"SV3.8.1"
    finally:
        client.close()
