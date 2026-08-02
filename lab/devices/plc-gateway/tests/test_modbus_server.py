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
