import threading

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.server import StartTcpServer

from app.config import Settings, settings as default_settings

# Simulates a small OT/ICS sensor gateway: coil 0 is a valve (1 = open),
# holding registers 0/1 are a temperature (23.5C, stored as 235) and a
# pressure reading (41.2 psi, stored as 412) - deliberately readable AND
# writable by any client, since Modbus TCP has no native access control.
# This is the exact gap CGIoT-1:2024 2-15-2/2-4-3 flag: a device shipped
# with no authentication on a control-plane protocol.


def _build_context() -> ModbusServerContext:
    # zero_mode=True: client address 0 maps to datastore index 0. Without it
    # pymodbus applies the classic Modbus off-by-one (client address 0 reads
    # datastore index 1) - confirmed live, not assumed, since a first pass
    # without this flag read back [412, 0] instead of [235, 412].
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 16),
        co=ModbusSequentialDataBlock(0, [1] + [0] * 15),
        hr=ModbusSequentialDataBlock(0, [235, 412] + [0] * 14),
        ir=ModbusSequentialDataBlock(0, [0] * 16),
        zero_mode=True,
    )
    return ModbusServerContext(slaves=store, single=True)


def _build_identity(settings: Settings) -> ModbusDeviceIdentification:
    # Real Modicon PLCs answer Modbus function code 0x2B (Read Device
    # Identification) - pymodbus serves it automatically once an identity
    # object is attached to the server, no extra wiring needed. This also
    # closes a previously-documented gap in this project: nmap's
    # modbus-discover NSE script returned "open but no data" against this
    # fixture before an identity object existed at all.
    identity = ModbusDeviceIdentification()
    identity.VendorName = settings.device_vendor
    identity.ProductCode = settings.device_model
    identity.ProductName = settings.device_model
    identity.ModelName = settings.device_model
    identity.MajorMinorRevision = settings.firmware_version
    return identity


def _serve(settings: Settings) -> None:
    context = _build_context()
    identity = _build_identity(settings)
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", settings.modbus_port))


def start_modbus_server(settings: Settings = default_settings) -> None:
    thread = threading.Thread(target=_serve, args=(settings,), daemon=True)
    thread.start()
