"""Each entity writes its state once per coordinator update.

Most breaker, panel and CT entities registered _state_update as a coordinator
listener in __init__ while CoordinatorEntity registered its own, so every
update wrote their state twice. A listener added in __init__ could also fire
before Home Assistant had set the entity up.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from custom_components.ldata import binary_sensor, sensor, switch, update

PANEL = "p1"
BREAKER = {
    "id": "b1", "stable_id": "b1", "name": "Dryer", "panel_id": PANEL, "poles": 2, "position": 1,
    "power": 10.0, "power1": 5.0, "power2": 5.0, "current": 1.0, "current1": 1.0, "current2": 1.0,
    "model": "LB250", "firmware": "2", "hardware": "1", "rating": 30, "serialNumber": "S",
    "state": "ManualON", "remoteState": "RemoteON", "bleRSSI": -60, "consumption": 1.0,
}
CT = {"id": "7", "name": "GRID", "panel_id": PANEL, "channel": "1", "power": 5.0, "current": 1.0, "consumption": 1.0}
PANEL_DATA = {
    "id": PANEL, "name": "Main", "connected": True, "rssi": -50, "firmware": "2",
    "installed_firmware": "2", "available_firmware": None,
    "voltage1": 120.0, "voltage2": 120.0, "frequency1": 60.0, "frequency2": 60.0,
    "overVoltage": False, "underVoltage": False,
}
PANEL_ENTITY = {
    "id": PANEL, "name": "Main", "serialNumber": PANEL, "model": "LWHEM", "hardware": "LDATA",
    "firmware": "2", "poles": 2, "data": PANEL_DATA,
}


class _Coordinator:
    """Just enough of DataUpdateCoordinator: listeners, called in order."""

    def __init__(self) -> None:
        self.user = "u"
        self.last_update_success = True
        self.config_entry = SimpleNamespace(options={}, entry_id="e")
        self._service = MagicMock()
        self._service.panel_has_hw_counters.return_value = False
        self.data = {
            "breakers": {"b1": dict(BREAKER)},
            "cts": {"7": dict(CT)},
            "panels": [dict(PANEL_DATA)],
            PANEL + "totalPower": 10.0,
        }
        self.listeners: list = []

    def async_add_listener(self, callback, context=None):
        self.listeners.append(callback)
        return lambda: self.listeners.remove(callback)

    def async_update_listeners(self) -> None:
        for callback in list(self.listeners):
            callback()


ENTITIES = {
    "breaker power": lambda c: sensor.LDATAOutputSensor(c, dict(BREAKER), sensor.SENSOR_TYPES[sensor.POWER]),
    "panel total": lambda c: sensor.LDATATotalUsageSensor(c, dict(PANEL_ENTITY), sensor.SENSOR_TYPES[sensor.POWER], "both"),
    "panel voltage": lambda c: sensor.LDATAPanelOutputSensor(c, dict(PANEL_ENTITY), sensor.SENSOR_TYPES[sensor.VOLTAGE], "1"),
    "ct power": lambda c: sensor.LDATACTOutputSensor(c, dict(CT), sensor.SENSOR_TYPES[sensor.POWER]),
    "ct lifetime": lambda c: sensor.LDATAEnergyUsageSensor(c, dict(CT), sensor.SENSOR_TYPES[sensor.CONSUMPTION]),
    "breaker lifetime": lambda c: sensor.LDATABreakerEnergyUsageSensor(c, dict(BREAKER), sensor.SENSOR_TYPES[sensor.CONSUMPTION]),
    "breaker daily": lambda c: sensor.LDATADailyUsageSensor(c, dict(BREAKER), False, PANEL),
    "ct daily": lambda c: sensor.LDATACTDailyUsageSensor(c, dict(CT)),
    "operational state": lambda c: sensor.LDATABreakerOperationalStateSensor(c, dict(BREAKER)),
    "ble rssi": lambda c: sensor.LDATABreakerBleRSSISensor(c, dict(BREAKER)),
    "position": lambda c: sensor.LDATABreakerPositionSensor(c, dict(BREAKER)),
    "wifi rssi": lambda c: sensor.LDATAPanelWifiRSSISensor(c, dict(PANEL_ENTITY)),
    "breaker state": lambda c: sensor.LDATABreakerStateSensor(c, dict(BREAKER)),
    "firmware update": lambda c: update.LDATAPanelFirmwareUpdateEntity(c, dict(PANEL_ENTITY)),
    "breaker switch": lambda c: switch.LDATASwitch(c, dict(BREAKER)),
    "blink led": lambda c: switch.LDATABlinkLEDSwitch(c, dict(BREAKER)),
    "breaker status": lambda c: binary_sensor.LDATABinarySensor(c, dict(BREAKER)),
    "cloud connected": lambda c: binary_sensor.LdataCloudConnectedSensor(c, dict(PANEL_ENTITY)),
    "panel over voltage": lambda c: binary_sensor.LDATAPanelOverVoltageSensor(c, dict(PANEL_ENTITY)),
    "breaker over current": lambda c: binary_sensor.LDATABreakerOverCurrentSensor(c, dict(BREAKER)),
}


@pytest.mark.parametrize("make", ENTITIES.values(), ids=ENTITIES.keys())
def test_one_write_per_update(make) -> None:
    coordinator = _Coordinator()
    entity = make(coordinator)
    entity.entity_id = "sensor.x"
    writes: list = []
    entity.async_write_ha_state = lambda: writes.append(1)

    # Nothing is registered before Home Assistant adds the entity...
    assert coordinator.listeners == []
    # ...which registers the one CoordinatorEntity listener.
    coordinator.async_add_listener(entity._handle_coordinator_update)

    coordinator.async_update_listeners()
    assert len(writes) == 1


def test_state_follows_the_data_through_the_one_listener() -> None:
    coordinator = _Coordinator()
    entity = ENTITIES["breaker power"](coordinator)
    entity.async_write_ha_state = lambda: None
    coordinator.async_add_listener(entity._handle_coordinator_update)

    coordinator.data["breakers"]["b1"]["power"] = 42.0
    coordinator.async_update_listeners()

    assert entity.native_value == 42.0
