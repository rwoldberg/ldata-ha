"""Tests for panel entities going unavailable while their panel is offline."""

from types import SimpleNamespace

import pytest

from custom_components.ldata import binary_sensor, sensor, switch
from custom_components.ldata.ldata_base_entity import (
    PanelOnlineMixin,
    is_panel_offline,
)

PANEL_ID = "LDATA-1"


def _coordinator(connected=True):
    panel = {
        "id": PANEL_ID,
        "serialNumber": PANEL_ID,
        "name": "Panel",
        "model": "DAU",
        "firmware": "2.0.0",
        "connected": connected,
        "voltage1": 121.5,
        "frequency1": 60.0,
        "rssi": -60,
    }
    breaker = {
        "id": "B1",
        "panel_id": PANEL_ID,
        "name": "Kitchen",
        "model": "LB120",
        "firmware": "1.0",
        "poles": 1,
        "position": 1,
        "power": 92.5,
        "current": 0.8,
        "bleRSSI": -70,
        "state": "ManualON",
        "remoteState": "RemoteON",
        "operationalState": "Normal",
        "blinkLED": False,
        "overCurrent": False,
        "overVoltage": False,
        "underVoltage": False,
    }
    ct = {
        "id": "1",
        "panel_id": PANEL_ID,
        "name": "Grid",
        "channel": "1",
        "power": 500.0,
        "current": 4.1,
    }
    return SimpleNamespace(
        data={
            "panels": [panel],
            "breakers": {"B1": breaker},
            "cts": {"1": ct},
            PANEL_ID + "totalPower": 92.5,
        },
        last_update_success=True,
        user="test-user",
        async_add_listener=lambda *_args, **_kwargs: (lambda: None),
    )


def _panel_entity_data(coordinator):
    panel = coordinator.data["panels"][0]
    return {**panel, "hardware": "LDATA", "poles": 2, "data": panel}


def _live_entities(coordinator):
    breaker = coordinator.data["breakers"]["B1"]
    ct = coordinator.data["cts"]["1"]
    panel_data = _panel_entity_data(coordinator)
    types = sensor.SENSOR_TYPES
    return {
        "breaker power": sensor.LDATAOutputSensor(coordinator, breaker, types[sensor.POWER]),
        "breaker current": sensor.LDATAOutputSensor(coordinator, breaker, types[sensor.CURRENT]),
        "breaker BLE RSSI": sensor.LDATABreakerBleRSSISensor(coordinator, breaker),
        "panel watts": sensor.LDATATotalUsageSensor(
            coordinator, panel_data, types[sensor.POWER], which_leg="both"
        ),
        "panel amps leg 1": sensor.LDATATotalUsageSensor(
            coordinator, {**panel_data, "poles": 1, "position": 1}, types[sensor.CURRENT], which_leg="1"
        ),
        "panel voltage leg 1": sensor.LDATAPanelOutputSensor(
            coordinator, panel_data, types[sensor.VOLTAGE], which_leg="1"
        ),
        "panel frequency leg 1": sensor.LDATAPanelOutputSensor(
            coordinator, panel_data, types[sensor.FREQUENCY], which_leg="1"
        ),
        "panel Wi-Fi RSSI": sensor.LDATAPanelWifiRSSISensor(coordinator, panel_data),
        "CT power": sensor.LDATACTOutputSensor(coordinator, ct, types[sensor.POWER]),
        "CT current": sensor.LDATACTOutputSensor(coordinator, ct, types[sensor.CURRENT]),
    }


def _state_entities(coordinator):
    breaker = coordinator.data["breakers"]["B1"]
    panel_data = _panel_entity_data(coordinator)
    return {
        "breaker status": binary_sensor.LDATABinarySensor(coordinator, breaker),
        "breaker over current": binary_sensor.LDATABreakerOverCurrentSensor(coordinator, breaker),
        "breaker over voltage": binary_sensor.LDATABreakerOverVoltageSensor(coordinator, breaker),
        "breaker under voltage": binary_sensor.LDATABreakerUnderVoltageSensor(coordinator, breaker),
        "panel over voltage": binary_sensor.LDATAPanelOverVoltageSensor(coordinator, panel_data),
        "panel under voltage": binary_sensor.LDATAPanelUnderVoltageSensor(coordinator, panel_data),
        "breaker switch": switch.LDATASwitch(coordinator, breaker),
        "blink LED switch": switch.LDATABlinkLEDSwitch(coordinator, breaker),
        "breaker state": sensor.LDATABreakerStateSensor(coordinator, breaker),
        "breaker operational state": sensor.LDATABreakerOperationalStateSensor(coordinator, breaker),
    }


def _entities(coordinator):
    return {**_live_entities(coordinator), **_state_entities(coordinator)}


ENTITY_NAMES = list(_entities(_coordinator()))


def _set_connected(coordinator, connected):
    panel = coordinator.data["panels"][0]
    coordinator.data["panels"] = [{**panel, "connected": connected}]


@pytest.mark.parametrize("name", ENTITY_NAMES)
def test_entity_unavailable_while_panel_offline(name) -> None:
    coordinator = _coordinator()
    entity = _entities(coordinator)[name]
    assert entity.available is True

    _set_connected(coordinator, False)
    assert entity.available is False

    _set_connected(coordinator, True)
    assert entity.available is True


@pytest.mark.parametrize("name", ENTITY_NAMES)
def test_entity_unavailable_when_coordinator_update_fails(name) -> None:
    coordinator = _coordinator()
    entity = _entities(coordinator)[name]

    coordinator.last_update_success = False

    assert entity.available is False


def test_panel_without_connected_flag_or_missing_is_not_offline() -> None:
    coordinator = _coordinator()
    panel = coordinator.data["panels"][0]
    entity = _live_entities(coordinator)["breaker power"]

    coordinator.data["panels"] = [{k: v for k, v in panel.items() if k != "connected"}]
    assert is_panel_offline(coordinator, PANEL_ID) is False
    assert entity.available is True

    coordinator.data["panels"] = []
    assert is_panel_offline(coordinator, PANEL_ID) is False
    assert entity.available is True


@pytest.mark.parametrize("name", ENTITY_NAMES)
def test_offline_flag_only_affects_entities_of_that_panel(name) -> None:
    coordinator = _coordinator()
    entity = _entities(coordinator)[name]

    coordinator.data["panels"].append({"id": "LDATA-2", "connected": False})

    assert entity.available is True


@pytest.mark.parametrize(
    ("cls", "data_key", "key"),
    [
        (sensor.LDATABreakerEnergyUsageSensor, "breakers", "B1"),
        (sensor.LDATAEnergyUsageSensor, "cts", "1"),
    ],
)
def test_energy_counter_keeps_value_while_panel_offline(cls, data_key, key) -> None:
    coordinator = _coordinator()
    entity = cls(
        coordinator, coordinator.data[data_key][key], sensor.SENSOR_TYPES[sensor.CONSUMPTION]
    )
    entity._state = 1234.5

    _set_connected(coordinator, False)

    assert entity.available is True
    assert entity.native_value == 1234.5


@pytest.mark.parametrize(
    "cls",
    [
        sensor.LDATABreakerEnergyUsageSensor,
        sensor.LDATAEnergyUsageSensor,
        sensor.LDATADailyUsageSensor,
        sensor.LDATACTDailyUsageSensor,
    ],
)
def test_energy_sensors_do_not_follow_panel_connection(cls) -> None:
    assert not issubclass(cls, PanelOnlineMixin)
