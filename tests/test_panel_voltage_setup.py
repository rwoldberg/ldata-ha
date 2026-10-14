"""Tests for panel voltage when the panel listing omits it at setup."""

from types import SimpleNamespace

import pytest

from custom_components.ldata import sensor
from custom_components.ldata.ldata_service import LDATAService


def _parse(panel: dict) -> dict:
    return LDATAService("", "", None).parse_panels(
        [{"id": "LDATA-1", "name": "Panel", "ModuleType": "LDATA", **panel}]
    )["panels"][0]


@pytest.mark.parametrize(
    "legs",
    [{"rmsVoltage2": 120.0}, {"rmsVoltage": None, "rmsVoltage2": 120.0}],
)
def test_parse_panels_missing_voltage_is_unknown_not_zero(legs) -> None:
    panel = _parse(legs)

    assert panel["voltage1"] is None
    assert panel["voltage2"] == 120.0
    assert panel["voltage"] is None


def test_parse_panels_keeps_real_zero_voltage() -> None:
    panel = _parse({"rmsVoltage": 0.0, "rmsVoltage2": 120.0})

    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (0.0, 120.0, 60.0)


def test_panel_voltage_sensor_reports_unknown_for_missing_voltage() -> None:
    panel = {
        "id": "LDATA-1",
        "serialNumber": "LDATA-1",
        "name": "Panel",
        "model": "DAU",
        "firmware": "1.9.2",
        "voltage1": None,
    }
    coordinator = SimpleNamespace(
        data={"panels": [panel]},
        last_update_success=True,
        user="test-user",
        async_add_listener=lambda *_args, **_kwargs: (lambda: None),
    )
    entity_data = {**panel, "hardware": "LDATA", "poles": 2, "data": panel}

    entity = sensor.LDATAPanelOutputSensor(
        coordinator, entity_data, sensor.SENSOR_TYPES[sensor.VOLTAGE], which_leg="1"
    )

    assert entity.native_value is None
