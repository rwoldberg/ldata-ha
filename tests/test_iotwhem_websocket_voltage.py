"""Tests for WHEMS panel voltage from IotWhem WebSocket notifications."""

import pytest

from custom_components.ldata.ldata_service import LDATAService


def _service() -> LDATAService:
    service = LDATAService("", "", None)
    service.status_data = {
        "breakers": {},
        "cts": {},
        "panels": [
            {"id": "P1", "panel_type": "WHEMS", "voltage1": 120.0, "voltage2": 120.0, "voltage": 120.0}
        ],
    }
    return service


@pytest.mark.parametrize(
    "data",
    [
        {"rmsVoltage": 0.0, "rmsVoltage2": 0},
        # rmsVoltage takes precedence: a real 0 V must not fall through to rmsVoltageA.
        {"rmsVoltage": 0.0, "rmsVoltageA": 118.0, "rmsVoltage2": 0, "rmsVoltageB": 117.0},
    ],
)
def test_iotwhem_websocket_applies_zero_voltage(data) -> None:
    service = _service()

    assert service._update_from_websocket({"modelName": "IotWhem", "data": {"id": "P1", **data}})
    panel = service.status_data["panels"][0]
    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (0.0, 0.0, 0.0)


def test_iotwhem_websocket_falls_back_to_leg_letter_keys() -> None:
    service = _service()

    assert service._update_from_websocket(
        {"modelName": "IotWhem", "data": {"id": "P1", "rmsVoltage": None, "rmsVoltageA": 118.0, "rmsVoltageB": 0.0}}
    )
    panel = service.status_data["panels"][0]
    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (118.0, 0.0, 59.0)
