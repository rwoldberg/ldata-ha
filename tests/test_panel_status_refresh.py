"""Regression tests for panel connection state going stale while a panel is offline."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from custom_components.ldata import sensor
from custom_components.ldata.coordinator import LDATAUpdateCoordinator
from custom_components.ldata.ldata_service import LDATAService


def _service(listings: dict[str, list[dict]]) -> LDATAService:
    service = LDATAService("", "", None)
    service.auth_token = "token"
    service.residence_id_list = ["res-1"]
    service.status_data = {
        "breakers": {},
        "cts": {},
        "panels": [
            {"id": "LDATA-1", "name": "Panel", "panel_type": "LDATA", "connected": True},
        ],
    }

    def _get(url, **_kwargs):
        key = "LDATA" if url.endswith("residentialBreakerPanels") else "WHEMS"
        return SimpleNamespace(status_code=200, json=lambda: listings.get(key, []))

    service.session = MagicMock()
    service.session.get.side_effect = _get
    return service


def test_refresh_panel_status_reports_panel_going_offline() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "model": "DAU", "connected": False}]})
    before = service.status_data

    assert service.refresh_panel_status() is True
    assert service.status_data["panels"][0]["connected"] is False
    # Copy-on-write, so the coordinator sees a new object.
    assert service.status_data is not before
    assert before["panels"][0]["connected"] is True


def test_refresh_panel_status_unchanged_returns_false() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "model": "DAU", "status": "READY"}]})
    before = service.status_data

    assert service.refresh_panel_status() is False
    assert service.status_data is before


def test_refresh_panel_status_only_queries_known_panel_types() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True}]})

    service.refresh_panel_status()

    urls = [call.args[0] for call in service.session.get.call_args_list]
    assert urls == ["https://my.leviton.com/api/Residences/res-1/residentialBreakerPanels"]


def test_refresh_panel_status_updates_voltage_with_connection_unchanged() -> None:
    service = _service(
        {"LDATA": [{"id": "LDATA-1", "connected": True, "rmsVoltage": 121.0, "rmsVoltage2": 119.0}]}
    )
    service.status_data["panels"][0].update(voltage1=0.0, voltage2=119.0, voltage=59.5)
    before = service.status_data

    assert service.refresh_panel_status() is True
    panel = service.status_data["panels"][0]
    assert panel["connected"] is True
    assert panel["voltage1"] == 121.0
    assert panel["voltage2"] == 119.0
    assert panel["voltage"] == 120.0
    assert service.status_data is not before
    assert before["panels"][0]["voltage1"] == 0.0


def test_refresh_panel_status_missing_voltage_keeps_cached_values() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True, "rmsVoltage": None}]})
    service.status_data["panels"][0].update(voltage1=120.0, voltage2=121.0, voltage=120.5)
    before = service.status_data

    assert service.refresh_panel_status() is False
    assert service.status_data is before
    panel = service.status_data["panels"][0]
    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (120.0, 121.0, 120.5)


def test_refresh_panel_status_updates_frequency_alarms_rssi_and_firmware() -> None:
    service = _service(
        {
            "LDATA": [
                {
                    "id": "LDATA-1",
                    "connected": True,
                    "frequencyA": 60.1,
                    "frequencyB": 59.9,
                    "overVoltage": True,
                    "underVoltage": False,
                    "overVoltageThreshold": 132,
                    "underVoltageThreshold": 108,
                    "rssi": -61,
                    "packageVer": "1.9.2",
                    "updateAvailability": "UP_TO_DATE",
                }
            ]
        }
    )
    service.status_data["panels"][0].update(
        frequency1=60.0,
        frequency2=60.0,
        frequency=60.0,
        overVoltage=False,
        underVoltage=False,
        overVoltageThreshold=130,
        underVoltageThreshold=108,
        rssi=-70.0,
        installed_firmware="1.9.1",
        firmware="1.9.1",
        available_firmware="1.9.2",
    )
    before = service.status_data

    assert service.refresh_panel_status() is True
    panel = service.status_data["panels"][0]
    assert (panel["frequency1"], panel["frequency2"]) == (60.1, 59.9)
    assert panel["frequency"] == (60.1 + 59.9) / 2
    assert panel["overVoltage"] is True
    assert panel["underVoltage"] is False
    assert panel["overVoltageThreshold"] == 132
    assert panel["underVoltageThreshold"] == 108
    assert panel["rssi"] == -61.0
    assert panel["installed_firmware"] == panel["firmware"] == "1.9.2"
    assert panel["available_firmware"] is None
    assert before["panels"][0]["installed_firmware"] == "1.9.1"


def test_refresh_panel_status_frequency_falls_back_to_cached_breakers() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True}]})
    service.status_data["panels"][0].update(frequency1=0, frequency2=0, frequency=0.0)
    service.status_data["breakers"] = {
        "b1": {"panel_id": "LDATA-1", "frequency1": 60.02, "frequency2": 0.0},
        "b2": {"panel_id": "LDATA-1", "frequency1": 0.0, "frequency2": 59.98},
        "other": {"panel_id": "LDATA-2", "frequency1": 50.0, "frequency2": 50.0},
    }

    assert service.refresh_panel_status() is True
    panel = service.status_data["panels"][0]
    assert (panel["frequency1"], panel["frequency2"]) == (60.02, 59.98)
    assert panel["frequency"] == (60.02 + 59.98) / 2


def test_refresh_panel_status_missing_fields_keep_cached_values() -> None:
    cached = {
        "voltage1": 120.0,
        "voltage2": 121.0,
        "voltage": 120.5,
        "frequency1": 60.0,
        "frequency2": 60.0,
        "frequency": 60.0,
        "overVoltage": True,
        "underVoltage": False,
        "overVoltageThreshold": 132,
        "underVoltageThreshold": 108,
        "rssi": -61.0,
        "installed_firmware": "1.9.2",
        "firmware": "1.9.2",
        "available_firmware": "2.0.0",
    }
    service = _service(
        {
            "LDATA": [
                {
                    "id": "LDATA-1",
                    "connected": True,
                    "rmsVoltage": None,
                    "frequencyA": None,
                    "overVoltage": None,
                    "packageVer": None,
                }
            ]
        }
    )
    service.status_data["panels"][0].update(cached)
    before = service.status_data

    assert service.refresh_panel_status() is False
    assert service.status_data is before
    panel = service.status_data["panels"][0]
    assert {key: panel[key] for key in cached} == cached


def test_refresh_panel_status_single_leg_voltage_uses_cached_other_leg() -> None:
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True, "rmsVoltage": 0.0}]})
    service.status_data["panels"][0].update(voltage1=122.63, voltage2=121.0, voltage=121.815)

    assert service.refresh_panel_status() is True
    panel = service.status_data["panels"][0]
    assert (panel["voltage1"], panel["voltage2"]) == (0.0, 121.0)
    assert panel["voltage"] == 60.5


def test_refresh_panel_status_null_rssi_clears_cached_rssi() -> None:
    # A panel on Ethernet reports rssi: null; that is a value, not a missing key.
    service = _service({"LDATA": [{"id": "LDATA-1", "connected": True, "rssi": None}]})
    service.status_data["panels"][0].update(rssi=-61.0)

    assert service.refresh_panel_status() is True
    assert service.status_data["panels"][0]["rssi"] is None


def test_extract_panel_fields_null_rssi_is_a_value_only_for_ldata() -> None:
    service = LDATAService("", "", None)

    assert service._extract_panel_fields({"rssi": None}, "LDATA") == {"rssi": None}
    assert "rssi" not in service._extract_panel_fields({"rssi": None}, "WHEMS")
    assert "rssi" not in service._extract_panel_fields({}, "LDATA")


def test_parse_panels_missing_voltage_is_unknown_not_zero() -> None:
    service = LDATAService("", "", None)
    panel = service.parse_panels(
        [{"id": "LDATA-1", "name": "Panel", "ModuleType": "LDATA", "rmsVoltage2": 120.0, "updateVersion": None}]
    )["panels"][0]

    assert panel["voltage1"] is None
    assert panel["voltage2"] == 120.0
    assert panel["voltage"] is None


def test_parse_panels_reads_panel_fields() -> None:
    service = LDATAService("", "", None)
    panel = service.parse_panels(
        [
            {
                "id": "LDATA-1",
                "ModuleType": "LDATA",
                "rmsVoltage": 121.0,
                "rmsVoltage2": 119.0,
                "overVoltageThreshold": 132,
                "rssi": "-60",
                "packageVer": "1.9.2",
                "updateAvailability": "UPDATE_AVAILABLE",
                "updateVersion": "2.0.0",
                "residentialBreakers": [
                    {"id": "b1", "model": "NONE-1", "position": 1, "poles": 1, "lineFrequency": 60.02},
                    {"id": "b2", "model": "NONE-1", "position": 3, "poles": 1, "lineFrequency": 59.98},
                ],
            }
        ]
    )["panels"][0]

    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (121.0, 119.0, 120.0)
    assert (panel["frequency1"], panel["frequency2"]) == (60.02, 59.98)
    assert panel["overVoltage"] is False
    assert panel["overVoltageThreshold"] == 132
    assert panel["underVoltageThreshold"] is None
    assert panel["rssi"] == -60.0
    assert panel["installed_firmware"] == panel["firmware"] == "1.9.2"
    assert panel["available_firmware"] == "2.0.0"


def test_iotwhem_websocket_applies_zero_voltage() -> None:
    service = LDATAService("", "", None)
    service.status_data = {
        "breakers": {},
        "cts": {},
        "panels": [
            {"id": "P1", "panel_type": "WHEMS", "voltage1": 120.0, "voltage2": 120.0, "voltage": 120.0}
        ],
    }

    assert service._update_from_websocket(
        {"modelName": "IotWhem", "data": {"id": "P1", "rmsVoltage": 0.0, "rmsVoltageA": 118.0, "rmsVoltage2": 0}}
    )
    panel = service.status_data["panels"][0]
    assert (panel["voltage1"], panel["voltage2"], panel["voltage"]) == (0.0, 0.0, 0.0)


def _coordinator() -> LDATAUpdateCoordinator:
    coordinator = LDATAUpdateCoordinator.__new__(LDATAUpdateCoordinator)
    coordinator._hass = SimpleNamespace(loop=MagicMock())
    coordinator._service = SimpleNamespace(version="test", _shutdown_requested=False)
    coordinator.config_entry = SimpleNamespace(options={})
    coordinator._debounce_timer = None
    coordinator._websocket_connected = False
    coordinator._websocket_ever_connected = False
    return coordinator


def test_reconnect_rearms_update_timer_cancelled_by_disconnect() -> None:
    coordinator = _coordinator()

    coordinator._handle_connection_change(True)
    first_timer = coordinator._debounce_timer
    assert first_timer is not None

    coordinator._handle_connection_change(False)
    first_timer.cancel.assert_called_once()
    assert coordinator._debounce_timer is None

    coordinator._handle_connection_change(True)
    assert coordinator._debounce_timer is not None
    assert coordinator._hass.loop.call_later.call_count == 2


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
