"""Tests for read-only panel firmware availability diagnostics."""

from unittest.mock import MagicMock

from homeassistant.helpers.entity import EntityCategory

from custom_components.ldata.ldata_service import _panel_firmware_versions
from custom_components.ldata.sensor import LDATAPanelFirmwareUpdateSensor


def _coordinator(panel: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"panels": [panel]}
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def _panel(*, installed: str = "2.1.2", available: str | None = "2.2.1") -> dict:
    return {
        "id": "test-panel",
        "firmware": installed,
        "installed_firmware": installed,
        "available_firmware": available,
    }


def _entity_data(panel: dict) -> dict:
    return {
        "id": "test-panel",
        "name": "Test Panel",
        "model": "LWHEM",
        "serialNumber": "test-panel",
        "firmware": panel["firmware"],
        "data": panel,
    }


def test_extracts_whem_and_ldata_firmware_metadata() -> None:
    assert _panel_firmware_versions({"version": "2.1.2", "downloaded": "2.2.1"}) == (
        "2.1.2",
        "2.2.1",
    )
    assert _panel_firmware_versions(
        {
            "packageVer": "1.1.18",
            "updateAvailability": "UPDATE_AVAILABLE",
            "updateVersion": "1.1.19",
        }
    ) == ("1.1.18", "1.1.19")
    assert _panel_firmware_versions(
        {
            "updateAvailability": "UPDATE_AVAILABLE",
            "updateVersion": "1.1.19",
        }
    ) == ("unknown", "1.1.19")
    assert _panel_firmware_versions(
        {
            "packageVer": "1.1.18",
            "updateAvailability": "UP_TO_DATE",
            "updateVersion": "1.1.18",
        }
    ) == ("1.1.18", None)


def test_reports_newer_downloaded_firmware() -> None:
    panel = _panel()
    entity = LDATAPanelFirmwareUpdateSensor(_coordinator(panel), _entity_data(panel))

    assert entity.native_value == "2.2.1"
    assert entity.extra_state_attributes["installed_version"] == "2.1.2"
    assert entity.extra_state_attributes["update_available"] is True
    assert entity.entity_category is EntityCategory.DIAGNOSTIC


def test_reports_up_to_date_without_distinct_candidate() -> None:
    for available in (None, "", "2.1.2"):
        panel = _panel(available=available)
        entity = LDATAPanelFirmwareUpdateSensor(
            _coordinator(panel), _entity_data(panel)
        )

        assert entity.native_value == "Up to date"
        assert entity.extra_state_attributes["update_available"] is False


def test_refreshes_from_latest_panel_data() -> None:
    panel = _panel(available=None)
    coordinator = _coordinator(panel)
    entity = LDATAPanelFirmwareUpdateSensor(coordinator, _entity_data(panel))
    coordinator.data["panels"] = [_panel(available="2.2.1")]
    entity.async_write_ha_state = MagicMock()

    entity._state_update()

    assert entity.native_value == "2.2.1"
    entity.async_write_ha_state.assert_called_once_with()
