"""Tests for read-only panel/Decora firmware availability diagnostics."""

from unittest.mock import MagicMock

from custom_components.ldata.ldata_service import _panel_firmware_versions
from custom_components.ldata.update import (
    LDATADecoraFirmwareUpdateEntity,
    LDATAPanelFirmwareUpdateEntity,
)


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


def _decora_coordinator(device: dict) -> MagicMock:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"decora_devices": {device["id"]: device}}
    coordinator.async_add_listener.return_value = MagicMock()
    return coordinator


def _decora_device(*, installed: str = "1.7.3", available: str | None = "1.7.4") -> dict:
    return {
        "id": "test-switch",
        "name": "Test Switch",
        "model": "D215S",
        "manufacturer": "Leviton",
        "mac": "00:07:a6:49:85:d6",
        "version": installed,
        "available_firmware": available,
        "connected": True,
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
    entity = LDATAPanelFirmwareUpdateEntity(_coordinator(panel), _entity_data(panel))

    assert entity.installed_version == "2.1.2"
    assert entity.latest_version == "2.2.1"
    # Deliberately not DIAGNOSTIC — see LDATAPanelFirmwareUpdateEntity's
    # docstring: that category hides entities from HA's Settings-level
    # "Updates available" aggregation, defeating the point of this entity.
    assert entity.entity_category is None


def test_reports_up_to_date_without_distinct_candidate() -> None:
    for available in (None, "", "2.1.2"):
        panel = _panel(available=available)
        entity = LDATAPanelFirmwareUpdateEntity(
            _coordinator(panel), _entity_data(panel)
        )

        assert entity.latest_version == entity.installed_version == "2.1.2"


def test_refreshes_from_latest_panel_data() -> None:
    panel = _panel(available=None)
    coordinator = _coordinator(panel)
    entity = LDATAPanelFirmwareUpdateEntity(coordinator, _entity_data(panel))
    coordinator.data["panels"] = [_panel(available="2.2.1")]
    entity.async_write_ha_state = MagicMock()

    entity._state_update()

    assert entity.latest_version == "2.2.1"
    entity.async_write_ha_state.assert_called_once_with()


def test_decora_reports_newer_downloaded_firmware() -> None:
    device = _decora_device()
    entity = LDATADecoraFirmwareUpdateEntity(_decora_coordinator(device), device)

    assert entity.installed_version == "1.7.3"
    assert entity.latest_version == "1.7.4"
    assert entity.entity_category is None


def test_decora_reports_up_to_date_without_distinct_candidate() -> None:
    for available in (None, "", "1.7.3"):
        device = _decora_device(available=available)
        entity = LDATADecoraFirmwareUpdateEntity(_decora_coordinator(device), device)

        assert entity.latest_version == entity.installed_version == "1.7.3"
