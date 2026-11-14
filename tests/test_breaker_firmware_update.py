"""Breaker firmware updates, found the way the My Leviton app finds them.

The LWHEM records here are from the sample data Leviton ships in its app
(residentialBreakers.json): an AFCI breaker whose panel has downloaded a newer
SiLabs build while updateAvailability still says UP_TO_DATE.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from homeassistant.components.update import UpdateEntityFeature

from custom_components.ldata import update
from custom_components.ldata.ldata_service import LDATAService, _breaker_firmware_versions
from custom_components.ldata.update import LDATABreakerFirmwareUpdateEntity


def _whem_breaker(**overrides) -> dict:
    breaker = {
        "id": "4C4557E12770",
        "name": "Bedroom",
        "model": "LB115-AST",
        "currentRating": 15,
        "position": 26,
        "poles": 1,
        "serialNumber": "F1D146",
        "hwVersion": "",
        "firmwareVersionMeter": "FWB7108000100",
        "firmwareVersionBLE": "FWC0778000102",
        "downloadedBLE": "",
        "firmwareVersionSiLabs": "FWC2422000001",
        "downloadedSiLabs": "FWC2422000100",
        "firmwareVersionTreeTable": "",
        "downloadedTreeTable": "",
        "updateAvailability": "UP_TO_DATE",
        "updateVersion": "",
        "canRemoteOn": True,
        "currentState": "ManualON",
        "remoteState": "RemoteON",
    }
    breaker.update(overrides)
    return breaker


def _ldata_breaker(**overrides) -> dict:
    breaker = {
        "id": "1A2B3C4D5E6F",
        "name": "Kitchen Lights",
        "model": "LB115-AS",
        "currentRating": 15,
        "position": 1,
        "poles": 1,
        "serialNumber": "S1",
        "hwVersion": "AFCI-01",
        "firmwareVersionMeter": "FWB3760000100",
        "firmwareVersionSiLabs": "FWB4073000100",
        "updateAvailability": "UPDATE_AVAILABLE",
        "updateVersion": "FWB4073000101",
        "canRemoteOn": True,
        "currentState": "ManualON",
        "remoteState": "RemoteON",
    }
    breaker.update(overrides)
    return breaker


def _parse(panel_type: str, breaker: dict) -> dict:
    panel = {"id": "panel-1", "name": "Panel", "ModuleType": panel_type, "residentialBreakers": [breaker]}
    return LDATAService("", "", None).parse_panels([panel])["breakers"][breaker["id"]]


def test_lwhem_breaker_has_the_newer_downloaded_build() -> None:
    parsed = _parse("WHEMS", _whem_breaker())

    assert parsed["installed_firmware"] == "FWC2422000001"
    assert parsed["available_firmware"] == "FWC2422000100"
    assert parsed["firmware_update_summary"] == "SiLabs FWC2422000001 → FWC2422000100"


def test_lwhem_breaker_without_a_newer_build_is_up_to_date() -> None:
    for downloaded in ("", None, "FWC2422000001", "FWC2422000000"):
        parsed = _parse("WHEMS", _whem_breaker(downloadedSiLabs=downloaded))

        assert parsed["available_firmware"] is None
        # Nothing to compare against: the breaker's own firmware, as on its device page.
        assert parsed["installed_firmware"] == "FWB7108000100"


def test_lwhem_breaker_ignores_update_availability() -> None:
    # On an LWHEM the app never reads it for breakers.
    parsed = _parse(
        "WHEMS",
        _whem_breaker(downloadedSiLabs="", updateAvailability="UPDATE_AVAILABLE", updateVersion="FWC2422000100"),
    )

    assert parsed["available_firmware"] is None


def test_lwhem_breaker_lists_every_image_that_changes() -> None:
    parsed = _parse("WHEMS", _whem_breaker(downloadedBLE="FWC0778000105"))

    # BLE comes first in the app's order, so it is the version shown.
    assert parsed["installed_firmware"] == "FWC0778000102"
    assert parsed["available_firmware"] == "FWC0778000105"
    assert parsed["firmware_update_summary"] == (
        "BLE FWC0778000102 → FWC0778000105, SiLabs FWC2422000001 → FWC2422000100"
    )


def test_ldata_breaker_follows_update_availability() -> None:
    parsed = _parse("LDATA", _ldata_breaker())

    assert parsed["installed_firmware"] == "FWB4073000100"
    assert parsed["available_firmware"] == "FWB4073000101"
    assert parsed["firmware_update_summary"] is None


def test_ldata_breaker_up_to_date() -> None:
    for availability in ("UP_TO_DATE", "CHECKING", "", None):
        parsed = _parse("LDATA", _ldata_breaker(updateAvailability=availability))

        assert parsed["available_firmware"] is None
        assert parsed["installed_firmware"] == "FWB4073000100"


def test_ldata_breaker_ignores_downloaded_images() -> None:
    parsed = _parse(
        "LDATA",
        _ldata_breaker(updateAvailability="UP_TO_DATE", firmwareVersionBLE="FWB3759000108", downloadedBLE="FWB3759000109"),
    )

    assert parsed["available_firmware"] is None


def test_ldata_breaker_without_silabs_firmware_shows_its_meter_firmware() -> None:
    assert _breaker_firmware_versions({}, ldata=True, firmware="FWB3760000100") == ("FWB3760000100", None, None)


def test_websocket_frame_with_one_field_is_merged() -> None:
    service = LDATAService("", "", None)
    breaker = _parse("WHEMS", _whem_breaker(downloadedSiLabs=""))
    assert breaker["available_firmware"] is None

    service._apply_breaker_update(breaker["id"], breaker, {"downloadedSiLabs": "FWC2422000100"}, source="WS")

    assert breaker["available_firmware"] == "FWC2422000100"
    assert breaker["firmware_fields"]["firmwareVersionSiLabs"] == "FWC2422000001"


def _entity(breaker: dict) -> LDATABreakerFirmwareUpdateEntity:
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = {"breakers": {breaker["id"]: breaker}}
    return LDATABreakerFirmwareUpdateEntity(coordinator, {**breaker, "panel_id": "panel-1"})


def test_entity_reports_an_update_without_offering_to_install_it() -> None:
    entity = _entity(_parse("WHEMS", _whem_breaker()))

    assert entity.installed_version == "FWC2422000001"
    assert entity.latest_version == "FWC2422000100"
    assert entity.release_summary == "SiLabs FWC2422000001 → FWC2422000100"
    assert entity.state == "on"
    assert not entity.supported_features & UpdateEntityFeature.INSTALL
    assert entity.entity_category is None
    # One per breaker: off until the user turns it on, so an update to every
    # breaker at once doesn't become a notification per breaker.
    assert entity.entity_registry_enabled_default is False


def test_entity_is_off_when_up_to_date() -> None:
    entity = _entity(_parse("LDATA", _ldata_breaker(updateAvailability="UP_TO_DATE")))

    assert entity.latest_version == entity.installed_version == "FWB4073000100"
    assert entity.state == "off"


def test_entity_trusts_leviton_over_version_order() -> None:
    # An LDATA update version need not sort above the installed one.
    entity = _entity(_parse("LDATA", _ldata_breaker(updateVersion="FWB4073000099")))

    assert entity.state == "on"


def test_entity_follows_coordinator_updates() -> None:
    breaker = _parse("WHEMS", _whem_breaker(downloadedSiLabs=""))
    entity = _entity(breaker)
    entity.async_write_ha_state = MagicMock()
    assert entity.state == "off"

    entity.coordinator.data["breakers"][breaker["id"]] = _parse("WHEMS", _whem_breaker())
    entity._handle_coordinator_update()

    assert entity.state == "on"
    entity.async_write_ha_state.assert_called_once_with()


@pytest.mark.asyncio
async def test_setup_adds_one_for_each_breaker() -> None:
    panel = {"id": "panel-1", "name": "Panel", "ModuleType": "WHEMS", "residentialBreakers": [_whem_breaker(), _ldata_breaker(position=2)]}
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = LDATAService("", "", None).parse_panels([panel])
    config_entry = SimpleNamespace(entry_id="entry-1", data={}, options={}, subentries={})
    hass = SimpleNamespace(data={"ldata": {config_entry.entry_id: coordinator}})
    entities = []

    await update.async_setup_entry(hass, config_entry, entities.extend)

    breakers = [e for e in entities if isinstance(e, LDATABreakerFirmwareUpdateEntity)]
    assert sorted(e.entity_data["id"] for e in breakers) == ["1A2B3C4D5E6F", "4C4557E12770"]
    assert len({e.unique_id for e in entities}) == len(entities)
