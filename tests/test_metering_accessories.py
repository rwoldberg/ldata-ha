"""Leviton Metering Accessories (model LSBMA) on a standard breaker.

Two accessories meter the two legs of a 2-pole standard breaker. Leviton keeps
the breaker as a NONE-2 record naming them in lsbmaId/lsbmaId2, and each
accessory points back with lsbmaParentId (record shapes from the My Leviton
app's own code).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from custom_components.ldata import switch
from custom_components.ldata.const import ALLOW_BREAKER_CONTROL, ALLOW_LED_BLINK, ENABLE_DECORA
from custom_components.ldata.ldata_service import LDATAService


def _record(id_: str, position: int, model: str, **extra) -> dict:
    record = {
        "id": id_,
        "name": f"Circuit {position}",
        "model": model,
        "currentRating": 30,
        "position": position,
        "poles": 1,
        "serialNumber": f"S-{id_}",
        "hwVersion": "",
        "firmwareVersionMeter": "",
        "canRemoteOn": False,
        "currentState": "ManualON",
        "remoteState": "RemoteON",
        "power": 0,
        "power2": 0,
        "rmsCurrent": 0,
        "rmsCurrent2": 0,
    }
    record.update(extra)
    return record


def _panel() -> dict:
    return {
        "id": "panel-1",
        "name": "Panel",
        "ModuleType": "WHEMS",
        "residentialBreakers": [
            _record("MA-1", 5, "LSBMA", name="Dryer (MA 1)", lsbmaParentId="DRYER", power=2400),
            _record("MA-2", 7, "LSBMA", name="Dryer (MA 2)", lsbmaParentId="DRYER", power=2300),
            _record("DRYER", 5, "NONE-2", name="Dryer", poles=2, lsbmaId="MA-1", lsbmaId2="MA-2"),
            _record("PUMP", 9, "NONE-1", name="Well pump"),
        ],
    }


def test_accessories_are_metered_and_their_breaker_is_not_unmonitored() -> None:
    data = LDATAService("", "", None).parse_panels([_panel()])

    assert set(data["breakers"]) == {"MA-1", "MA-2"}
    assert data["panels"][0]["dumb_breakers"] == [
        {"id": "PUMP", "name": "Well pump", "position": 9, "poles": 1},
    ]
    assert data["panel-1totalPower"] == pytest.approx(4700)


def test_a_breaker_with_one_accessory_is_not_unmonitored_either() -> None:
    panel = _panel()
    panel["residentialBreakers"][2] = _record("DRYER", 5, "NONE-2", poles=2, lsbmaId="MA-1", lsbmaId2="")

    data = LDATAService("", "", None).parse_panels([panel])

    assert [b["id"] for b in data["panels"][0]["dumb_breakers"]] == ["PUMP"]


@pytest.mark.asyncio
async def test_accessories_get_no_power_switch_but_keep_identify() -> None:
    data = LDATAService("", "", None).parse_panels([_panel()])
    smart = _record("SMART", 1, "LB120-ST", canRemoteOn=True)
    data["breakers"]["SMART"] = LDATAService("", "", None).parse_panels(
        [{"id": "panel-1", "name": "Panel", "ModuleType": "WHEMS", "residentialBreakers": [smart]}]
    )["breakers"]["SMART"]
    coordinator = MagicMock()
    coordinator.user = "test-user"
    coordinator.data = data
    coordinator.async_add_listener.return_value = MagicMock()
    config_entry = SimpleNamespace(
        entry_id="entry-1",
        data={},
        options={ALLOW_BREAKER_CONTROL: True, ALLOW_LED_BLINK: True, ENABLE_DECORA: False},
        subentries={},
    )
    hass = SimpleNamespace(data={"ldata": {config_entry.entry_id: coordinator}})
    entities = []

    await switch.async_setup_entry(hass, config_entry, entities.extend)

    power = sorted(e.entity_data["id"] for e in entities if type(e) is switch.LDATASwitch)
    blink = sorted(e.entity_data["id"] for e in entities if type(e) is switch.LDATABlinkLEDSwitch)
    assert power == ["SMART"]
    assert blink == ["MA-1", "MA-2", "SMART"]
