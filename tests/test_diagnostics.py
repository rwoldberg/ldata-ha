"""The diagnostics download leaves out what identifies the account or the home.

These files get attached to public issues. They keep what the download was
added for: device ids, MACs and serial numbers, to diagnose a device that
forked in two or landed in the wrong subentry.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import attr
import pytest
from homeassistant import loader
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_test_home_assistant,
)

from custom_components.ldata import diagnostics
from custom_components.ldata.const import DOMAIN

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        "config_subentry_id" not in {field.name for field in attr.fields(dr.DeviceEntry)},
        reason="needs a Home Assistant core with per-device subentries (2026.8 or newer)",
    ),
]

EMAIL = "Jane.Doe@example.com"
USER_ID = "user-0123456789"
SECRETS = (EMAIL, "hunter22", USER_ID, "res-42", "acct-7", "192.168.1.57")


async def _download(entities: list[str], **decora) -> tuple[dict, dict]:
    async with async_test_home_assistant() as hass:
        hass.data.pop(loader.DATA_CUSTOM_COMPONENTS, None)
        entry = MockConfigEntry(
            domain=DOMAIN,
            title=f"Leviton LDATA ({EMAIL})",
            data={
                "username": EMAIL,
                "password": "hunter22",
                "refresh_token": "token-1",
                "userid": USER_ID,
                "residence_id": "res-42",
            },
            options={"confirmed_solar_import_uids": [f"{EMAIL.lower()}-ldata_b1_lifetime_import"]},
        )
        entry.add_to_hass(hass)
        device = dr.async_get(hass).async_get_or_create(
            config_entry_id=entry.entry_id, identifiers={(DOMAIN, "AA:BB:CC:11:22:33")}, name="Hallway Dimmer"
        )
        for unique_id in entities:
            er.async_get(hass).async_get_or_create(
                "sensor", DOMAIN, unique_id, config_entry=entry, device_id=device.id
            )
        hass.data[DOMAIN] = {
            entry.entry_id: SimpleNamespace(
                data={
                    "decora_devices": {
                        "SW-1": {
                            "name": "Hallway Dimmer",
                            "mac": "AA:BB:CC:11:22:33",
                            "serial": "1000AB12CD34",
                            "localIP": "192.168.1.57",
                            "residenceId": "res-42",
                            "residentialAccountId": "acct-7",
                            **decora,
                        }
                    },
                    "panels": [{"id": "LDATA-1", "name": "Main Panel", "serialNumber": "LDATA-1"}],
                }
            )
        }
        try:
            return (
                await diagnostics.async_get_config_entry_diagnostics(hass, entry),
                await diagnostics.async_get_device_diagnostics(hass, entry, device),
            )
        finally:
            await hass.async_stop(force=True)


async def test_account_and_home_are_left_out() -> None:
    # Entities made before unique ids were keyed on the user id, one of them
    # after a re-authentication typed the email with other capitals.
    entry_dump, device_dump = await _download([f"{EMAIL}-ldata_b1_power", f"{EMAIL.lower()}-ldata_b1_current"])

    for dump in (entry_dump, device_dump):
        text = json.dumps(dump).casefold()
        for secret in SECRETS:
            assert secret.casefold() not in text, secret

    assert entry_dump["entry"]["title"] == "**REDACTED**"
    assert sorted(entity["unique_id"] for entity in entry_dump["entities"]) == [
        "**REDACTED**-ldata_b1_current",
        "**REDACTED**-ldata_b1_power",
    ]
    assert entry_dump["entry"]["options"]["confirmed_solar_import_uids"] == ["**REDACTED**-ldata_b1_lifetime_import"]


async def test_what_diagnoses_a_device_is_kept() -> None:
    entry_dump, device_dump = await _download([f"{USER_ID}-ldata_b1_power"])

    text = json.dumps(entry_dump)
    for kept in ("AA:BB:CC:11:22:33", "1000AB12CD34", "LDATA-1", "Main Panel", "Hallway Dimmer"):
        assert kept in text, kept
    assert device_dump["device"]["identifiers"] == ["('ldata', 'AA:BB:CC:11:22:33')"]
