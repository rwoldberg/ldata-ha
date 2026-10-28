"""reset_panel_energy over ledger-backed sensors.

Needs both fix/ldata-hourly-energy (the ledger and ledger_reset) and
fix/ldata-reset-energy-breaker-lookup (_async_reset_panel_energy), so it is
added by whichever of the two PRs merges second.
"""

import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from custom_components import ldata as init
from tests.test_ldata_hourly_energy import (  # noqa: F401  (fixtures)
    LDATAEnergyLedger,
    _daily_sensor,
    _lifetime_sensor,
    _pacific_time,
    _ts,
    sensor_clock,
)

DOMAIN = init.DOMAIN


@pytest.mark.asyncio
async def test_reset_panel_energy_uses_the_ledger(sensor_clock) -> None:  # noqa: F811
    ledger = LDATAEnergyLedger()
    ledger.apply("tech", 15, {"1": 0.03}, _ts(14, 16, 0, 29), "WS")
    ledger.apply("tech", 15, {"1": 0.05}, _ts(14, 17, 0, 29), "WS")
    sensor_clock.value = _ts(14, 18, 10)

    daily = _daily_sensor(ledger)
    daily._state = 4.2
    panel_daily = _daily_sensor(ledger, panel_total=True)
    panel_daily._state = 9.9
    lifetime = _lifetime_sensor(ledger)
    lifetime._state = 120.0
    lifetime._ledger_ref = 0.08

    coord = daily.coordinator
    coord.data["panels"] = [{"id": "LDATA-1", "serialNumber": "LDATA-1"}]
    devices = {
        "panel": SimpleNamespace(id="panel", name="Panel", identifiers={(DOMAIN, "LDATA-1")}),
        "tech": SimpleNamespace(id="tech", name="Tech", identifiers={(DOMAIN, "tech")}),
    }
    entities = [
        SimpleNamespace(entity_id="sensor.panel_daily", domain="sensor", device_id="panel"),
        SimpleNamespace(entity_id="sensor.tech_daily", domain="sensor", device_id="tech"),
        SimpleNamespace(entity_id="sensor.tech_consumption", domain="sensor", device_id="tech"),
    ]
    by_id = {
        "sensor.panel_daily": panel_daily,
        "sensor.tech_daily": daily,
        "sensor.tech_consumption": lifetime,
    }
    dev_reg = MagicMock()
    dev_reg.async_get.side_effect = devices.get
    hass = MagicMock()
    hass.data = {DOMAIN: {"entry-1": coord}}

    with (
        patch.object(init, "LDATAUpdateCoordinator", type(coord)),
        patch.object(init.dr, "async_get", return_value=dev_reg),
        patch.object(init.er, "async_get", return_value=MagicMock()),
        patch.object(init.er, "async_entries_for_config_entry", return_value=entities),
        patch.object(init, "_get_sensor_entity", side_effect=lambda _h, eid: by_id[eid]),
    ):
        await init._async_reset_panel_energy(hass, "tech")

    # Daily sensors are set to the ledger's energy for the day so far, not 0.
    assert daily._state == pytest.approx(0.08)
    assert daily._ledger_ref == pytest.approx(0.08)
    assert daily._last_date == datetime.date(2026, 10, 14)
    assert panel_daily._state == pytest.approx(0.08)
    # The lifetime sensor follows the ledger and is left unchanged.
    assert lifetime._state == 120.0
    assert lifetime._ledger_ref == 0.08
