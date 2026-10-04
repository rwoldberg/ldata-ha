"""The daily energy sensors must not publish a timestamp that changes every update."""

from unittest.mock import MagicMock

from custom_components.ldata.sensor import (
    LDATACTDailyUsageSensor,
    LDATADailyUsageSensor,
)


def _attributes(cls) -> dict:
    sensor = MagicMock()
    sensor._midnight_baseline = 1.0
    sensor._last_date = None
    sensor._use_hw_counters = False
    sensor._energy_key = "import"
    sensor._panel_energy_key = "import"
    sensor._last_update_time = 1759140000.0
    # Skip the base classes: only the attributes this class adds matter here.
    base = type("Base", (), {"extra_state_attributes": {}})
    prop = cls.__dict__["extra_state_attributes"]
    original = prop.fget
    import builtins

    real_super = builtins.super

    def fake_super(*args):
        return base()

    original.__globals__["super"] = fake_super
    try:
        return original(sensor)
    finally:
        original.__globals__.pop("super", None)
        assert builtins.super is real_super


def test_breaker_daily_sensor_has_no_update_timestamp() -> None:
    assert "last_update_time" not in _attributes(LDATADailyUsageSensor)


def test_ct_daily_sensor_has_no_update_timestamp() -> None:
    assert "last_update_time" not in _attributes(LDATACTDailyUsageSensor)
