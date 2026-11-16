"""A DAU hub that is synchronizing counts as online.

Leviton's breakerPanelStatus is READY, NOT_READY or SYNCHRONIZING, and the
My Leviton app shows only NOT_READY as disconnected. An offline panel's
sensors are unavailable and stop counting energy, so a hub in the middle of
a sync must not count as offline.
"""

from custom_components.ldata.ldata_service import LDATAService


def test_synchronizing_hub_is_online() -> None:
    service = LDATAService("", "", None)

    assert service._is_panel_connected({"model": "DAU", "status": "SYNCHRONIZING"})
    assert service._is_panel_connected({"model": "DAU", "status": "READY"})
    assert not service._is_panel_connected({"model": "DAU", "status": "NOT_READY"})
