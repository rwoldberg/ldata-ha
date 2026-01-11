"""Switch support for an LDATA devices."""

import asyncio
import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, LOGGER_NAME, READ_ONLY, READ_ONLY_DEFAULT
from .ldata_entity import LDATAEntity

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the switch for the breakers."""

    entry = hass.data[DOMAIN][config_entry.entry_id]

    read_only = config_entry.options.get(
        READ_ONLY,
        config_entry.data.get(
            READ_ONLY, config_entry.data.get(READ_ONLY, READ_ONLY_DEFAULT)
        ),
    )
    if read_only is False:
        for breaker_id in entry.data["breakers"]:
            breaker_data = entry.data["breakers"][breaker_id]
            switch = LDATASwitch(entry, breaker_data)
            async_add_entities([switch])


class LDATASwitch(LDATAEntity, SwitchEntity):
    """Define the switch for the breaker."""

    def __init__(self, coordinator, data) -> None:
        """Init LDATASwitch."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = None
        self._last_known_is_on: bool = False
        self._consecutive_update_failures: int = 0

        if current_data := self.coordinator.data["breakers"][self.breaker_data["id"]]:
            if (
                current_data["state"] == "ManualON"
                and current_data["remoteState"] == "RemoteON"
            ):
                self._state = True
            else:
                self._state = False
            
            # Set the initial "last known" state
            self._last_known_is_on = self._state

        # Subscribe to updates.
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            new_data = self.coordinator.data["breakers"][self.breaker_data["id"]]
            if (
                new_data["state"] == "ManualON"
                and new_data["remoteState"] == "RemoteON"
            ):
                self._state = True
            else:
                self._state = False
            
            self._last_known_is_on = self._state
            self._consecutive_update_failures = 0

        except (KeyError, TypeError):
            self._consecutive_update_failures += 1

        if self._consecutive_update_failures > 5:
            self._state = None
        else:
            self._state = self._last_known_is_on
            
        self.async_write_ha_state()

    @property
    def icon(self) -> str:
        """Return the icon type."""
        if self.is_on is True:
            return "mdi:electric-switch-closed"
        return "mdi:electric-switch"

    @property
    def is_on(self) -> bool | None:
        """Returns true if the switch is on."""
        return self._state

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Trip the breaker."""
        # Capture result to verify success before updating state
        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.remote_off, self.breaker_data["id"]
        )

        if result:
            self._state = False
            self.async_write_ha_state()
            # Wait for the physical device to react before refreshing
            await asyncio.sleep(2)
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to turn off breaker %s", self.name)
            # Write state immediately to revert the UI toggle to its previous position
            self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Reset the breaker."""
        # Capture result to verify success before updating state
        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.remote_on, self.breaker_data["id"]
        )

        if result:
            self._state = True
            self.async_write_ha_state()
            # Wait for the physical device to react before refreshing
            await asyncio.sleep(2)
            await self.coordinator.async_request_refresh()
        else:
            _LOGGER.error("Failed to turn on breaker %s", self.name)
            # Write state immediately to revert the UI toggle to its previous position
            self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        attributes = super().extra_state_attributes
        attributes["panel_id"] = self.breaker_data["panel_id"]

        return attributes

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return "Breaker"
