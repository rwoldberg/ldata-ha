"""Switch support for an LDATA devices."""

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, LOGGER_NAME, ALLOW_BREAKER_CONTROL, ALLOW_BREAKER_CONTROL_DEFAULT
from .ldata_entity import LDATAEntity
from .api.exceptions import LDATAAuthError

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the switch for the breakers."""

    entry = hass.data[DOMAIN][config_entry.entry_id]

    allow_breaker_control = config_entry.options.get(
        ALLOW_BREAKER_CONTROL,
        config_entry.data.get(ALLOW_BREAKER_CONTROL, ALLOW_BREAKER_CONTROL_DEFAULT),
    )
    if allow_breaker_control is True:
        breakers = entry.data.get("breakers", {})
        for breaker_id, breaker_data in breakers.items():
            switch = LDATASwitch(entry, breaker_data)
            async_add_entities([switch])

    # Blink LED switches are always available regardless of breaker control setting
    breakers = entry.data.get("breakers", {})
    for breaker_id, breaker_data in breakers.items():
        async_add_entities([LDATABlinkLEDSwitch(entry, breaker_data)])


class LDATASwitch(LDATAEntity, SwitchEntity):
    """Define the switch for the breaker."""

    def __init__(self, coordinator, data) -> None:
        """Init LDATASwitch."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = None
        self._last_known_is_on: bool = False
        self._consecutive_update_failures: int = 0

        breakers = self.coordinator.data.get("breakers", {})
        if current_data := breakers.get(self.breaker_data["id"]):
            if (
                current_data.get("state") == "ManualON"
                and current_data.get("remoteState") == "RemoteON"
            ):
                self._state = True
            else:
                self._state = False
            
            # Set the initial "last known" state
            self._last_known_is_on = self._state

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            breakers = self.coordinator.data.get("breakers", {})
            if new_data := breakers.get(self.breaker_data["id"]):
                if (
                    new_data.get("state") == "ManualON"
                    and new_data.get("remoteState") == "RemoteON"
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
            # else: keep self._state as last known value
            
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
        try:
            # Native async call since we decoupled the API module
            result = await self.coordinator.service.remote_off(self.breaker_data["id"])
        except LDATAAuthError as ex:
            _LOGGER.error("Auth error turning off breaker %s: %s", self.name, ex)
            self.async_write_ha_state()
            return
        except Exception as ex:
            _LOGGER.error("Error turning off breaker %s: %s", self.name, ex)
            self.async_write_ha_state()
            return

        if result:
            self._state = False
            self.async_write_ha_state()
        else:
            _LOGGER.error("Failed to turn off breaker %s", self.name)
            self.async_write_ha_state()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Reset the breaker."""
        try:
            # Native async call since we decoupled the API module
            result = await self.coordinator.service.remote_on(self.breaker_data["id"])
        except LDATAAuthError as ex:
            _LOGGER.error("Auth error turning on breaker %s: %s", self.name, ex)
            self.async_write_ha_state()
            return
        except Exception as ex:
            _LOGGER.error("Error turning on breaker %s: %s", self.name, ex)
            self.async_write_ha_state()
            return

        if result:
            self._state = True
            self.async_write_ha_state()
        else:
            _LOGGER.error("Failed to turn on breaker %s", self.name)
            self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Returns the extra attributes for the breaker."""
        attributes = super().extra_state_attributes
        attributes["panel_id"] = self.breaker_data.get("panel_id")

        return attributes

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the LDATA device's name."""
        return "Breaker"


class LDATABlinkLEDSwitch(LDATAEntity, SwitchEntity):
    """Switch to control breaker LED blinking."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, data) -> None:
        """Init LDATABlinkLEDSwitch."""
        super().__init__(data=data, coordinator=coordinator)
        self.breaker_data = data
        self._state = data.get("blinkLED", False)

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self.coordinator.async_add_listener(self._state_update))
        await super().async_added_to_hass()

    @callback
    def _state_update(self):
        """Call when the coordinator has an update."""
        try:
            if breakers := self.coordinator.data.get("breakers"):
                if new_data := breakers.get(self.breaker_data["id"]):
                    self._state = new_data.get("blinkLED", False)
        except (KeyError, TypeError):
            pass
        self.async_write_ha_state()

    @property
    def icon(self) -> str:
        return "mdi:led-on" if self.is_on else "mdi:led-off"

    @property
    def is_on(self) -> bool | None:
        return self._state

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable LED blinking."""
        try:
            result = await self.coordinator.service.set_blink_led(self.breaker_data["id"], True)
        except LDATAAuthError as ex:
            _LOGGER.error("Auth error enabling blink LED for %s: %s", self.name, ex)
            return
        except Exception as ex:
            _LOGGER.error("Error enabling blink LED for %s: %s", self.name, ex)
            return
        if result:
            self._state = True
            self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable LED blinking."""
        try:
            result = await self.coordinator.service.set_blink_led(self.breaker_data["id"], False)
        except LDATAAuthError as ex:
            _LOGGER.error("Auth error disabling blink LED for %s: %s", self.name, ex)
            return
        except Exception as ex:
            _LOGGER.error("Error disabling blink LED for %s: %s", self.name, ex)
            return
        if result:
            self._state = False
            self.async_write_ha_state()

    @property
    def name_suffix(self) -> str | None:
        return "Blink LED"

    @property
    def unique_id_suffix(self) -> str | None:
        return "blink_led"