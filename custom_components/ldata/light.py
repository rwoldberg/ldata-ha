"""Support for Leviton Decora Smart Wi-Fi light entities."""

import asyncio
import logging
from typing import Any

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ColorMode,
    LightEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DECORA_MODELS_LIGHT,
    DOMAIN,
    LOGGER_NAME,
    POWER_OFF,
    POWER_ON,
)
from .decora_entity import DecoraEntity

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Decora Smart Wi-Fi light entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]

    if not coordinator.data:
        return

    entities = []
    for dev_id, dev_data in coordinator.data.get("decora_devices", {}).items():
        model = dev_data.get("model")
        name = (dev_data.get("name") or "").lower()

        # Light devices, OR switches named with "light" in name
        if model in DECORA_MODELS_LIGHT:
            entities.append(DecoraLight(coordinator, dev_data))
        elif model in ("DW15S", "D215S") and "light" in name:
            entities.append(DecoraLight(coordinator, dev_data))

    if entities:
        async_add_entities(entities)


class DecoraLight(DecoraEntity, LightEntity):
    """Representation of a Leviton Decora Smart Wi-Fi light."""

    def __init__(self, coordinator, data) -> None:
        """Init DecoraLight."""
        super().__init__(data=data, coordinator=coordinator)
        self._state = data.get("power") == POWER_ON
        self._brightness = data.get("brightness", 0)
        self._can_dim = data.get("canSetLevel", False)

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device = self._get_device_data()
        if device:
            self._state = device.get("power") == POWER_ON
            self._brightness = device.get("brightness", 0)
        self.async_write_ha_state()

    @property
    def is_on(self) -> bool:
        """Return True if entity is on."""
        return self._state

    @property
    def brightness(self) -> int | None:
        """Return the brightness of this light between 0..255."""
        if not self._can_dim:
            return None
        return int(self._brightness * 255 / 100) if self._brightness else 0

    @property
    def color_mode(self) -> ColorMode:
        """Return the color mode of the light."""
        if self._can_dim:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    @property
    def supported_color_modes(self) -> set[ColorMode]:
        """Flag supported color modes."""
        if self._can_dim:
            return {ColorMode.BRIGHTNESS}
        return {ColorMode.ONOFF}

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn the light on."""
        device = self._get_device_data()
        if not device:
            return

        residence_id = device.get("residenceId")
        if ATTR_BRIGHTNESS in kwargs:
            brightness_pct = int(kwargs[ATTR_BRIGHTNESS] * 100 / 255)
            payload = {"power": POWER_ON, "brightness": brightness_pct}
        else:
            payload = {"power": POWER_ON}

        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            payload,
        )
        if result:
            self._state = True
            if ATTR_BRIGHTNESS in kwargs:
                self._brightness = int(kwargs[ATTR_BRIGHTNESS] * 100 / 255)
            self.async_write_ha_state()
            await asyncio.sleep(1)
            await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the light off."""
        device = self._get_device_data()
        if not device:
            return

        residence_id = device.get("residenceId")
        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            {"power": POWER_OFF},
        )
        if result:
            self._state = False
            self.async_write_ha_state()
            await asyncio.sleep(1)
            await self.coordinator.async_request_refresh()

    @property
    def name_suffix(self) -> str | None:
        """Suffix to append to the device's name."""
        return None

    @property
    def unique_id_suffix(self) -> str | None:
        """Return the unique id suffix."""
        return "light"
