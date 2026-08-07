"""Support for Leviton Decora Smart Wi-Fi fan entities."""

import asyncio
import logging
from typing import Any

from homeassistant.components.fan import (
    FanEntity,
    FanEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DECORA_MODELS_FAN,
    DECORA_MODELS_SWITCH,
    DOMAIN,
    LOGGER_NAME,
    POWER_OFF,
    POWER_ON,
)
from .decora_entity import DecoraEntity, add_entities_grouped_by_decora_room

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Decora Smart Wi-Fi fan entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]

    if not coordinator.data:
        return

    entities = []
    for dev_id, dev_data in coordinator.data.get("decora_devices", {}).items():
        model = dev_data.get("model")
        name = (dev_data.get("name") or "").lower()

        # Fan devices, OR switches named with "fan" in name
        if model in DECORA_MODELS_FAN:
            entities.append(DecoraFan(coordinator, dev_data))
        elif model in DECORA_MODELS_SWITCH and "fan" in name:
            entities.append(DecoraFan(coordinator, dev_data))

    add_entities_grouped_by_decora_room(config_entry, async_add_entities, entities)


class DecoraFan(DecoraEntity, FanEntity):
    """Representation of a Leviton Decora Smart Wi-Fi fan."""

    def __init__(self, coordinator, data) -> None:
        """Init DecoraFan."""
        super().__init__(data=data, coordinator=coordinator)
        self._state = data.get("power") == POWER_ON
        self._brightness = data.get("brightness", 0)  # brightness is speed for fans
        self._can_set_speed = data.get("canSetLevel", False)
        self._min_level = data.get("minLevel", 25)
        self._max_level = data.get("maxLevel", 100)

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
    def percentage(self) -> int | None:
        """Return the current speed percentage."""
        if not self._can_set_speed:
            return None
        return self._brightness

    @property
    def speed_count(self) -> int:
        """Return the number of speeds the fan supports."""
        if self._min_level and self._max_level and self._min_level > 0:
            return int(self._max_level / self._min_level)
        return 4

    @property
    def supported_features(self) -> FanEntityFeature:
        """Flag supported features."""
        features = FanEntityFeature.TURN_OFF | FanEntityFeature.TURN_ON
        if self._can_set_speed:
            features |= FanEntityFeature.SET_SPEED
        return features

    async def async_turn_on(
        self,
        percentage: int | None = None,
        preset_mode: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Turn the fan on."""
        device = self._get_device_data()
        if not device:
            return

        residence_id = device.get("residenceId")
        payload = {"power": POWER_ON}
        if percentage is not None:
            payload["brightness"] = percentage

        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            payload,
        )
        if result:
            self._state = True
            if percentage is not None:
                self._brightness = percentage
            self.async_write_ha_state()
            await asyncio.sleep(1)
            await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the fan off."""
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

    async def async_set_percentage(self, percentage: int) -> None:
        """Set the speed percentage of the fan."""
        device = self._get_device_data()
        if not device:
            return

        residence_id = device.get("residenceId")
        if percentage == 0:
            await self.async_turn_off()
            return

        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            {"power": POWER_ON, "brightness": percentage},
        )
        if result:
            self._state = True
            self._brightness = percentage
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
        return "fan"
