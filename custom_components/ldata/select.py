"""Support for Leviton Decora Smart Wi-Fi select entities."""

import asyncio
import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DECORA_MODELS_GFCI,
    DECORA_MODELS_CONTROLLER,
    DOMAIN,
    LOGGER_NAME,
)
from .decora_entity import DecoraEntity, add_entities_grouped_by_decora_room

_LOGGER = logging.getLogger(LOGGER_NAME)


# ═══════════════════════════════════════════════════════════════════════════
# Option Maps — API integer value → human-readable label
# ═══════════════════════════════════════════════════════════════════════════

AUTO_SHUTOFF_MAP = {
    0: "Disabled",
    60: "1 Minute",
    300: "5 Minutes",
    600: "10 Minutes",
    900: "15 Minutes",
    1800: "30 Minutes",
    3600: "1 Hour",
    7200: "2 Hours",
    10800: "3 Hours",
    14400: "4 Hours",
    18000: "5 Hours",
    21600: "6 Hours",
    25200: "7 Hours",
    28800: "8 Hours",
    32400: "9 Hours",
    36000: "10 Hours",
    39600: "11 Hours",
    43200: "12 Hours",
}

STATUS_LED_MAP = {
    0: "Always Off",
    254: "Status Mode",
    255: "Locator Mode",
}

LOAD_TYPE_MAP = {
    0: "Incandescent",
    1: "LED",
    2: "CFL",
    4: "MLV",
    5: "Non-Dimmable",
    6: "ELV",
}

FADE_ON_OFF_RATE_MAP = {
    0: "Instant",
    5: "0.5 Seconds",
    10: "1 Second",
    15: "1.5 Seconds",
    20: "2 Seconds",
    30: "3 Seconds",
    50: "5 Seconds",
    100: "10 Seconds",
    150: "15 Seconds",
    250: "25 Seconds",
}

CONTROL_TIMING_MAP = {
    80: "Normal",
    92: "Medium",
    97: "Extended",
}

DIM_LED_MAP = {
    0: "Always Off",
    1: "1 Second",
    2: "2 Seconds",
    3: "3 Seconds",
    5: "5 Seconds",
    10: "10 Seconds",
    15: "15 Seconds",
    25: "25 Seconds",
    255: "Always On",
}

DIMMING_MODE_MAP = {
    False: "Forward",
    True: "Reverse",
}

MOTION_MODE_MAP = {
    0: "Occupancy",
    1: "Vacancy",
}

MOTION_NIGHT_MODE_MAP = {
    0: "Room Lights",
    2: "Guidelight",
}

MOTION_SNOOZE_MAP = {
    0: "Disabled",
    1: "1 Minute",
    5: "5 Minutes",
    10: "10 Minutes",
    15: "15 Minutes",
    30: "30 Minutes",
    60: "1 Hour",
    120: "2 Hours",
    180: "3 Hours",
    240: "4 Hours",
    300: "5 Hours",
    360: "6 Hours",
    420: "7 Hours",
    480: "8 Hours",
    540: "9 Hours",
    600: "10 Hours",
    660: "11 Hours",
    720: "12 Hours",
    1440: "24 Hours",
}

MOTION_TIMEOUT_MAP = {
    1: "1 Minute",
    2: "2 Minutes",
    3: "3 Minutes",
    4: "4 Minutes",
    5: "5 Minutes",
    6: "6 Minutes",
    7: "7 Minutes",
    8: "8 Minutes",
    9: "9 Minutes",
    10: "10 Minutes",
    15: "15 Minutes",
    20: "20 Minutes",
    25: "25 Minutes",
    30: "30 Minutes",
    45: "45 Minutes",
    60: "60 Minutes",
}


def _reverse_map(m: dict) -> dict:
    return {v: k for k, v in m.items()}


# ═══════════════════════════════════════════════════════════════════════════
# Select entity descriptors — (api_field, label, icon, option_map, is_supported_fn)
# ═══════════════════════════════════════════════════════════════════════════

def _is_dimmable_light(dev: dict) -> bool:
    return dev.get("canSetLevel", False) and dev.get("model") not in (
        DECORA_MODELS_GFCI + DECORA_MODELS_CONTROLLER
    )


def _has_motion(dev: dict) -> bool:
    return dev.get("motionMode") is not None


def _is_elv(dev: dict) -> bool:
    return dev.get("model") == "D2ELV"


def _not_motion_not_gfci(dev: dict) -> bool:
    return not _has_motion(dev) and dev.get("model") not in DECORA_MODELS_GFCI


def _not_controller_not_gfci(dev: dict) -> bool:
    return (
        dev.get("model") not in DECORA_MODELS_CONTROLLER
        and dev.get("model") not in DECORA_MODELS_GFCI
    )


# Each tuple: (api_field, suffix, icon, option_map, is_supported_fn)
SELECT_DESCRIPTORS = [
    ("autoOffTime", "Auto Shutoff", "mdi:timer-off-outline", AUTO_SHUTOFF_MAP, _not_motion_not_gfci),
    ("statusLED", "Status LED", "mdi:led-on", STATUS_LED_MAP, _not_controller_not_gfci),
    ("loadType", "Bulb Type", "mdi:lightbulb-cfl", LOAD_TYPE_MAP, _is_dimmable_light),
    ("triacOff", "Control Timing", "mdi:tune", CONTROL_TIMING_MAP, _is_dimmable_light),
    ("fadeOnTime", "Fade On Rate", "mdi:network-strength-3", FADE_ON_OFF_RATE_MAP, _is_dimmable_light),
    ("fadeOffTime", "Fade Off Rate", "mdi:network-strength-1", FADE_ON_OFF_RATE_MAP, _is_dimmable_light),
    ("dimLED", "LED Bar Behavior", "mdi:dots-vertical", DIM_LED_MAP, _is_dimmable_light),
    ("reversePhase", "Dimming Mode", "mdi:sine-wave", DIMMING_MODE_MAP, _is_elv),
    ("motionMode", "Motion Mode", "mdi:exit-run", MOTION_MODE_MAP, _has_motion),
    ("motionNightMode", "Motion Night Mode", "mdi:lightbulb-night", MOTION_NIGHT_MODE_MAP, _has_motion),
    ("motionDisableTime", "Motion Snooze", "mdi:alarm-snooze", MOTION_SNOOZE_MAP, _has_motion),
    ("motionTimeout", "Motion Timeout", "mdi:timer", MOTION_TIMEOUT_MAP, _has_motion),
]


# ═══════════════════════════════════════════════════════════════════════════
# Platform setup
# ═══════════════════════════════════════════════════════════════════════════

async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Decora Smart Wi-Fi select entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]

    if not coordinator.data:
        return

    entities = []
    for dev_id, dev_data in coordinator.data.get("decora_devices", {}).items():
        for api_field, suffix, icon, option_map, is_supported_fn in SELECT_DESCRIPTORS:
            # Only create if the device has the field AND passes the support check
            if dev_data.get(api_field) is not None and is_supported_fn(dev_data):
                entities.append(
                    DecoraSelectEntity(
                        coordinator, dev_data,
                        api_field=api_field,
                        suffix=suffix,
                        icon_str=icon,
                        option_map=option_map,
                    )
                )

    add_entities_grouped_by_decora_room(config_entry, async_add_entities, entities)


# ═══════════════════════════════════════════════════════════════════════════
# Generic select entity — one class handles all option maps
# ═══════════════════════════════════════════════════════════════════════════

class DecoraSelectEntity(DecoraEntity, SelectEntity):
    """Config select entity for a Leviton Decora Smart Wi-Fi device."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(
        self,
        coordinator,
        data,
        *,
        api_field: str,
        suffix: str,
        icon_str: str,
        option_map: dict,
    ) -> None:
        """Init DecoraSelectEntity."""
        self._api_field = api_field
        self._suffix = suffix
        self._icon_str = icon_str
        self._option_map = option_map
        self._reverse_map = _reverse_map(option_map)
        super().__init__(data=data, coordinator=coordinator)

        raw = data.get(api_field)
        self._current = self._option_map.get(raw, list(self._option_map.values())[0])

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        device = self._get_device_data()
        if device and device.get(self._api_field) is not None:
            raw = device[self._api_field]
            self._current = self._option_map.get(raw, self._current)
        self.async_write_ha_state()

    @property
    def icon(self) -> str:
        """Return the icon."""
        return self._icon_str

    @property
    def options(self) -> list[str]:
        """Return the list of available options."""
        return list(self._option_map.values())

    @property
    def current_option(self) -> str | None:
        """Return the currently selected option."""
        return self._current

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        if option not in self._reverse_map:
            return

        device = self._get_device_data()
        if not device:
            return

        api_value = self._reverse_map[option]
        residence_id = device.get("residenceId")
        result = await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            {self._api_field: api_value},
        )
        if result:
            self._current = option
            self.async_write_ha_state()
            await asyncio.sleep(1)
            await self.coordinator.async_request_refresh()

    @property
    def name_suffix(self) -> str | None:
        return self._suffix

    @property
    def unique_id_suffix(self) -> str | None:
        return self._api_field
