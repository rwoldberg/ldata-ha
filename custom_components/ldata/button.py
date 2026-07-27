"""Support for Leviton Decora Smart Wi-Fi button entities."""

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DECORA_MODELS_GFCI, DOMAIN, LOGGER_NAME
from .decora_entity import DecoraEntity

_LOGGER = logging.getLogger(LOGGER_NAME)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Decora Smart Wi-Fi button entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]

    if not coordinator.data:
        return

    entities = []
    for dev_id, dev_data in coordinator.data.get("decora_devices", {}).items():
        # Identify button — all devices
        entities.append(DecoraIdentifyButton(coordinator, dev_data))
        # Silence Buzzer button — GFCI only
        if dev_data.get("model") in DECORA_MODELS_GFCI:
            entities.append(DecoraSilenceBuzzerButton(coordinator, dev_data))

    if entities:
        async_add_entities(entities)


class DecoraIdentifyButton(DecoraEntity, ButtonEntity):
    """Button to identify (blink) a Decora device."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:flash"

    def __init__(self, coordinator, data) -> None:
        """Init DecoraIdentifyButton."""
        super().__init__(data=data, coordinator=coordinator)

    async def async_press(self) -> None:
        """Press the button."""
        device = self._get_device_data()
        if not device:
            return
        residence_id = device.get("residenceId")
        await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            {"identify": 10},
        )

    @property
    def name_suffix(self) -> str | None:
        return "Identify"

    @property
    def unique_id_suffix(self) -> str | None:
        return "identify"


class DecoraSilenceBuzzerButton(DecoraEntity, ButtonEntity):
    """Button to silence the GFCI audible alert."""

    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:volume-off"

    def __init__(self, coordinator, data) -> None:
        """Init DecoraSilenceBuzzerButton."""
        super().__init__(data=data, coordinator=coordinator)

    async def async_press(self) -> None:
        """Press the button."""
        device = self._get_device_data()
        if not device:
            return
        residence_id = device.get("residenceId")
        await self.coordinator.hass.async_add_executor_job(
            self.coordinator.service.set_iot_switch,
            residence_id,
            self._dev_id,
            {"silenceBuzzer": True},
        )

    @property
    def name_suffix(self) -> str | None:
        return "Silence Audible Alert"

    @property
    def unique_id_suffix(self) -> str | None:
        return "silence_buzzer"
