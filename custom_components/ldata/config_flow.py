"""Config flow for Leviton LDATA integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector

from .const import (
    DOMAIN,
    LOGGER_NAME,
    READ_ONLY,
    READ_ONLY_DEFAULT,
    THREE_PHASE,
    THREE_PHASE_DEFAULT,
    UPDATE_INTERVAL,
    UPDATE_INTERVAL_DEFAULT,
)
from .ldata_service import LDATAService

_LOGGER = logging.getLogger(LOGGER_NAME)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
        vol.Required("three_phase"): bool,
        vol.Required("read_only"): bool,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect."""
    service = LDATAService(data[CONF_USERNAME], data[CONF_PASSWORD], data[THREE_PHASE])
    try:
        result = await hass.async_add_executor_job(service.auth)
    except Exception as ex:
        raise InvalidAuth from ex

    if not result:
        _LOGGER.error("Failed to authenticate with Leviton API")
        raise CannotConnect
    
    return {"title": f"Leviton LDATA ({data[CONF_USERNAME]})"}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Leviton LDATA."""

    VERSION = 1
    DOMAIN = DOMAIN

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                await self.async_set_unique_id(user_input[CONF_USERNAME])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "OptionsFlow":
        """Get the options flow for this handler."""
        return OptionsFlow(config_entry)


class OptionsFlow(config_entries.OptionsFlow):
    """Handle the options flow for Leviton LDATA."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""

    async def async_step_init(self, user_input=None) -> ConfigFlowResult:
        """Return the options form."""
        if user_input is not None:
            # If 'log_fields' is empty or just whitespace, ensure it's saved as an empty string.
            if "log_fields" in user_input and not user_input["log_fields"].strip():
                user_input["log_fields"] = ""
            return self.async_create_entry(title="", data=user_input)
        
        current_options = self.config_entry.options
        current_data = self.config_entry.data

        options_schema = {
            vol.Optional(
                UPDATE_INTERVAL,
                default=current_options.get(UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT),
            ): int,
            vol.Optional(
                THREE_PHASE,
                default=current_options.get(THREE_PHASE, current_data.get(THREE_PHASE, THREE_PHASE_DEFAULT)),
            ): bool,
            vol.Optional(
                READ_ONLY,
                default=current_options.get(READ_ONLY, current_data.get(READ_ONLY, READ_ONLY_DEFAULT)),
            ): bool,
            vol.Optional(
                "log_warnings",
                default=current_options.get("log_warnings", True),
            ): bool,
            vol.Optional(
                "log_all_raw",
                default=current_options.get("log_all_raw", False),
            ): bool,
            vol.Optional(
                "enable_specific_logging",
                default=current_options.get("enable_specific_logging", False),
            ): bool,
            vol.Optional(
                "log_fields",
                default=current_options.get("log_fields", ""),
            ): selector.TextSelector(selector.TextSelectorConfig(multiline=True)),
        }

        return self.async_show_form(step_id="init", data_schema=vol.Schema(options_schema))


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
