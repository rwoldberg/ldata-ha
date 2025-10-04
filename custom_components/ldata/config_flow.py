"""Config flow for LDATA."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigEntry, OptionsFlow
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN
from .ldata_service import LDATAService

_LOGGER = logging.getLogger(__name__)

class LDATAConfigFlow(ConfigFlow, domain=DOMAIN):
    """LDATA config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle a flow initialized by the user."""
        errors: dict[str, str] = {}
        if user_input is not None:
            service = LDATAService(user_input["email"], user_input["password"], None)
            if await self.hass.async_add_executor_job(service.login):
                await self.async_set_unique_id(user_input["email"])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input["email"], data=user_input
                )
            errors["base"] = "auth"
        
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required("email"): str,
                    vol.Required("password"): str,
                }
            ),
            errors=errors,
        )
    
    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> OptionsFlow:
        """Create the options flow."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(OptionsFlow):
    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        "log_warnings",
                        default=self.config_entry.options.get("log_warnings", True),
                    ): bool,
                    vol.Optional(
                        "log_raw_data",
                        default=self.config_entry.options.get("log_raw_data", False),
                    ): bool,
                }
            ),
        )
