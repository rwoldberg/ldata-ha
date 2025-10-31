"""Config flow for Leviton LDATA integration."""
from __future__ import annotations

import logging
from typing import Any, Mapping

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
from .ldata_service import LDATAService, LDATAAuthError, TwoFactorRequired

_LOGGER = logging.getLogger(LOGGER_NAME)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
        vol.Required("three_phase"): bool,
        vol.Required("read_only"): bool,
    }
)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Leviton LDATA."""

    VERSION = 1
    DOMAIN = DOMAIN

    def __init__(self):
        """Initialize the config flow."""
        self.service: LDATAService | None = None
        self.user_data: dict[str, Any] | None = None
        # Add this to store the entry being re-authenticated
        self.reauth_entry: config_entries.ConfigEntry | None = None

    async def _validate_input(self, hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
        """Validate the user input allows us to connect."""
        
        # Pass None for entry during initial setup
        self.service = LDATAService(data[CONF_USERNAME], data[CONF_PASSWORD], None) 
        try:
            result = await hass.async_add_executor_job(self.service.auth_with_credentials)
        
        except TwoFactorRequired:
            # This is not an error, it's the next step
            raise
        except LDATAAuthError as ex:
            # This is an invalid auth error
            _LOGGER.error("Invalid credentials: %s", ex)
            raise InvalidAuth from ex
        
        except Exception as ex:
            _LOGGER.error("Error validating credentials: %s", ex)
            raise CannotConnect from ex
    
        if not result:
            # This path should not be reachable if auth_with_credentials raises
            _LOGGER.error("Failed to authenticate with Leviton API")
            raise InvalidAuth
        
        return {"title": f"Leviton LDATA ({data[CONF_USERNAME]})"}

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Handle re-authentication."""
        # Store the entry for later update
        self.reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        
        # Store the existing config to pre-fill the form
        self.user_data = dict(entry_data)
        
        # Forward to the user step, which will be shown
        return await self.async_step_user(user_input=None)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            
            # If this is a reauth, user_data is pre-filled.
            # We merge the new user_input (username/password)
            # with the old data (three_phase, read_only).
            if self.user_data:
                self.user_data.update(user_input)
                input_to_validate = self.user_data
            else:
                input_to_validate = user_input

            try:
                # Store user data in case we need it for the 2FA step
                self.user_data = input_to_validate
                info = await self._validate_input(self.hass, input_to_validate)
                
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except TwoFactorRequired:
                # 2FA is needed. Move to the 2FA step.
                return await self.async_step_2fa()
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                # 2FA was not required, create or update entry
                
                if self.reauth_entry:
                    _LOGGER.debug("Re-auth (no 2FA) successful, updating entry.")
                    # Explicitly update data
                    new_data = self.reauth_entry.data.copy()
                    new_data[CONF_USERNAME] = self.user_data[CONF_USERNAME]
                    new_data[CONF_PASSWORD] = self.user_data[CONF_PASSWORD]
                    if self.service:
                        new_data["refresh_token"] = self.service.refresh_token
                        new_data["userid"] = self.service.userid
                    
                    self.hass.config_entries.async_update_entry(self.reauth_entry, data=new_data)
                    await self.hass.config_entries.async_reload(self.reauth_entry.entry_id)
                    return self.async_abort(reason="reauth_successful")
                
                # This is a new setup
                if self.service:
                    self.user_data["refresh_token"] = self.service.refresh_token
                    self.user_data["userid"] = self.service.userid

                await self.async_set_unique_id(self.user_data[CONF_USERNAME])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=self.user_data)

        # Pre-fill the form with data if it's a re-auth
        schema = STEP_USER_DATA_SCHEMA
        if self.user_data:
            schema = vol.Schema({
                vol.Required(CONF_USERNAME, default=self.user_data.get(CONF_USERNAME)): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(THREE_PHASE, default=self.user_data.get(THREE_PHASE, THREE_PHASE_DEFAULT)): bool,
                vol.Required(READ_ONLY, default=self.user_data.get(READ_ONLY, READ_ONLY_DEFAULT)): bool,
            })

        return self.async_show_form(
            step_id="user",
            data_schema=schema, # Use the potentially modified schema
            errors=errors,
        )

    async def async_step_2fa(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the 2FA step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if not self.service or not self.user_data:
                # Something went wrong, start over
                return self.async_abort(reason="unknown")

            try:
                code = user_input["2fa_code"]
                # Call the new complete_2fa method
                result = await self.hass.async_add_executor_job(
                    self.service.complete_2fa, code
                )
                
                if not result:
                    # This should not be reachable if complete_2fa raises LDATAAuthError
                    errors["base"] = "invalid_2fa"
                else:
                    # 2FA was successful, create or update entry
                    
                    if self.reauth_entry:
                        _LOGGER.debug("Re-auth (with 2FA) successful, updating entry.")
                        # Explicitly update data
                        new_data = self.reauth_entry.data.copy()
                        new_data[CONF_USERNAME] = self.user_data[CONF_USERNAME]
                        new_data[CONF_PASSWORD] = self.user_data[CONF_PASSWORD]
                        if self.service:
                            new_data["refresh_token"] = self.service.refresh_token
                            new_data["userid"] = self.service.userid
                        
                        self.hass.config_entries.async_update_entry(self.reauth_entry, data=new_data)
                        await self.hass.config_entries.async_reload(self.reauth_entry.entry_id)
                        return self.async_abort(reason="reauth_successful")

                    # This is a new setup
                    username = self.user_data[CONF_USERNAME]
                    self.user_data["refresh_token"] = self.service.refresh_token
                    self.user_data["userid"] = self.service.userid
                    
                    await self.async_set_unique_id(username)
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(
                        title=f"Leviton LDATA ({username})", data=self.user_data
                    )
            
            except LDATAAuthError as ex:
                _LOGGER.warning("2FA failed: %s", ex)
                errors["base"] = "invalid_2fa"
            except Exception:
                _LOGGER.exception("Unexpected error during 2FA validation")
                errors["base"] = "unknown"
        
        # Show the 2FA form
        return self.async_show_form(
            step_id="2fa",
            data_schema=vol.Schema({vol.Required("2fa_code"): str}),
            errors=errors,
            description_placeholders={"username": self.user_data[CONF_USERNAME]} if self.user_data else {},
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
            if "log_fields" in user_input and not user_input["log_fields"].strip():
                user_input["log_fields"] = ""
            return self.async_create_entry(title="", data=user_input)
        
        current_options = self.config_entry.options
        current_data = self.config_entry.data

        options_schema = {
            vol.Optional(
                UPDATE_INTERVAL,
                default=current_options.get(UPDATE_INTERVAL, UPDATE_INTERVAL_DEFAULT),
            ): vol.All(vol.Coerce(int), vol.Range(min=30)),
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
                "log_data_warnings",
                default=current_options.get("log_data_warnings", True),
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
