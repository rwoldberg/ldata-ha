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
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    DOMAIN,
    LOGGER_NAME,
    ALLOW_BREAKER_CONTROL,
    ALLOW_BREAKER_CONTROL_DEFAULT,
    THREE_PHASE,
    THREE_PHASE_DEFAULT,
    HA_INFORM_RATE,
    HA_INFORM_RATE_DEFAULT,
    HA_INFORM_RATE_MIN,
    HA_INFORM_RATE_MAX,
    GAP_HANDLING,
    GAP_HANDLING_DEFAULT,
    GAP_HANDLING_OPTIONS,
    GAP_THRESHOLD,
    GAP_THRESHOLD_DEFAULT,
    GAP_THRESHOLD_MIN,
    GAP_THRESHOLD_MAX,
)
from .ldata_service import LDATAService, LDATAAuthError, TwoFactorRequired

_LOGGER = logging.getLogger(LOGGER_NAME)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
        vol.Required("three_phase"): bool,
        vol.Required("allow_breaker_control"): bool,
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
        self.reauth_entry: config_entries.ConfigEntry | None = None

    async def _validate_input(self, hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
        """Validate the user input allows us to connect."""
        session = async_get_clientsession(hass)
        self.service = LDATAService(data[CONF_USERNAME], data[CONF_PASSWORD], None, session) 
        try:
            result = await self.service.auth_with_credentials()
        
        except TwoFactorRequired:
            raise
        except LDATAAuthError as ex:
            _LOGGER.error("Invalid credentials: %s", ex)
            raise InvalidAuth from ex
        except Exception as ex:
            _LOGGER.error("Error validating credentials: %s", ex)
            raise CannotConnect from ex
    
        if not result:
            _LOGGER.error("Failed to authenticate with Leviton API")
            raise InvalidAuth
        
        return {"title": f"Leviton LDATA ({data[CONF_USERNAME]})"}

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Handle re-authentication."""
        self.reauth_entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        self.user_data = dict(entry_data)
        return await self.async_step_user(user_input=None)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            
            if self.user_data:
                self.user_data.update(user_input)
                input_to_validate = self.user_data
            else:
                input_to_validate = user_input

            try:
                self.user_data = input_to_validate
                info = await self._validate_input(self.hass, input_to_validate)
                
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except TwoFactorRequired:
                return await self.async_step_2fa()
            except Exception:
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                if self.reauth_entry:
                    _LOGGER.debug("Re-auth (no 2FA) successful, updating entry.")
                    new_data = self.reauth_entry.data.copy()
                    new_data[CONF_USERNAME] = self.user_data[CONF_USERNAME]
                    new_data[CONF_PASSWORD] = self.user_data[CONF_PASSWORD]
                    if self.service:
                        new_data["refresh_token"] = self.service.refresh_token
                        new_data["userid"] = self.service.userid
                    
                    self.hass.config_entries.async_update_entry(self.reauth_entry, data=new_data)
                    await self.hass.config_entries.async_reload(self.reauth_entry.entry_id)
                    return self.async_abort(reason="reauth_successful")
                
                if self.service:
                    self.user_data["refresh_token"] = self.service.refresh_token
                    self.user_data["userid"] = self.service.userid

                await self.async_set_unique_id(self.user_data[CONF_USERNAME])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=info["title"], data=self.user_data)

        schema = STEP_USER_DATA_SCHEMA
        if self.user_data:
            schema = vol.Schema({
                vol.Required(CONF_USERNAME, default=self.user_data.get(CONF_USERNAME)): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(THREE_PHASE, default=self.user_data.get(THREE_PHASE, THREE_PHASE_DEFAULT)): bool,
                vol.Required(ALLOW_BREAKER_CONTROL, default=self.user_data.get(ALLOW_BREAKER_CONTROL, ALLOW_BREAKER_CONTROL_DEFAULT)): bool,
            })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_2fa(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the 2FA step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if not self.service or not self.user_data:
                return self.async_abort(reason="unknown")

            try:
                code = user_input["2fa_code"]
                result = await self.service.complete_2fa(code)
                
                if not result:
                    errors["base"] = "invalid_2fa"
                else:
                    if self.reauth_entry:
                        _LOGGER.debug("Re-auth (with 2FA) successful, updating entry.")
                        new_data = self.reauth_entry.data.copy()
                        new_data[CONF_USERNAME] = self.user_data[CONF_USERNAME]
                        new_data[CONF_PASSWORD] = self.user_data[CONF_PASSWORD]
                        if self.service:
                            new_data["refresh_token"] = self.service.refresh_token
                            new_data["userid"] = self.service.userid
                        
                        self.hass.config_entries.async_update_entry(self.reauth_entry, data=new_data)
                        await self.hass.config_entries.async_reload(self.reauth_entry.entry_id)
                        return self.async_abort(reason="reauth_successful")

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

        show_gap_options = True
        coordinator = self.hass.data.get(DOMAIN, {}).get(self.config_entry.entry_id)
        if coordinator and hasattr(coordinator, '_service') and coordinator._service:
            service = coordinator._service
            if hasattr(service, '_panel_has_hw_counters') and service._panel_has_hw_counters:
                show_gap_options = not all(service._panel_has_hw_counters.values())

        options_schema = {
            vol.Optional(
                HA_INFORM_RATE,
                default=current_options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT),
            ): vol.All(
                vol.Coerce(float),
                vol.Range(min=HA_INFORM_RATE_MIN, max=HA_INFORM_RATE_MAX)
            ),
            vol.Optional(
                THREE_PHASE,
                default=current_options.get(THREE_PHASE, current_data.get(THREE_PHASE, THREE_PHASE_DEFAULT)),
            ): bool,
            vol.Optional(
                ALLOW_BREAKER_CONTROL,
                default=current_options.get(ALLOW_BREAKER_CONTROL, current_data.get(ALLOW_BREAKER_CONTROL, ALLOW_BREAKER_CONTROL_DEFAULT)),
            ): bool,
        }

        if show_gap_options:
            options_schema[vol.Optional(
                GAP_HANDLING,
                default=current_options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT),
            )] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[
                        selector.SelectOptionDict(value="skip", label="Skip — Don't accumulate energy during gaps"),
                        selector.SelectOptionDict(value="extrapolate", label="Extrapolate — Assume last known power continued"),
                        selector.SelectOptionDict(value="average", label="Average — Use mean of last and recovery power"),
                    ],
                    mode=selector.SelectSelectorMode.DROPDOWN,
                )
            )
            options_schema[vol.Optional(
                GAP_THRESHOLD,
                default=current_options.get(GAP_THRESHOLD, GAP_THRESHOLD_DEFAULT),
            )] = vol.All(
                vol.Coerce(float),
                vol.Range(min=GAP_THRESHOLD_MIN, max=GAP_THRESHOLD_MAX)
            )

        options_schema.update({
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
        })

        return self.async_show_form(step_id="init", data_schema=vol.Schema(options_schema))


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""