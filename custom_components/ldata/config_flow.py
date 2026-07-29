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
    ALLOW_BREAKER_CONTROL,
    ALLOW_BREAKER_CONTROL_DEFAULT,
    ENABLE_DECORA,
    ENABLE_DECORA_DEFAULT,
    THREE_PHASE,
    THREE_PHASE_DEFAULT,
    HA_INFORM_RATE,
    HA_INFORM_RATE_DEFAULT,
    HA_INFORM_RATE_MIN,
    HA_INFORM_RATE_MAX,
    GAP_HANDLING,
    GAP_HANDLING_DEFAULT,
    GAP_HANDLING_LABELS,
    GAP_THRESHOLD,
    GAP_THRESHOLD_DEFAULT,
    GAP_THRESHOLD_MIN,
    GAP_THRESHOLD_MAX,
    CONF_RESIDENCE_ID,
    RESIDENCE_IMPORT_SOURCE,
)
from .ldata_service import LDATAService, LDATAAuthError, TwoFactorRequired

_LOGGER = logging.getLogger(LOGGER_NAME)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
        vol.Required("three_phase"): bool,
        vol.Required("allow_breaker_control"): bool,
        vol.Required(ENABLE_DECORA, default=ENABLE_DECORA_DEFAULT): bool,
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
        # Populated by _after_auth() once credentials are validated, for the
        # residence-selection step on brand-new (non-reauth) setups.
        self.discovered_residences: list[dict[str, str]] = []
        self._pending_title: str | None = None

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

    async def _finalize_entry(self, title: str) -> ConfigFlowResult:
        """Persist a successful auth as either a reauth update or a new entry.

        Shared by async_step_user and async_step_2fa — both reach this once
        credentials (and 2FA, if required) have been validated, by way of
        _after_auth() (which handles residence selection for new setups).
        """
        if self.reauth_entry:
            _LOGGER.debug("Re-auth successful, updating entry.")
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

        # Entries created via the residence picker carry a residence_id, so
        # the same Leviton account can back multiple entries (one per
        # residence) without colliding on username alone. Entries with no
        # residence_id (discovery found nothing, or an older HA core/flow
        # path) keep the original username-only unique_id.
        residence_id = self.user_data.get(CONF_RESIDENCE_ID)
        unique_id = f"{self.user_data[CONF_USERNAME]}::{residence_id}" if residence_id else self.user_data[CONF_USERNAME]
        await self.async_set_unique_id(unique_id)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=title, data=self.user_data)

    async def _after_auth(self, title: str) -> ConfigFlowResult:
        """Reached once credentials (and 2FA, if required) are validated.

        Reauth goes straight to _finalize_entry — residence selection only
        applies to brand-new setups, never to refreshing an existing entry's
        credentials. For new setups, discover the account's residences and,
        if there's more than one, ask which to set up; a single (or zero)
        discovered residence skips the extra step entirely.
        """
        if self.reauth_entry:
            return await self._finalize_entry(title)

        try:
            self.discovered_residences = await self.hass.async_add_executor_job(
                self.service.discover_residences
            )
        except Exception:
            _LOGGER.exception("Failed to discover residences; proceeding without residence filtering")
            self.discovered_residences = []

        if len(self.discovered_residences) <= 1:
            if self.discovered_residences:
                self.user_data[CONF_RESIDENCE_ID] = self.discovered_residences[0]["id"]
            return await self._finalize_entry(title)

        self._pending_title = title
        return await self.async_step_residence()

    def _residence_schema(self) -> vol.Schema:
        options = [
            selector.SelectOptionDict(value=r["id"], label=r["name"])
            for r in self.discovered_residences
        ]
        return vol.Schema({
            vol.Required(
                "residences", default=[self.discovered_residences[0]["id"]]
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=options,
                    multiple=True,
                    mode=selector.SelectSelectorMode.LIST,
                )
            )
        })

    async def async_step_residence(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Let the user choose which residence(s) to set up as separate entries."""
        if user_input is not None:
            selected = user_input.get("residences") or []
            if not selected:
                return self.async_show_form(
                    step_id="residence",
                    data_schema=self._residence_schema(),
                    errors={"base": "no_residence_selected"},
                )

            # async_create_entry can only be called once per flow, so the
            # first selection finishes THIS flow; any additional selections
            # are created as separate entries via the internal
            # residence_import source, reusing the auth tokens already
            # obtained here so the user isn't prompted to log in again.
            first, *rest = selected
            for residence_id in rest:
                residence_name = next(
                    (r["name"] for r in self.discovered_residences if r["id"] == residence_id),
                    residence_id,
                )
                residence_data = {**self.user_data, CONF_RESIDENCE_ID: residence_id}
                await self.hass.config_entries.flow.async_init(
                    DOMAIN,
                    context={"source": RESIDENCE_IMPORT_SOURCE},
                    data={
                        "title": f"Leviton LDATA ({residence_name})",
                        "entry_data": residence_data,
                    },
                )

            self.user_data[CONF_RESIDENCE_ID] = first
            # Give the first entry a residence-named title too, matching the
            # "rest" entries above — without this, the first selected
            # residence's entry keeps the generic username-only title set
            # back in _after_auth(), making it indistinguishable in the UI
            # from any other entry that also happens to use just the
            # username (including another "first" pick from a separate
            # multi-residence setup run).
            first_residence_name = next(
                (r["name"] for r in self.discovered_residences if r["id"] == first),
                first,
            )
            return await self._finalize_entry(f"Leviton LDATA ({first_residence_name})")

        return self.async_show_form(
            step_id="residence",
            data_schema=self._residence_schema(),
        )

    async def async_step_residence_import(self, import_data: dict[str, Any]) -> ConfigFlowResult:
        """Internal-only step: create an additional entry for a residence the
        user selected alongside their first, reusing already-obtained auth
        tokens — never reached via any user-facing form.
        """
        entry_data = import_data["entry_data"]
        residence_id = entry_data[CONF_RESIDENCE_ID]
        await self.async_set_unique_id(f"{entry_data[CONF_USERNAME]}::{residence_id}")
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=import_data["title"], data=entry_data)

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
            # with the old data (three_phase, allow_breaker_control).
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
                return await self._after_auth(info["title"])

        # Pre-fill the form with data if it's a re-auth
        schema = STEP_USER_DATA_SCHEMA
        if self.user_data:
            schema = vol.Schema({
                vol.Required(CONF_USERNAME, default=self.user_data.get(CONF_USERNAME)): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(THREE_PHASE, default=self.user_data.get(THREE_PHASE, THREE_PHASE_DEFAULT)): bool,
                vol.Required(ALLOW_BREAKER_CONTROL, default=self.user_data.get(ALLOW_BREAKER_CONTROL, ALLOW_BREAKER_CONTROL_DEFAULT)): bool,
                vol.Required(ENABLE_DECORA, default=self.user_data.get(ENABLE_DECORA, ENABLE_DECORA_DEFAULT)): bool,
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

            code = user_input["2fa_code"]
            try:
                # Call the new complete_2fa method
                result = await self.hass.async_add_executor_job(
                    self.service.complete_2fa, code
                )
            except LDATAAuthError as ex:
                _LOGGER.warning("2FA failed: %s", ex)
                errors["base"] = "invalid_2fa"
            except Exception:
                _LOGGER.exception("Unexpected error during 2FA validation")
                errors["base"] = "unknown"
            else:
                if not result:
                    # This should not be reachable if complete_2fa raises LDATAAuthError
                    errors["base"] = "invalid_2fa"
                else:
                    # 2FA was successful, create or update entry — deliberately
                    # OUTSIDE the try/except above (matches async_step_user's
                    # pattern) so a legitimate AbortFlow raised deep inside
                    # (_finalize_entry's "already configured" check, when
                    # re-adding an account/residence that's already set up)
                    # propagates to HA's flow manager instead of being caught
                    # by the broad `except Exception` and misreported as a
                    # generic "unknown" error.
                    username = self.user_data[CONF_USERNAME]
                    return await self._after_auth(f"Leviton LDATA ({username})")
        
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

        # Check if any panel uses power×time fallback (no hw counters).
        # If ALL panels have hw counters, gap handling options are irrelevant.
        show_gap_options = True
        coordinator = self.hass.data.get(DOMAIN, {}).get(self.config_entry.entry_id)
        if coordinator and hasattr(coordinator, '_service') and coordinator._service:
            service = coordinator._service
            if hasattr(service, '_panel_has_hw_counters') and service._panel_has_hw_counters:
                # If every panel has hw counters, hide gap options
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
            vol.Optional(
                ENABLE_DECORA,
                default=current_options.get(ENABLE_DECORA, current_data.get(ENABLE_DECORA, ENABLE_DECORA_DEFAULT)),
            ): bool,
        }

        # Only show gap handling when at least one panel lacks hw counters
        if show_gap_options:
            options_schema[vol.Optional(
                GAP_HANDLING,
                default=current_options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT),
            )] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=[
                        selector.SelectOptionDict(value=value, label=label)
                        for value, label in GAP_HANDLING_LABELS.items()
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
                "log_parsed_data",
                default=current_options.get("log_parsed_data", False),
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
