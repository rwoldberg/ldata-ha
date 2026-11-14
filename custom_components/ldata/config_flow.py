"""Config flow for Leviton LDATA integration."""
from __future__ import annotations

import logging
from typing import Any, Mapping

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import section
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import selector

from .const import (
    DOMAIN,
    LOGGER_NAME,
    ALLOW_BREAKER_CONTROL,
    ALLOW_BREAKER_CONTROL_DEFAULT,
    ALLOW_LED_BLINK,
    ALLOW_LED_BLINK_DEFAULT,
    ENABLE_DECORA,
    ENABLE_DECORA_DEFAULT,
    SHOW_SIDEBAR_PANEL,
    SHOW_SIDEBAR_PANEL_DEFAULT,
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
from .sub_panels import NOT_FED, SUB_PANELS, looped, sub_panel_feeds

_LOGGER = logging.getLogger(LOGGER_NAME)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
        vol.Required("three_phase"): bool,
        vol.Required("allow_breaker_control"): bool,
        vol.Required(ALLOW_LED_BLINK, default=ALLOW_LED_BLINK_DEFAULT): bool,
        vol.Required(ENABLE_DECORA, default=ENABLE_DECORA_DEFAULT): bool,
        vol.Required(SHOW_SIDEBAR_PANEL, default=SHOW_SIDEBAR_PANEL_DEFAULT): bool,
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
                vol.Required(ALLOW_LED_BLINK, default=self.user_data.get(ALLOW_LED_BLINK, ALLOW_LED_BLINK_DEFAULT)): bool,
                vol.Required(ENABLE_DECORA, default=self.user_data.get(ENABLE_DECORA, ENABLE_DECORA_DEFAULT)): bool,
                vol.Required(SHOW_SIDEBAR_PANEL, default=self.user_data.get(SHOW_SIDEBAR_PANEL, SHOW_SIDEBAR_PANEL_DEFAULT)): bool,
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


class _SubPanelSection:
    """The options form's "Sub-panels" section.

    One field for each load center, holding the breaker in another load
    center that feeds it. Home Assistant labels a field it has no translation
    for with the field's own name, so each field is named after its load
    center. Offered only while Leviton reports two or more load centers.
    """

    def __init__(self, coordinator: Any, options: Mapping[str, Any]) -> None:
        data = getattr(coordinator, "data", None) or {}
        panels = sorted(
            (panel for panel in data.get("panels", []) if panel.get("id")),
            key=lambda panel: (str(panel.get("name") or "").casefold(), str(panel["id"])),
        )
        self.stored = sub_panel_feeds(options)
        self.fields: dict[str, str] = {}  # field -> the load center it is about
        self._choices: dict[str, tuple[str, int]] = {}  # choice -> (feeding panel, position)
        self._offered: dict[str, list[selector.SelectOptionDict]] = {}
        if len(panels) < 2:
            return

        names: dict[str, str] = {}
        for panel in panels:
            name = str(panel.get("name") or panel["id"])
            if name in names.values():
                name = f"{name} ({panel['id']})"
            names[panel["id"]] = name
            self.fields[name] = panel["id"]

        breakers: dict[str, list[selector.SelectOptionDict]] = {}
        for panel in panels:
            found = [
                breaker
                for breaker in (data.get("breakers") or {}).values()
                if breaker.get("panel_id") == panel["id"]
            ] + list(panel.get("dumb_breakers") or [])
            listed = []
            for breaker in found:
                try:
                    position = int(breaker.get("position"))
                except (TypeError, ValueError):
                    continue
                listed.append((position, breaker))
            listed.sort(key=lambda item: item[0])
            breakers[panel["id"]] = [
                self._choice(panel["id"], names[panel["id"]], position, breaker)
                for position, breaker in listed
            ]

        none = selector.SelectOptionDict(value=NOT_FED, label="Not a sub-panel")
        for sub_id in names:
            offered = [none]
            for panel_id in names:
                if panel_id != sub_id:
                    offered.extend(breakers[panel_id])
            # A stored link to a breaker Leviton no longer lists stays on
            # offer, or saving the form for another reason would drop it.
            feed = self.stored.get(sub_id)
            if feed and feed[0] in names and self._value(*feed) not in self._choices:
                offered.append(self._choice(feed[0], names[feed[0]], feed[1], {}))
            self._offered[sub_id] = offered

    @staticmethod
    def _value(panel_id: str, position: int) -> str:
        return f"{panel_id}|{position}"

    def _choice(
        self, panel_id: str, panel_name: str, position: int, breaker: Mapping[str, Any]
    ) -> selector.SelectOptionDict:
        value = self._value(panel_id, position)
        self._choices[value] = (panel_id, position)
        two_pole = str(breaker.get("poles")) == "2"
        parts = [panel_name, f"{position}/{position + 2}" if two_pole else str(position)]
        if breaker.get("name"):
            parts.append(str(breaker["name"]))
        if breaker.get("rating"):
            parts.append(f"{breaker['rating']} A")
        return selector.SelectOptionDict(value=value, label=" · ".join(parts))

    def schema(self, chosen: Mapping[str, Any] | None) -> dict[Any, Any]:
        """Return the section for the form, or nothing when it does not apply."""
        if not self.fields:
            return {}
        fields = {}
        for field, sub_id in self.fields.items():
            feed = self.stored.get(sub_id)
            default = (chosen or {}).get(field) or (self._value(*feed) if feed else NOT_FED)
            if default not in {option["value"] for option in self._offered[sub_id]}:
                default = NOT_FED
            fields[vol.Required(field, default=default)] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=self._offered[sub_id],
                    mode=selector.SelectSelectorMode.DROPDOWN,
                    # Names the "none" choice; a breaker keeps its own label.
                    translation_key="sub_panel_feed",
                )
            )
        linked = any(sub_id in self.stored for sub_id in self.fields.values())
        # Optional: Home Assistant's form always sends the section, but
        # something that posts only the options it wants to change does not.
        return {
            vol.Optional(SUB_PANELS): section(
                vol.Schema(fields), {"collapsed": not (linked or chosen)}
            )
        }

    def read(self, chosen: Mapping[str, Any] | None) -> dict[str, tuple[str, int]]:
        """Return every feed after the form: what was chosen, and what it did not show."""
        shown = set(self.fields.values())
        feeds = {sub_id: feed for sub_id, feed in self.stored.items() if sub_id not in shown}
        for field, sub_id in self.fields.items():
            feed = self._choices.get((chosen or {}).get(field, NOT_FED))
            if feed and feed[0] != sub_id:
                feeds[sub_id] = feed
        return feeds


class OptionsFlow(config_entries.OptionsFlow):
    """Handle the options flow for Leviton LDATA."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""

    async def async_step_init(self, user_input=None) -> ConfigFlowResult:
        """Return the options form."""
        coordinator = self.hass.data.get(DOMAIN, {}).get(self.config_entry.entry_id)
        sub_panels = _SubPanelSection(coordinator, self.config_entry.options)
        errors: dict[str, str] = {}
        chosen_feeds = None
        if user_input is not None:
            user_input = dict(user_input)
            # Home Assistant's frontend leaves an emptied optional text field
            # out of the submission, so a missing log_fields means the user
            # cleared it.
            user_input.setdefault("log_fields", "")
            if not user_input["log_fields"].strip():
                user_input["log_fields"] = ""
            # The section is only on the form while Leviton reports two or
            # more load centers; without it, or when a submission leaves it
            # out, the stored links are left alone.
            chosen_feeds = user_input.pop(SUB_PANELS, None)
            if sub_panels.fields and chosen_feeds is not None:
                feeds = sub_panels.read(chosen_feeds)
                if looped(feeds):
                    errors["base"] = "sub_panel_loop"
                else:
                    user_input[SUB_PANELS] = {
                        sub_id: {"panel": panel_id, "position": position}
                        for sub_id, (panel_id, position) in feeds.items()
                    }
            # The entry's options also hold keys this form does not show: the
            # sensor platform's import-sensor classifications
            # (confirmed_solar_import_uids, suppressed_import_uids), and the gap
            # options when they are hidden. async_create_entry replaces all of
            # entry.options, so start from the current options and apply the
            # form values on top.
            if not errors:
                return self.async_create_entry(
                    title="", data={**self.config_entry.options, **user_input}
                )

        # After a refused submission the form comes back as it was filled in.
        current_options = {**self.config_entry.options, **(user_input or {})}
        current_data = self.config_entry.data

        # Check if any panel uses power×time fallback (no hw counters).
        # If ALL panels have hw counters, gap handling options are irrelevant.
        show_gap_options = True
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
                ALLOW_LED_BLINK,
                default=current_options.get(ALLOW_LED_BLINK, current_data.get(ALLOW_LED_BLINK, ALLOW_LED_BLINK_DEFAULT)),
            ): bool,
            vol.Optional(
                ENABLE_DECORA,
                default=current_options.get(ENABLE_DECORA, current_data.get(ENABLE_DECORA, ENABLE_DECORA_DEFAULT)),
            ): bool,
            vol.Optional(
                SHOW_SIDEBAR_PANEL,
                default=current_options.get(SHOW_SIDEBAR_PANEL, current_data.get(SHOW_SIDEBAR_PANEL, SHOW_SIDEBAR_PANEL_DEFAULT)),
            ): bool,
        }
        options_schema.update(sub_panels.schema(chosen_feeds))

        # Only show gap handling when at least one panel lacks hw counters
        if show_gap_options:
            options_schema[vol.Optional(
                GAP_HANDLING,
                default=current_options.get(GAP_HANDLING, GAP_HANDLING_DEFAULT),
            )] = selector.SelectSelector(
                selector.SelectSelectorConfig(
                    # The translations (selector.gap_handling) name the
                    # options; these English labels show where a language
                    # has none.
                    options=[
                        selector.SelectOptionDict(value=value, label=label)
                        for value, label in GAP_HANDLING_LABELS.items()
                    ],
                    mode=selector.SelectSelectorMode.DROPDOWN,
                    translation_key=GAP_HANDLING,
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
            # suggested_value, not default: a default would refill the stored
            # value when the user clears the field.
            vol.Optional(
                "log_fields",
                description={"suggested_value": current_options.get("log_fields", "")},
            ): selector.TextSelector(selector.TextSelectorConfig(multiline=True)),
        })

        return self.async_show_form(
            step_id="init", data_schema=vol.Schema(options_schema), errors=errors
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
