"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""

import asyncio
from datetime import timedelta
import logging
import requests

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import DOMAIN, LOGGER_NAME
from .ldata_service import LDATAService, LDATAAuthError

_LOGGER = logging.getLogger(LOGGER_NAME)


class LDATAUpdateCoordinator(DataUpdateCoordinator):
    """LDATAUpdateCoordinator to handle fetching new data about the LDATA module."""

    def __init__(
        self, hass: HomeAssistant, user, password, update_interval, entry
    ) -> None:
        """Initialize the coordinator and set up the Controller object."""
        self._hass = hass
        self.user = user
        self._service = LDATAService(user, password, entry)
        self._available = True
        self.config_entry = entry

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
            config_entry=entry,
        )

    def _redact_data(self, data):
        """Redact sensitive fields from data for logging."""
        if isinstance(data, dict):
            # Create a new dict to avoid modifying the original data
            redacted = {}
            for key, value in data.items():
                # Check for the specific keys requested
                if key in ["IP", "Token", "residenceId", "mac", "residentialRoomId"]:
                    redacted[key] = "***REDACTED***"
                else:
                    redacted[key] = self._redact_data(value)
            return redacted
        elif isinstance(data, list):
            return [self._redact_data(item) for item in data]
        else:
            return data

    async def _async_update_data(self):
        """Fetch data from LDATA Controller."""
        try:
            async with asyncio.timeout(30):
                # This will now either return data or raise an Exception
                returnData = await self._hass.async_add_executor_job(
                    self._service.status  # Fetch new status
                )

            # --- Start of selective debug logging ---
            options = self.config_entry.options
            
            # Check if "Log All Raw Data" is enabled
            if options.get("log_all_raw", False):
                # Redact sensitive data before logging
                redacted_data = self._redact_data(returnData)
                _LOGGER.warning("Leviton API Full Data: %s", redacted_data)
            
            # Else, check if specific field logging is enabled AND if fields have been provided
            elif options.get("enable_specific_logging", False):
                if fields_to_log_str := options.get("log_fields", ""):
                    fields_to_log = [f.strip() for f in fields_to_log_str.split(',') if f.strip()]
                    log_output = {}

                    # Search for requested fields in the data payload
                    if returnData and returnData.get('cts'): # Add check for data
                        for ct_id, ct_data in returnData.get('cts', {}).items():
                            for field in fields_to_log:
                                if field in ct_data:
                                    key_name = f"CT_{ct_id}_{field}"
                                    log_output[key_name] = ct_data[field]
                    
                    if log_output:
                        _LOGGER.warning("Leviton Selected Raw Data: %s", log_output)
            # --- End of selective debug logging ---
            
            return returnData

        except LDATAAuthError as ex:
            # This is our specific auth failure
            _LOGGER.warning("Authentication failed: %s. Please re-authenticate.", ex)
            raise ConfigEntryAuthFailed(f"Authentication failed: {ex}") from ex
        
        except requests.exceptions.RequestException as ex:
            # This is a network/DNS/timeout error from ldata_service.
            # This is NOT an auth failure, just a temporary error.
            _LOGGER.warning("Connection error communicating with LDATA: %s", ex)
            raise UpdateFailed(f"Connection error: {ex}") from ex

        except Exception as ex:
            # This catches all other errors (e.g., "Could not get Account ID")
            self._available = False
            _LOGGER.warning(
                "Error communicating with LDATA for %s: %s", self.user, str(ex)
            )
            # This will result in the "Failed setup, will retry" message
            raise UpdateFailed(f"Error communicating with LDATA: {ex}") from ex

    @property
    def service(self) -> LDATAService:
        """Return the LDATA service."""
        return self._service
