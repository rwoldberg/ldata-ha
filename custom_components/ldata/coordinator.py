"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""

import asyncio
import logging
import requests

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import DOMAIN, LOGGER_NAME, HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT, HA_INFORM_RATE_MIN
from .ldata_service import LDATAService, LDATAAuthError

_LOGGER = logging.getLogger(LOGGER_NAME)


class LDATAUpdateCoordinator(DataUpdateCoordinator):
    """LDATAUpdateCoordinator to handle fetching new data about the LDATA module."""

    def __init__(
        self, hass: HomeAssistant, user, password, entry
    ) -> None:
        """Initialize the coordinator and set up the Controller object."""
        self._hass = hass
        self.user = user
        self._service = LDATAService(user, password, entry)
        self._available = True
        self.config_entry = entry
        self._websocket_task = None
        self._debounce_timer = None
        self._websocket_connected = False
        self._websocket_ever_connected = False

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            # No polling - WebSocket is the primary data source
            update_interval=None,
            config_entry=entry,
        )
        
        # Start the WebSocket Listener in the background
        self._websocket_task = self.config_entry.async_create_background_task(
            self._hass, 
            self._service.async_run_websocket(
                self._handle_websocket_update,
                self._handle_connection_change
            ),
            "ldata_websocket"
        )

    def _handle_connection_change(self, connected: bool):
        """Handle WebSocket connection state changes."""
        was_connected = self._websocket_connected
        self._websocket_connected = connected
        
        if connected and not was_connected:
            if self._websocket_ever_connected:
                _LOGGER.debug(f"[v{self._service.version}] WebSocket reconnected")
            else:
                _LOGGER.debug(f"[v{self._service.version}] WebSocket connected")
                self._websocket_ever_connected = True
        elif not connected and was_connected:
            _LOGGER.debug(f"[v{self._service.version}] WebSocket disconnected")
            # Stop the self-re-arming timer so we don't push stale data
            if self._debounce_timer:
                self._debounce_timer.cancel()
                self._debounce_timer = None

    async def async_shutdown(self):
        """Gracefully shutdown the WebSocket connection."""
        _LOGGER.debug("Shutting down LDATA coordinator")
        
        # Signal the WebSocket to stop
        self._service._shutdown_requested = True
        
        # Cancel the WebSocket task if it exists
        if self._websocket_task:
            self._websocket_task.cancel()
            try:
                await self._websocket_task
            except asyncio.CancelledError:
                pass
        
        # Cancel any pending debounce timer
        if self._debounce_timer:
            self._debounce_timer.cancel()
            self._debounce_timer = None

    def _handle_websocket_update(self):
        """Callback for when WebSocket receives new data.
        
        Starts the debounce timer if not already running. Once started, the
        timer self-re-arms in _apply_debounced_update, so this only needs to
        kick-start the first cycle (or restart after a disconnect).
        """
        if self._debounce_timer is None:
            inform_rate = max(
                HA_INFORM_RATE_MIN,
                self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
            )
            
            self._debounce_timer = self._hass.loop.call_later(
                inform_rate, 
                self._apply_debounced_update
            )

    def _apply_debounced_update(self):
        """Apply the aggregated data update to Home Assistant.
        
        This runs on a steady cadence (every ha_inform_rate seconds) once the
        first WebSocket message is received. The debounce timer self-re-arms
        so updates continue even if no new WS messages arrive during a cycle.
        """
        self._debounce_timer = None
        
        try:
            data = self._service.status_data
            
            if not data:
                return
            
            # Log data if enabled
            self._log_data_if_enabled(data, "WebSocket")
            
            # Retrieve the current inform rate
            inform_rate = max(
                HA_INFORM_RATE_MIN,
                self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
            )
            
            # Log the update with useful context
            breaker_count = len(data.get("breakers", {})) if data else 0
            ct_count = len(data.get("cts", {})) if data else 0
            _LOGGER.debug(
                f"[v{self._service.version}] Pushing ({inform_rate}s) update to HA: {breaker_count} breakers, {ct_count} CTs"
            )
            
            # This notifies all sensors to refresh from the cache
            self.async_set_updated_data(data)
        
        except Exception as e:
            _LOGGER.error(f"[v{self._service.version}] Error in debounced update: {e}")
        
        finally:
            # ALWAYS re-arm the timer so updates never stall
            if self._websocket_connected:
                inform_rate = max(
                    HA_INFORM_RATE_MIN,
                    self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
                )
                self._debounce_timer = self._hass.loop.call_later(
                    inform_rate,
                    self._apply_debounced_update
                )

    def _log_data_if_enabled(self, data, source: str = ""):
        """Log data based on user options."""
        options = self.config_entry.options
        
        # Check if "Log All Raw Data" is enabled
        if options.get("log_all_raw", False):
            redacted_data = self._redact_data(data)
            _LOGGER.warning("Leviton %s Full Data: %s", source, redacted_data)
        
        # Check if specific field logging is enabled
        elif options.get("enable_specific_logging", False):
            if fields_to_log_str := options.get("log_fields", ""):
                fields_to_log = [f.strip() for f in fields_to_log_str.split(',') if f.strip()]
                log_output = {}
                if data and data.get('cts'):
                    for ct_id, ct_data in data.get('cts', {}).items():
                        for field in fields_to_log:
                            if field in ct_data:
                                log_output[f"CT_{ct_id}_{field}"] = ct_data[field]
                
                if log_output:
                    _LOGGER.warning("Leviton %s Selected Data: %s", source, log_output)

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
        """Fetch data from LDATA Controller.
        
        WebSocket is the primary data source. This method is only called for
        initial data fetch at startup. After that, WebSocket handles all updates.
        """
        # If WebSocket is connected and we have data, skip - WebSocket handles updates
        if self._websocket_connected and self.data is not None:
            return self.data
        
        # Initial fetch or WebSocket not yet connected
        _LOGGER.debug("Fetching initial LDATA data")
        
        try:
            async with asyncio.timeout(30):
                # This will now either return data or raise an Exception
                returnData = await self._hass.async_add_executor_job(
                    self._service.status  # Fetch new status
                )

            # Log data if enabled
            self._log_data_if_enabled(returnData, "API")
            
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
                "Unexpected error communicating with LDATA for %s: %s", self.user, ex
            )
            # This will result in the "Failed setup, will retry" message
            raise UpdateFailed(f"Error communicating with LDATA: {ex}") from ex

    @property
    def service(self) -> LDATAService:
        """Return the LDATA service."""
        return self._service
