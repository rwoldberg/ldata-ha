"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""

import asyncio
import logging
import time
import requests

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import DOMAIN, LOGGER_NAME, HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT, HA_INFORM_RATE_MIN, CT_POLL_INTERVAL
from .ldata_service import LDATAService, LDATAAuthError

_LOGGER = logging.getLogger(LOGGER_NAME)

# REST polling interval for breaker/CT data (seconds)
# This is a FALLBACK — only used when WS auto-detection confirms a panel
# does not deliver breaker data via WebSocket.
REST_POLL_INTERVAL = 30

# Grace period (seconds) before REST poll loops start actively polling.
# This gives the WebSocket time to connect, subscribe, and prove whether
# it delivers breaker data. If WS delivers breaker data within this window,
# REST polling stays disabled.
WS_DETECTION_GRACE_PERIOD = 45


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
        self._rest_poll_task = None
        self._ct_poll_task = None
        self._debounce_timer = None
        self._websocket_connected = False
        self._websocket_ever_connected = False

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            # No polling - WebSocket + REST polling handle updates
            update_interval=None,
            config_entry=entry,
        )
        
        # Start the WebSocket Listener — this is the PRIMARY data source
        self._websocket_task = self.config_entry.async_create_background_task(
            self._hass, 
            self._service.async_run_websocket(
                self._handle_websocket_update,
                self._handle_connection_change
            ),
            "ldata_websocket"
        )
        
        # Start the REST polling task as a FALLBACK for breaker/CT data.
        # WS-first: these loops wait for the WS auto-detection grace period
        # before polling. If WS delivers all data, they remain idle.
        self._rest_poll_task = self.config_entry.async_create_background_task(
            self._hass,
            self._rest_poll_loop(),
            "ldata_rest_poll"
        )
        
        # Start the fast CT-only poll as a FALLBACK for energy data.
        # Only activates for panels where WS doesn't deliver energy counters.
        self._ct_poll_task = self.config_entry.async_create_background_task(
            self._hass,
            self._ct_poll_loop(),
            "ldata_ct_poll"
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
        """Gracefully shutdown the WebSocket connection and REST polling."""
        _LOGGER.debug("Shutting down LDATA coordinator")
        
        # Signal the WebSocket to stop
        self._service._shutdown_requested = True
        
        # Cancel the REST polling task
        if self._rest_poll_task:
            self._rest_poll_task.cancel()
            try:
                await self._rest_poll_task
            except asyncio.CancelledError:
                pass
        
        # Cancel the CT polling task
        if self._ct_poll_task:
            self._ct_poll_task.cancel()
            try:
                await self._ct_poll_task
            except asyncio.CancelledError:
                pass
        
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

    async def _rest_poll_loop(self):
        """Periodically poll the REST API for fresh breaker and CT data.
        
        WS-FIRST STRATEGY: This loop is a FALLBACK. It waits for the WebSocket
        auto-detection grace period before starting, giving WS time to prove
        it can deliver breaker data. Only panels where WS demonstrably fails
        to deliver breaker data will be polled via REST.
        """
        # Wait for initial data to be available before starting the poll loop
        while not self._service.status_data and not self._service._shutdown_requested:
            await asyncio.sleep(5)
        
        # WS-first: wait for the full detection grace period.
        # During this time, the WebSocket is connecting, subscribing, and
        # the auto-detection in _update_from_websocket is tracking whether
        # IotWhem messages contain breaker data. If WS delivers breaker data,
        # _panel_needs_rest_poll stays False and this loop does nothing.
        _LOGGER.debug(
            f"[v{self._service.version}] REST poll loop: waiting {WS_DETECTION_GRACE_PERIOD}s "
            f"for WebSocket auto-detection before enabling fallback polling"
        )
        await asyncio.sleep(WS_DETECTION_GRACE_PERIOD)
        
        if self._service.needs_rest_poll:
            _LOGGER.info(
                f"[v{self._service.version}] REST poll loop: WS did not deliver breaker data for panels "
                f"{[pid for pid, need in self._service._panel_needs_rest_poll.items() if need]} — "
                f"enabling REST polling as fallback"
            )
        else:
            _LOGGER.debug(
                f"[v{self._service.version}] REST poll loop: all panels receiving breaker data via WS — "
                f"REST polling not needed (will continue monitoring)"
            )
        
        while not self._service._shutdown_requested:
            try:
                poll_interval = max(
                    HA_INFORM_RATE_MIN,
                    self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
                )
                
                await asyncio.sleep(poll_interval)
                
                if self._service._shutdown_requested:
                    break
                
                # WS-first: only run the REST poll if at least one panel needs it.
                # This check is dynamic — if WS starts delivering breaker data for
                # a panel that was previously REST-polled, polling stops for that panel.
                if not self._service.needs_rest_poll:
                    continue
                
                # Run the blocking REST calls in executor
                refreshed = await self._hass.async_add_executor_job(
                    self._service.refresh_breaker_data
                )
                
                if refreshed:
                    # Trigger a debounced update to HA
                    self._handle_websocket_update()
                    
            except asyncio.CancelledError:
                break
            except LDATAAuthError as ex:
                _LOGGER.warning(f"[v{self._service.version}] Auth error during REST poll: {ex}")
                await asyncio.sleep(60)
            except Exception as ex:
                _LOGGER.warning(f"[v{self._service.version}] REST poll error: {ex}")
                await asyncio.sleep(30)
        
        _LOGGER.debug(f"[v{self._service.version}] REST poll loop stopped")

    async def _ct_poll_loop(self):
        """Fast poll loop for CT energy data on panels where WS doesn't deliver it.
        
        WS-FIRST STRATEGY: This loop is a FALLBACK. It waits for the WebSocket
        auto-detection grace period. Only panels where WS fails to deliver
        energyConsumption/energyImport will be polled. If WS delivers all CT
        data, this loop does nothing.
        """
        # Wait for initial data to be available
        while not self._service.status_data and not self._service._shutdown_requested:
            await asyncio.sleep(5)
        
        # WS-first: wait for the full detection grace period + a bit extra
        # so the REST poll loop detects first
        _LOGGER.debug(
            f"[v{self._service.version}] CT poll loop: waiting {WS_DETECTION_GRACE_PERIOD + 5}s "
            f"for WebSocket auto-detection before enabling fallback CT polling"
        )
        await asyncio.sleep(WS_DETECTION_GRACE_PERIOD + 5)
        
        if self._service.needs_rest_poll:
            _LOGGER.info(
                f"[v{self._service.version}] CT poll loop started as fallback "
                f"(interval={CT_POLL_INTERVAL}s, panels: "
                f"{[pid for pid, need in self._service._panel_needs_rest_poll.items() if need]})"
            )
        else:
            _LOGGER.debug(f"[v{self._service.version}] CT poll loop started (no panels need CT polling, monitoring...)")
        
        while not self._service._shutdown_requested:
            try:
                await asyncio.sleep(CT_POLL_INTERVAL)
                
                if self._service._shutdown_requested:
                    break
                
                # WS-first: only run if at least one panel needs REST polling
                if not self._service.needs_rest_poll:
                    continue
                
                # Run the lightweight CT-only REST call in executor
                refreshed = await self._hass.async_add_executor_job(
                    self._service.refresh_ct_data
                )
                
                if refreshed:
                    # Trigger a debounced update to HA
                    self._handle_websocket_update()
                    
            except asyncio.CancelledError:
                break
            except LDATAAuthError as ex:
                _LOGGER.warning(f"[v{self._service.version}] Auth error during CT poll: {ex}")
                await asyncio.sleep(60)
            except Exception as ex:
                _LOGGER.warning(f"[v{self._service.version}] CT poll error: {ex}")
                await asyncio.sleep(30)
        
        _LOGGER.debug(f"[v{self._service.version}] CT poll loop stopped")

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
        
        WebSocket is the PRIMARY data source. This method is only called for
        initial data fetch at startup. After that, WebSocket handles all updates,
        with REST polling as a fallback only for panels where WS doesn't deliver
        breaker/CT data.
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
