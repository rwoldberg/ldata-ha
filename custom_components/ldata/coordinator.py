"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""

import asyncio
import logging

import aiohttp

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store

from .const import (
    DOMAIN, 
    LOGGER_NAME, 
    HA_INFORM_RATE, 
    HA_INFORM_RATE_DEFAULT, 
    HA_INFORM_RATE_MIN,
    WS_DETECTION_GRACE_PERIOD
)
from .ldata_service import LDATAService, LDATAAuthError

_LOGGER = logging.getLogger(LOGGER_NAME)

STORAGE_VERSION = 1

class LDATAUpdateCoordinator(DataUpdateCoordinator):
    """LDATAUpdateCoordinator to handle fetching new data about the LDATA module."""

    def __init__(
        self, hass: HomeAssistant, user, password, entry
    ) -> None:
        """Initialize the coordinator and set up the Controller object."""
        self._hass = hass
        self.user = user
        session = async_get_clientsession(hass)
        self._service = LDATAService(user, password, entry, session)
        self._available = True
        self.config_entry = entry
        self._websocket_task = None
        self._ct_poll_task = None
        self._debounce_timer = None
        self._websocket_connected = False
        self._websocket_ever_connected = False
        
        # Setup Home Assistant .storage Disk Persistence
        self._store = Store(hass, STORAGE_VERSION, f"{DOMAIN}_{entry.entry_id}_energy_data")
        self._disk_data_loaded = False

        # No polling interval — WebSocket + slow hourly sync handle updates
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
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
        
        # Start the slow poll loop for the hourly hardware True-Up
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
                _LOGGER.debug("[v%s] WebSocket reconnected", self._service.version)
            else:
                _LOGGER.debug("[v%s] WebSocket connected", self._service.version)
                self._websocket_ever_connected = True
                
            # FORCE START THE CONTINUOUS INTEGRATOR LOOP!
            self._handle_websocket_update("Connection Established")
            
        elif not connected and was_connected:
            _LOGGER.debug("[v%s] WebSocket disconnected", self._service.version)
            if self._debounce_timer:
                self._debounce_timer.cancel()
                self._debounce_timer = None

    async def async_shutdown(self):
        """Gracefully shutdown the WebSocket connection, tasks, and force-save to disk."""
        _LOGGER.debug("Shutting down LDATA coordinator")
        self._service._shutdown_requested = True
        
        # Force a hard drive save instantly upon shutdown
        if self._service.status_data:
            await self._store.async_save(self._service.status_data)
            _LOGGER.debug("Successfully saved LDATA accumulator persistence to disk on shutdown")
        
        if self._ct_poll_task:
            self._ct_poll_task.cancel()
            try:
                await self._ct_poll_task
            except asyncio.CancelledError:
                pass
        
        if self._websocket_task:
            self._websocket_task.cancel()
            try:
                await self._websocket_task
            except asyncio.CancelledError:
                pass
        
        if self._debounce_timer:
            self._debounce_timer.cancel()
            self._debounce_timer = None

    async def _ct_poll_loop(self):
        """Slow poll loop for the Hourly Hardware True-Up."""
        while not self._service.status_data and not self._service._shutdown_requested:
            await asyncio.sleep(5)
        
        await asyncio.sleep(WS_DETECTION_GRACE_PERIOD)
        
        _LOGGER.info(
            "[v%s] Slow poll loop starting (interval=3600s, panels needing CT sync: %s)",
            self._service.version, 
            [pid for pid, need in self._service._panel_needs_ct_poll.items() if need],
        )
        
        while not self._service._shutdown_requested:
            try:
                refreshed = False
                if await self._service.refresh_panel_data():
                    refreshed = True
                
                if self._service.needs_ct_poll:
                    if await self._service.refresh_ct_data():
                        refreshed = True
                
                if refreshed:
                    self._handle_websocket_update("Scheduled/REST")
                    
                await asyncio.sleep(3600)
                    
            except asyncio.CancelledError:
                break
            except LDATAAuthError as ex:
                _LOGGER.warning("[v%s] Auth error during slow poll: %s", self._service.version, ex)
                await asyncio.sleep(60)
            except Exception as ex:
                _LOGGER.warning("[v%s] Slow poll error: %s", self._service.version, ex)
                await asyncio.sleep(30)

    def _get_stored_data(self):
        """Helper function for the delayed disk save."""
        return self._service.status_data

    def _handle_websocket_update(self, source="Scheduled/REST"):
        if self._debounce_timer is None:
            inform_rate = max(
                HA_INFORM_RATE_MIN,
                self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
            )
            self._debounce_timer = self._hass.loop.call_later(
                inform_rate, 
                self._apply_debounced_update,
                source
            )

    def _apply_debounced_update(self, source="Scheduled/REST"):
        self._debounce_timer = None
        
        try:
            if hasattr(self._service, "advance_all_drift"):
                self._service.advance_all_drift()
                
            data = self._service.status_data
            if not data:
                return
            
            self._log_data_if_enabled(data, source)
            self.async_set_updated_data(data)
            
            # TRIGGER DISK SAVE: Write the memory state to hard drive automatically (debounced 60s)
            self._store.async_delay_save(self._get_stored_data, 60)
        
        except Exception as e:
            _LOGGER.error("[v%s] Error in debounced update: %s", self._service.version, e)
        
        finally:
            if self._websocket_connected:
                inform_rate = max(
                    HA_INFORM_RATE_MIN,
                    self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
                )
                self._debounce_timer = self._hass.loop.call_later(
                    inform_rate,
                    self._apply_debounced_update,
                    "WebSocket Loop"
                )

    def _log_data_if_enabled(self, data, source: str = ""):
        options = self.config_entry.options
        if options.get("log_parsed_data", False):
            redacted_data = self._redact_data(data)
            _LOGGER.warning("Leviton %s Parsed Data: %s", source, redacted_data)
        elif options.get("enable_specific_logging", False):
            if fields_to_log_str := options.get("log_fields", ""):
                fields_to_log = [f.strip() for f in fields_to_log_str.split(',') if f.strip()]
                log_output = {}
                if data:
                    for ct_id, ct_data in data.get('cts', {}).items():
                        for field in fields_to_log:
                            if field in ct_data:
                                log_output["CT_%s_%s" % (ct_id, field)] = ct_data[field]
                    for b_id, b_data in data.get('breakers', {}).items():
                        for field in fields_to_log:
                            if field in b_data:
                                log_output["Breaker_%s_%s" % (b_data.get('name', b_id), field)] = b_data[field]
                    for panel in data.get('panels', []):
                        for field in fields_to_log:
                            if field in panel:
                                log_output["Panel_%s_%s" % (panel.get('name', panel.get('id', '?')), field)] = panel[field]
                if log_output:
                    _LOGGER.warning("Leviton %s Selected Data: %s", source, log_output)

    _REDACT_KEYS = frozenset({
        "IP", "Token", "residenceId", "mac", "residentialRoomId",
        "id", "userId", "accountId", "auth_token", "refresh_token",
        "password", "serialNumber", "ttl", "created",
    })

    def _redact_data(self, data):
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                if key in self._REDACT_KEYS:
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
        
        # INTERCEPT STARTUP: Load previous math accumulators from hard drive before talking to cloud
        if not self._disk_data_loaded:
            try:
                stored = await self._store.async_load()
                if stored:
                    _LOGGER.info("Successfully recovered LDATA Riemann integrator state from disk.")
                    self._service.status_data = stored
            except Exception as ex:
                _LOGGER.warning("Failed to load LDATA disk persistence: %s", ex)
            self._disk_data_loaded = True

        if self._websocket_connected and self.data is not None:
            return self.data
        
        _LOGGER.debug("Fetching initial LDATA data")
        
        try:
            async with asyncio.timeout(30):
                returnData = await self._service.status()
                
            if returnData:
                self._store.async_delay_save(self._get_stored_data, 1)

            self._log_data_if_enabled(returnData, "API")
            return returnData

        except LDATAAuthError as ex:
            _LOGGER.warning("Authentication failed: %s. Please re-authenticate.", ex)
            raise ConfigEntryAuthFailed("Authentication failed: %s" % ex) from ex
        
        except aiohttp.ClientError as ex:
            _LOGGER.warning("Connection error communicating with LDATA: %s", ex)
            raise UpdateFailed("Connection error: %s" % ex) from ex

        except Exception as ex:
            self._available = False
            _LOGGER.warning("Unexpected error communicating with LDATA for %s: %s", self.user, ex)
            raise UpdateFailed("Error communicating with LDATA: %s" % ex) from ex

    @property
    def service(self) -> LDATAService:
        return self._service