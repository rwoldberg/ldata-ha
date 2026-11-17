"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""

import asyncio
import logging
import time
import requests

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import DOMAIN, LOGGER_NAME, HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT, HA_INFORM_RATE_MIN, AUTH_RENEWAL_BACKOFF, AUTH_RENEWAL_BACKOFF_MAX, BREAKER_POLL_INTERVAL, CT_POLL_INTERVAL, PANEL_STATUS_POLL_INTERVAL, STATUS_TIMEOUT
from .ldata_service import LDATAService, LDATAAuthError, TwoFactorRequired, _safe_error
_LOGGER = logging.getLogger(LOGGER_NAME)

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
        self.config_entry = entry
        self._websocket_task = None
        self._rest_poll_task = None
        self._ct_poll_task = None
        self._panel_status_task = None
        self._debounce_timer = None
        self._websocket_connected = False
        self._websocket_ever_connected = False
        # Token renewal after setup, see _async_auth_failed.
        self._auth_lock = asyncio.Lock()
        self._auth_retry_at = 0.0
        self._auth_backoff = AUTH_RENEWAL_BACKOFF
        # Set when Leviton refused the stored credentials themselves; only
        # the reauth flow (which reloads the entry) can clear it.
        self._auth_failed = False

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
                self._handle_connection_change,
                self._handle_decora_websocket_update,
                self._handle_websocket_auth_rejected,
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

        # Re-read each panel's cloud connection state over REST. An offline
        # panel sends no WebSocket data, so this is the only way its
        # "connected" flag (and the Cloud Connected sensor) can change.
        self._panel_status_task = self.config_entry.async_create_background_task(
            self._hass,
            self._panel_status_poll_loop(),
            "ldata_panel_status_poll"
        )

    @callback
    def _handle_websocket_auth_rejected(self) -> None:
        """Renew the token after Leviton rejected the WebSocket login."""
        self.config_entry.async_create_background_task(
            self._hass,
            self._async_auth_failed("WebSocket login"),
            "ldata_auth_renewal",
        )

    async def _async_auth_failed(self, source: str) -> None:
        """Log in again with the stored credentials after Leviton refused the token.

        Leviton tokens expire, and a password change revokes them. Nothing
        else renews one after setup: status() falls back to the stored
        credentials, but it only runs at setup and on a refresh requested
        while the WebSocket is down. Without this the WebSocket retried the
        refused token and the REST polls kept failing, while every entity
        stayed available showing frozen values.

        Several loops report the same refusal, so reports while a login is
        under way are dropped, and after a login the next one waits for
        _auth_retry_at, backing off while logins keep failing. If Leviton
        refuses the credentials themselves, or the account now needs a 2FA
        code, nothing here can fix it: that starts Home Assistant's reauth
        flow, and the entities go unavailable until it completes.
        """
        if self._auth_failed or self._auth_lock.locked() or self._service._shutdown_requested:
            return
        async with self._auth_lock:
            if time.monotonic() < self._auth_retry_at:
                return
            _LOGGER.warning(
                f"[v{self._service.version}] Leviton refused the stored token ({source}); "
                f"logging in again with the stored credentials"
            )
            try:
                await self._hass.async_add_executor_job(self._service.auth_with_credentials)
            except (LDATAAuthError, TwoFactorRequired):
                self._auth_failed = True
                # An empty token stops the WebSocket and the REST polls from
                # retrying one Leviton refuses; reauth reloads the entry.
                self._service.clear_tokens()
                _LOGGER.error(
                    f"[v{self._service.version}] Leviton refused the stored credentials, or the "
                    f"account now needs a 2FA code; please reauthenticate the integration"
                )
                self.async_set_update_error(
                    UpdateFailed("Leviton refused the stored credentials")
                )
                self.config_entry.async_start_reauth(self._hass)
                return
            except Exception as ex:  # pylint: disable=broad-except
                # The login service could not be reached or failed; try again later.
                self._auth_retry_at = time.monotonic() + self._auth_backoff
                _LOGGER.warning(
                    f"[v{self._service.version}] Logging in again failed ({_safe_error(ex)}); "
                    f"next attempt in {self._auth_backoff:.0f}s"
                )
                self._auth_backoff = min(self._auth_backoff * 2, AUTH_RENEWAL_BACKOFF_MAX)
                if not self._websocket_connected:
                    # No data is arriving: show that instead of frozen values.
                    self.async_set_update_error(
                        UpdateFailed("Leviton refused the stored token and logging in again failed")
                    )
                return

            self._auth_backoff = AUTH_RENEWAL_BACKOFF
            self._auth_retry_at = time.monotonic() + AUTH_RENEWAL_BACKOFF
            self._persist_refreshed_tokens()
            _LOGGER.info(f"[v{self._service.version}] Logged in again; using the new token")
            if not self.last_update_success and self._service.status_data:
                self.async_set_updated_data(self._service.status_data)

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
            # Restart the push cadence that the disconnect branch below
            # cancelled. Without this, HA receives nothing until new WS data
            # arrives — which never happens while the panel is offline.
            self._handle_websocket_update()
        elif not connected and was_connected:
            _LOGGER.debug(f"[v{self._service.version}] WebSocket disconnected")
            # Stop the self-re-arming timer so we don't push stale data
            if self._debounce_timer:
                self._debounce_timer.cancel()
                self._debounce_timer = None

    async def async_shutdown(self):
        """Gracefully shutdown the WebSocket connection and REST polling."""
        _LOGGER.debug("Shutting down LDATA coordinator")

        # Let DataUpdateCoordinator cancel its own pending work too. After
        # async_request_refresh (fan/light/switch/select commands) its
        # request-refresh debouncer keeps a cooldown timer, which refreshes
        # again if a second request came in during the cooldown. Left
        # running past this shutdown, that refresh finds the WebSocket
        # disconnected and fetches status over REST for an unloaded entry.
        await super().async_shutdown()

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
        
        # Cancel the panel status polling task
        if self._panel_status_task:
            self._panel_status_task.cancel()
            try:
                await self._panel_status_task
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

    def _inform_rate(self) -> float:
        """Return the configured HA update cadence, clamped to the allowed minimum."""
        return max(
            HA_INFORM_RATE_MIN,
            self.config_entry.options.get(HA_INFORM_RATE, HA_INFORM_RATE_DEFAULT)
        )

    def _breaker_poll_interval(self) -> float:
        """Return the breaker REST poll interval: its own, or the inform rate if longer.

        See BREAKER_POLL_INTERVAL. A shorter inform rate no longer makes the
        poll toggle the panels' bandwidth more often.
        """
        return max(BREAKER_POLL_INTERVAL, self._inform_rate())

    async def _fallback_poll_loop(self, *, loop_name, get_interval, needs_poll, fetch, merge):
        """Shared sleep/refresh/exception scaffolding for the REST poll loops.

        Each loop sleeps for `get_interval()`, bails out on shutdown, skips the
        cycle if `needs_poll()` is False, otherwise runs `fetch` in the
        executor and `merge` on the event loop, and pushes a debounced update
        if the merge applied anything. The merge runs here, not in the
        executor, so it applies the result to the status_data the WebSocket
        has kept updating while the fetch ran, instead of writing back a copy
        taken before it.
        """
        while not self._service._shutdown_requested:
            try:
                await asyncio.sleep(get_interval())

                if self._service._shutdown_requested:
                    break

                if not needs_poll():
                    continue

                fetched = await self._hass.async_add_executor_job(fetch)

                if merge(fetched):
                    self._handle_websocket_update()

            except asyncio.CancelledError:
                break
            except LDATAAuthError as ex:
                _LOGGER.warning(f"[v{self._service.version}] {loop_name} auth error: {ex}")
                await self._async_auth_failed(loop_name)
                await asyncio.sleep(60)
            except Exception as ex:
                _LOGGER.warning(f"[v{self._service.version}] {loop_name} error: {_safe_error(ex)}")
                await asyncio.sleep(30)

        _LOGGER.debug(f"[v{self._service.version}] {loop_name} loop stopped")

    async def _rest_poll_loop(self):
        """Periodically poll the REST API for fresh breaker data.

        WS-FIRST STRATEGY: This loop is a FALLBACK. It waits for the WebSocket
        auto-detection grace period before starting. Only panels where WS
        demonstrably fails to deliver breaker data will be polled via REST.

        On panels with hardware energy counters (firmware 2.0+), daily energy
        uses hardware counters and this poll is only needed for power/current
        freshness. On older firmware, this poll is critical for daily energy
        (power×time integration).
        """
        # Wait for initial data
        while not self._service.status_data and not self._service._shutdown_requested:
            await asyncio.sleep(5)

        # Wait for WS auto-detection grace period
        _LOGGER.debug(
            f"[v{self._service.version}] REST poll loop: waiting {WS_DETECTION_GRACE_PERIOD}s "
            f"for WebSocket auto-detection before enabling fallback polling"
        )
        await asyncio.sleep(WS_DETECTION_GRACE_PERIOD)

        if self._service.needs_breaker_poll:
            _LOGGER.info(
                f"[v{self._service.version}] REST poll loop: enabling breaker energy polling for panels "
                f"{[pid for pid, need in self._service._panel_needs_breaker_poll.items() if need]} — "
                f"energyConsumption/energyImport only arrive via REST (not WebSocket)"
            )
        else:
            _LOGGER.debug(
                f"[v{self._service.version}] REST poll loop: no panels with breakers found — "
                f"REST polling not needed"
            )

        await self._fallback_poll_loop(
            loop_name="REST poll",
            get_interval=self._breaker_poll_interval,
            needs_poll=lambda: self._service.needs_breaker_poll,
            fetch=self._service.fetch_breaker_poll,
            merge=self._service.merge_rest_poll,
        )

    async def _ct_poll_loop(self):
        """Poll loop for CT energy data.

        CT energy counters require a bandwidth toggle (1→0→1) to refresh.
        This only runs for panels that have CTs (set during parse_panels).
        """
        # Wait for initial data to be available
        while not self._service.status_data and not self._service._shutdown_requested:
            await asyncio.sleep(5)

        # Brief startup delay to let WS connect first
        await asyncio.sleep(10)

        if self._service.needs_rest_poll:
            _LOGGER.info(
                f"[v{self._service.version}] CT poll loop started "
                f"(interval={CT_POLL_INTERVAL}s, panels with CTs: "
                f"{[pid for pid, need in self._service._panel_needs_rest_poll.items() if need]})"
            )
        else:
            _LOGGER.debug(f"[v{self._service.version}] CT poll loop: no panels have CTs, monitoring...")

        await self._fallback_poll_loop(
            loop_name="CT poll",
            get_interval=lambda: CT_POLL_INTERVAL,
            needs_poll=lambda: self._service.needs_rest_poll,
            fetch=self._service.fetch_ct_poll,
            merge=self._service.merge_rest_poll,
        )

    async def _panel_status_poll_loop(self):
        """Poll each panel's cloud connection state and push an update when it changes."""
        while not self._service.status_data and not self._service._shutdown_requested:
            await asyncio.sleep(5)

        await self._fallback_poll_loop(
            loop_name="Panel status poll",
            get_interval=lambda: PANEL_STATUS_POLL_INTERVAL,
            needs_poll=lambda: True,
            fetch=self._service.fetch_panel_status,
            merge=self._service.merge_panel_status,
        )

    def _handle_websocket_update(self):
        """Callback for when WebSocket receives new data.
        
        Starts the debounce timer if not already running. Once started, the
        timer self-re-arms in _apply_debounced_update, so this only needs to
        kick-start the first cycle (or restart after a disconnect).
        """
        if self._debounce_timer is None:
            self._debounce_timer = self._hass.loop.call_later(
                self._inform_rate(),
                self._apply_debounced_update
            )

    def _apply_debounced_update(self):
        """Apply the aggregated data update to Home Assistant.
        
        This runs on a steady cadence (every ha_inform_rate seconds) once the
        first WebSocket message is received. The debounce timer self-re-arms
        so updates continue even if no new WS messages arrive during a cycle.
        """
        self._debounce_timer = None
        inform_rate = self._inform_rate()

        try:
            data = self._service.status_data

            # While the credentials are refused, a socket that is still open
            # must not make the entities available again (see
            # _async_auth_failed).
            if not data or self._auth_failed:
                return

            # Log data if enabled
            self._log_data_if_enabled(data, "WebSocket")

            # Log the update with useful context
            breaker_count = len(data.get("breakers", {}))
            ct_count = len(data.get("cts", {}))
            _LOGGER.debug(
                f"[v{self._service.version}] Pushing ({inform_rate}s) update to HA: {breaker_count} breakers, {ct_count} CTs"
            )

            # This notifies all sensors to refresh from the cache
            self.async_set_updated_data(data)

        except Exception as e:
            _LOGGER.error(f"[v{self._service.version}] Error in debounced update: {_safe_error(e)}")

        finally:
            # ALWAYS re-arm the timer so updates never stall, unless the
            # coordinator is shutting down — otherwise a re-arm racing with
            # async_shutdown() (which cancels self._debounce_timer captured
            # before this new one is assigned) can leak a timer that fires
            # after shutdown.
            if self._websocket_connected and not self._service._shutdown_requested:
                self._debounce_timer = self._hass.loop.call_later(
                    inform_rate,
                    self._apply_debounced_update
                )

    def _handle_decora_websocket_update(self):
        """Callback for Decora IotSwitch WebSocket data — immediate push, no debounce.

        Unlike breaker/CT updates (which go through the debounce timer above
        to respect HA_INFORM_RATE), Decora state changes push immediately —
        these are typically direct user actions (flipping a switch), where a
        responsive UI matters more than reducing DB writes.
        """
        data = self._service.status_data
        if not data or self._auth_failed:
            return

        decora_count = len(data.get("decora_devices", {}))
        _LOGGER.debug(
            f"[v{self._service.version}] Pushing realtime Decora update to HA: {decora_count} devices"
        )
        self.async_set_updated_data(data)

    def _log_data_if_enabled(self, data, source: str = ""):
        """Log data based on user options."""
        options = self.config_entry.options
        
        # Check if "Log All Parsed Data" is enabled
        if options.get("log_parsed_data", False):
            redacted_data = self._redact_data(data)
            _LOGGER.warning("Leviton %s Parsed Data: %s", source, redacted_data)
        
        # Check if specific field logging is enabled
        elif options.get("enable_specific_logging", False):
            if fields_to_log_str := options.get("log_fields", ""):
                fields_to_log = [f.strip() for f in fields_to_log_str.split(',') if f.strip()]
                log_output = {}
                if data:
                    for ct_data in data.get('cts', {}).values():
                        for field in fields_to_log:
                            if field in ct_data:
                                log_output[f"CT_{ct_data.get('channel', '?')}_{field}"] = ct_data[field]
                    
                    for b_id, b_data in data.get('breakers', {}).items():
                        for field in fields_to_log:
                            if field in b_data:
                                log_output[f"Breaker_{b_data.get('name', '?')}_{field}"] = b_data[field]

                    for panel in data.get('panels', []):
                        for field in fields_to_log:
                            if field in panel:
                                log_output[f"Panel_{panel.get('name', '?')}_{field}"] = panel[field]

                if log_output:
                    # The chosen fields get the same redaction as the full dump.
                    _LOGGER.warning("Leviton %s Selected Data: %s", source, self._redact_data(log_output))

    _REDACT_KEYS = frozenset({
        "IP", "Token", "residenceId", "mac", "residentialRoomId",
        "id", "userId", "accountId", "auth_token", "refresh_token",
        "password", "serialNumber", "ttl", "created",
        # Device identifiers and the LAN address the parsed data also holds.
        "stable_id", "panel_id", "serial", "localIP",
    })
    # Collections in the parsed data keyed by breaker, CT, device or room id.
    _ID_KEYED = frozenset({"breakers", "cts", "decora_devices", "rooms"})

    def _redact_data(self, data, parent=None):
        """Redact sensitive fields from data for logging.

        Ids appear as keys too: the breaker, CT, Decora device and room
        collections are keyed by id, and each panel's total power is kept
        under "<panel id>totalPower". Those keys are replaced by numbers.
        A field named in the specific-field logging option, e.g.
        "Breaker_Dryer_serialNumber", is redacted by its field name.
        """
        if isinstance(data, dict):
            redacted = {}
            totals = 0
            for index, (key, value) in enumerate(data.items(), start=1):
                field = key
                if parent in self._ID_KEYED:
                    key = f"#{index}"
                elif isinstance(key, str) and key.endswith("totalPower") and key != "totalPower":
                    totals += 1
                    key = f"#{totals} totalPower"
                elif isinstance(key, str) and key.startswith(("Breaker_", "Panel_", "CT_")):
                    field = key.rsplit("_", 1)[-1]
                if field in self._REDACT_KEYS:
                    redacted[key] = "***REDACTED***"
                else:
                    redacted[key] = self._redact_data(value, field)
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

        # Only the first refresh toggles the panels' bandwidth for fresh
        # values. A later one runs because the WebSocket is down and something
        # asked for a refresh (every Decora command does) and only reads.
        toggle_bandwidth = self.data is None

        try:
            # status() ends within STATUS_TIMEOUT (see const.py), so this
            # never gives up on a refresh that then runs on in its thread.
            async with asyncio.timeout(STATUS_TIMEOUT):
                # This will now either return data or raise an Exception
                returnData = await self._hass.async_add_executor_job(
                    self._service.status, toggle_bandwidth
                )

            # Log data if enabled
            self._log_data_if_enabled(returnData, "API")

            self._persist_refreshed_tokens()

            return returnData

        except LDATAAuthError as ex:
            # This is our specific auth failure
            _LOGGER.warning("Authentication failed: %s. Please re-authenticate.", ex)
            raise ConfigEntryAuthFailed(f"Authentication failed: {ex}") from ex
        
        except requests.exceptions.RequestException as ex:
            # This is a network/DNS/timeout error from ldata_service.
            # This is NOT an auth failure, just a temporary error. The
            # UpdateFailed text is logged by Home Assistant too, so it gets
            # the same URL-free description.
            _LOGGER.warning("Connection error communicating with LDATA: %s", _safe_error(ex))
            raise UpdateFailed(f"Connection error: {_safe_error(ex)}") from ex

        except Exception as ex:
            # This catches all other errors (e.g., "Could not get Account ID")
            _LOGGER.warning("Unexpected error communicating with LDATA: %s", _safe_error(ex))
            # This will result in the "Failed setup, will retry" message
            raise UpdateFailed(f"Error communicating with LDATA: {_safe_error(ex)}") from ex

    def _persist_refreshed_tokens(self) -> None:
        """Persist a token refreshed during status() into the config entry.

        status()'s credential-fallback path (see ldata_service.py) obtains a
        fresh refresh_token/userid on the LDATAService instance when the
        stored one expired, but only on that in-memory instance — it can't
        write to the config entry itself (that call isn't safe from the
        executor thread status() runs on). Without this, every future
        restart would repeat the same expired-token-then-credential-fallback
        detour instead of healing once. Cheap to call unconditionally: a
        dict-equality-free comparison, and a no-op unless something changed.
        """
        entry = self.config_entry
        if not entry:
            return
        if (
            self._service.refresh_token == entry.data.get("refresh_token", "")
            and self._service.userid == entry.data.get("userid", "")
        ):
            return
        self._hass.config_entries.async_update_entry(
            entry,
            data={
                **entry.data,
                "refresh_token": self._service.refresh_token,
                "userid": self._service.userid,
            },
        )
        _LOGGER.info(f"[v{self._service.version}] Persisted refreshed LDATA auth token")

    @property
    def service(self) -> LDATAService:
        """Return the LDATA service."""
        return self._service
