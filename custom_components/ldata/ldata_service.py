"""The LDATAService object."""

import logging
import typing
import time
import socket
import re
import os
import json
import threading
import requests
import asyncio
import aiohttp

from .const import _LEG1_POSITIONS, LOGGER_NAME, THREE_PHASE, THREE_PHASE_DEFAULT

try:
    # Read manifest.json dynamically to get the version
    with open(os.path.join(os.path.dirname(__file__), 'manifest.json')) as f:
        manifest_data = json.load(f)
        VERSION = manifest_data.get('version', 'Unknown')
except Exception:
    VERSION = "Unknown"

defaultHeaders = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
    "host": "my.leviton.com",
    "Origin": "https://myapp.leviton.com",
    "Referer": "https://myapp.leviton.com/",
    "Connection": "keep-alive",
    "DNT": "1",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site",
    "Sec-GPC": "1",
    "Priority": "u=0",
}

_LOGGER = logging.getLogger(LOGGER_NAME)


class TwoFactorRequired(Exception):
    """Raised when 2FA code is required."""

class LDATAAuthError(Exception):
    """Raised for authentication failures that require re-auth."""


class LDATAService:
    """The LDATAService object."""
    _last_login_attempt_time = 0.0

    def __init__(self, username, password, entry) -> None:
        """Init LDATAService."""
        self.username = username
        self.password = password
        self.entry = entry
        self.version = VERSION
        self.auth_token = ""
        self.refresh_token = entry.data.get("refresh_token", "") if entry else ""
        self.userid = entry.data.get("userid", "") if entry else ""
        self.account_id = ""
        self.residence_id_list = []  # type: list[str]
        self.session = requests.Session()
        self.session.headers.update(defaultHeaders)
        
        # Lock to serialize REST poll operations. The breaker poll and CT poll
        # both use self.session and interact with the bandwidth setting.
        # Without serialization the CT toggle (bandwidth:0) can corrupt a
        # concurrent breaker GET, causing the cloud to return stale zeros.
        self._rest_poll_lock = threading.Lock()
        # Cache for the latest status data to support WebSocket updates
        self.status_data = None
        # Three-phase voltage calculation mode — cached from options so all
        # update paths (REST, WS direct, WS embedded) use the same formula.
        self._three_phase = THREE_PHASE_DEFAULT
        if entry:
            self._three_phase = entry.options.get(
                THREE_PHASE, entry.data.get(THREE_PHASE, THREE_PHASE_DEFAULT)
            )
        # Storage for full auth response to support WebSocket handshake
        self.full_auth_response = None
        # Flag for graceful shutdown
        self._shutdown_requested = False
        
        # Per-panel CT polling flag.
        # CT energy counters require bandwidth toggle + REST poll to update.
        # Breaker data (power, energyConsumption) arrives via WebSocket — no REST needed.
        # Key: panel_id, Value: True if panel has CTs requiring polling
        self._panel_needs_rest_poll: dict[str, bool] = {}
        # Track whether panels have hardware energy counters (energyConsumption).
        # Set True when we see non-None consumption data from a breaker.
        # When False, breaker daily sensors fall back to power×time integration.
        self._panel_has_hw_counters: dict[str, bool] = {}
        # Track how many IotWhem WS messages we've seen per panel without breaker data
        self._ws_iotwhem_count: dict[str, int] = {}
        # Detection threshold (still used for logging, but no longer triggers breaker REST poll)
        _WS_DETECTION_THRESHOLD = 5
        self._WS_DETECTION_THRESHOLD = _WS_DETECTION_THRESHOLD
        # Track when WS last delivered breaker data per panel (for coordinator)
        self._ws_last_breaker_data_time: dict[str, float] = {}

        # ── Unified zero-transition protection ────────────────────────
        # On V2 firmware the cloud sporadically sends zero power *and/or*
        # zero rmsCurrent for breakers that actually carry a stable load.
        # This happens on both the WS and REST paths.
        #
        # We protect BOTH power and current together:
        #   • A breaker is considered "loaded" when EITHER power > 0 OR
        #     current > 0.  (A tiny motor can show current with ~0 real W.)
        #   • Once loaded, ALL electrical fields (power, current, voltage,
        #     frequency) are frozen until the breaker reports zero for BOTH
        #     power AND current for N consecutive updates.
        #   • Any single non-zero reading on either metric resets the counter.
        #
        # The counter is intentionally shared across REST and WS updates so
        # a single stale zero from one transport does not reset the sequence
        # established by the other.
        self._breaker_zero_count: dict[str, int] = {}
        _ZERO_CONFIRM_THRESHOLD = 3
        self._ZERO_CONFIRM_THRESHOLD = _ZERO_CONFIRM_THRESHOLD
        # Stash the last-known-good values so we can hold them during
        # the zero-confirmation window.  Keyed by breaker_id.
        self._breaker_last_good: dict[str, dict] = {}
        # Track the timestamp of the last zero-counter increment per breaker.
        # If too much wall-clock time passes between increments (e.g. because
        # a non-zero reading arrived in between), the counter resets.
        self._breaker_zero_last_time: dict[str, float] = {}
        # Maximum seconds between consecutive zero readings before the counter
        # resets.  This prevents slow accumulation across bandwidth toggle
        # cycles from eventually tripping the threshold.
        self._ZERO_DECAY_SECONDS = 180.0
        # Panels currently undergoing a bandwidth toggle.  While a panel is
        # in this set, zero-counter increments for its breakers are suppressed
        # so that the transient zeros caused by bandwidth:0 don't accumulate.
        self._panels_in_bandwidth_toggle: set[str] = set()

    def _check_rate_limit(self) -> None:
        """Enforces a 10-second wait between login attempts."""
        current_time = time.time()
        
        time_since_last_attempt = current_time - LDATAService._last_login_attempt_time
        
        if time_since_last_attempt < 10.0:
            wait_time = 10.0 - time_since_last_attempt
            _LOGGER.warning(f"[v{self.version}] Rate limiting login. Waiting for {wait_time:.1f} seconds.")
            # This is running in an executor job, so time.sleep is OK.
            time.sleep(wait_time)
        
        LDATAService._last_login_attempt_time = time.time()

    def _test_internet_connectivity(self) -> str:
        """Helper to check if google.com is resolvable."""
        try:
            socket.gethostbyname("google.com")
            return "ACTIVE"
        except socket.error:
            return "DOWN"
            
    def _get_clean_error_msg(self, response_text: str) -> str:
        """Helper to strip HTML and deduplicate common gateway errors."""
        # Strip HTML tags
        msg = re.sub('<[^<]+?>', '', response_text)
        # Collapse multiple spaces into one
        msg = re.sub(r'\s+', ' ', msg).strip()
        
        # Deduplicate common Nginx/Gateway error strings that appear twice
        if "502 Bad Gateway" in msg:
            return "502 Bad Gateway"
        if "504 Gateway Time-out" in msg:
            return "504 Gateway Time-out"
            
        return msg

    def clear_tokens(self) -> None:
        """Clear the tokens to force a re-login."""
        self.auth_token = ""
        self.refresh_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id_list = []
        self.full_auth_response = None

    def auth_with_credentials(self) -> bool:
        """Authenticate to the server using username and password."""
        self._check_rate_limit()
        
        headers = {**defaultHeaders}
        data = {"email": self.username, "password": self.password}
        
        result = self.session.post(
            "https://my.leviton.com/api/Person/login?include=user",
            headers=headers,
            json=data,
            timeout=15,
        )
        
        if result.status_code == 200:
            json_data = result.json()
            self.auth_token = json_data["id"]
            self.userid = json_data["userId"]
            self.refresh_token = json_data["id"] # Store the auth token
            self.full_auth_response = json_data # Store full response for WebSocket
            _LOGGER.debug(f"[v{self.version}] Login successful (HTTP 200).")
            return True

        # Treat both 401 and 406 as potential auth failures
        if result.status_code == 401 or result.status_code == 406:
            clean_msg = self._get_clean_error_msg(result.text)
            _LOGGER.warning(
                f"[v{self.version}] Authentication failed (HTTP {result.status_code}). Check this log for the 2FA string. "
                f"Response text: {clean_msg}"
            )
            
            if "InsufficientData:Personusestwofactorauthentication.Requirescode." in result.text:
                _LOGGER.debug(f"[v{self.version}] Found 2FA string, raising TwoFactorRequired.")
                raise TwoFactorRequired
            else:
                _LOGGER.warning(f"[v{self.version}] 2FA string not found, assuming invalid credentials.")
                raise LDATAAuthError(f"[v{self.version}] Invalid username or password")

        # Handle other non-200, non-401/406 errors
        raise LDATAAuthError(f"[v{self.version}] Login failed with status code: {result.status_code}")


    def complete_2fa(self, code: str) -> bool:
        """Complete the 2FA authentication step."""
        self._check_rate_limit()

        _LOGGER.debug(f"[v{self.version}] Attempting 2FA completion with code.")
        
        headers = {**defaultHeaders}
        data = {
            "email": self.username,
            "password": self.password,
            "code": code
        }
        
        result = self.session.post(
            "https://my.leviton.com/api/Person/login?include=user",
            headers=headers,
            json=data,
            timeout=15,
        )

        if result.status_code == 200:
            json_data = result.json()
            self.auth_token = json_data["id"]
            self.userid = json_data["userId"]
            self.refresh_token = json_data["id"] # Store the auth token
            self.full_auth_response = json_data # Store full response for WebSocket
            _LOGGER.debug(f"[v{self.version}] 2FA login successful (HTTP 200).")
            return True
        
        # Failed 2FA
        clean_msg = self._get_clean_error_msg(result.text)
        _LOGGER.warning(f"[v{self.version}] 2FA completion failed (HTTP {result.status_code}). Response: {clean_msg}")
        raise LDATAAuthError(f"[v{self.version}] Invalid 2FA code")

    def refresh_auth(self) -> bool:
        """Validate the stored auth token with retries."""
        if not self.refresh_token:
            _LOGGER.debug(f"[v{self.version}] No stored token available.")
            return False # This will trigger credential login

        # We need the userId to check. If we don't have it, we must fail.
        if not self.userid:
             _LOGGER.warning(f"[v{self.version}] No userId found, cannot validate token. Forcing re-auth.")
             self.clear_tokens()
             return False # Force re-login
             
        _LOGGER.debug(f"[v{self.version}] Validating stored auth token.")
        self.auth_token = self.refresh_token
        
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"
        
        # --- RETRY LOGIC START ---
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            attempts += 1
            try:
                result = self.session.get(url, headers=headers, timeout=15)
                
                if result.status_code == 200:
                    _LOGGER.debug(f"[v{self.version}] Stored token is still valid.")
                    if not self.account_id:
                        json_data = result.json()
                        if len(json_data) > 0:
                            for item in json_data:
                                if "residentialAccountId" in item:
                                    self.account_id = item["residentialAccountId"]
                                    break
                    return True # Success!
                
                # Handle Auth Errors (401, 403, 406)
                if result.status_code in (401, 403, 406):
                    _LOGGER.warning(
                        f"[v{self.version}] Token check failed (Attempt {attempts}/{max_attempts}) with status {result.status_code}. Waiting..."
                    )
                    if attempts < max_attempts:
                        time.sleep(5) # Wait 5 seconds before retrying
                        continue # Try again
                    else:
                        # STRIKE 3: The token is truly dead.
                        _LOGGER.error(f"[v{self.version}] Token invalid after {max_attempts} attempts. Forcing re-auth.")
                        self.clear_tokens()
                        raise LDATAAuthError(f"[v{self.version}] Token expired or invalid")
                
                # Handle Server Errors (500, 502, 503, etc)
                else:
                    clean_msg = self._get_clean_error_msg(result.text)
                    _LOGGER.warning(
                        f"[v{self.version}] Server error during token check (Attempt {attempts}/{max_attempts}): {result.status_code} {result.reason} - {clean_msg}. Waiting..."
                    )
                    if attempts < max_attempts:
                        time.sleep(5)
                        continue
                    else:
                        raise requests.exceptions.RequestException(f"Server error: {result.status_code} {result.reason}")

            except requests.exceptions.RequestException as ex:
                # Handle Network Errors (DNS, Timeout, etc)
                msg = str(ex)
                if hasattr(ex, "response") and ex.response is not None:
                     clean_msg = self._get_clean_error_msg(ex.response.text)
                     msg = f"{ex.response.status_code} {ex.response.reason} - {clean_msg}"

                _LOGGER.warning(
                    f"[v{self.version}] Network error during token check (Attempt {attempts}/{max_attempts}): {msg}. Waiting..."
                )
                if attempts < max_attempts:
                    time.sleep(5)
                    continue
                else:
                    raise
            except Exception as ex:
                _LOGGER.error(f"[v{self.version}] Unexpected error during token check: {ex}")
                self.clear_tokens()
                raise LDATAAuthError(f"[v{self.version}] Token validation error: {ex}") from ex
        
        return False

    def get_residential_account(self) -> bool:
        """Get the Residential Account for the user."""
        if self.account_id:
            _LOGGER.debug(f"[v{self.version}] Account ID already known.")
            return True

        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"

        try:
            result = self.session.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                f"[v{self.version}] Get Residential Account result {result.status_code}: {result.text}"
            )
            
            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid during API call get_residence. Status code: {result.status_code}")

            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                # Search for the residential account id
                for item in result_json:
                    if "residentialAccountId" in item:
                        self.account_id = item["residentialAccountId"]
                        if self.account_id is not None:
                            break
                if self.account_id is not None:
                    # Save the userId if we just got it
                    if "userId" in result_json[0]:
                        self.userid = result_json[0]["userId"]
                    return True
            _LOGGER.error(f"[v{self.version}] Unable to get Residential Account!")
            self.clear_tokens()
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, LDATAAuthError):
                raise # Re-raise auth errors
            _LOGGER.exception(f"[v{self.version}] Exception while getting Residential Account!")
            self.clear_tokens()

        return False

    def get_residencePermissions(self) -> bool:
        """Get the additional residences for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"
        try:
            result = self.session.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                f"[v{self.version}] Get Residence Permissions result {result.status_code}: {result.text}"
            )
            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid during API call get_residencePermissions. Status code: {result.status_code}")

            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                for account in result_json:
                    if account["residenceId"] is not None:
                        if account["residenceId"] not in self.residence_id_list:
                            self.residence_id_list.append(account["residenceId"])
                return True
            _LOGGER.error(f"[v{self.version}] Unable to get Residence Permissions!")
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, LDATAAuthError):
                raise
            _LOGGER.exception(f"[v{self.version}] Exception while getting Residence Permissions!")
        return False

    def get_residences(self) -> bool:
        """Get the Residential Account for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/ResidentialAccounts/{self.account_id}/residences"
        try:
            result = self.session.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                f"[v{self.version}] Get Residences Account result {result.status_code}: {result.text}"
            )
            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid during API call get_residences. Status code: {result.status_code}")

            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                self.residence_id_list.append(result_json[0]["id"])
                return True
            _LOGGER.error(f"[v{self.version}] Unable to get Residences!")
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, LDATAAuthError):
                raise
            _LOGGER.exception(f"[v{self.version}] Exception while getting Residences!")
        return False

    def get_residence(self) -> bool:
        """Get the Residential Account for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/ResidentialAccounts/{self.account_id}"
        try:
            result = self.session.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                f"[v{self.version}] Get Residence Account result {result.status_code}: {result.text}"
            )
            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid during API call get_residence. Status code: {result.status_code}")

            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                self.residence_id_list.append(result_json["primaryResidenceId"])
                return True
            _LOGGER.error(f"[v{self.version}] Unable to get Residence!")
            self.clear_tokens()
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, LDATAAuthError):
                raise
            _LOGGER.exception(f"[v{self.version}] Exception while getting Residence!")
            self.clear_tokens()
        return False

    def get_Whems_breakers(self, panel_id: str) -> list[dict] | None:
        """Get the whemns modules for the residence."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["filter"] = "{}"
        url = f"https://my.leviton.com/api/IotWhems/{panel_id}/residentialBreakers"
        try:
            result = self.session.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                f"[v{self.version}] Get WHEMS breakers result {result.status_code}: {result.text}"
            )
            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid during API call get_Whems_breakers. Status code: {result.status_code}")

            if result.status_code == 200:
                return result.json()
            
            clean_msg = self._get_clean_error_msg(result.text)
            _LOGGER.error(f"[v{self.version}] Unable to get WHEMS breakers! HTTP {result.status_code}: {clean_msg}")
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, LDATAAuthError):
                raise
            _LOGGER.exception(f"[v{self.version}] Exception while getting WHEMS breakers!")
        return None

    def get_Whems_CT(self, panel_id: str) -> list[dict] | None:
        """Get the whemns CTs for the panel module."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["filter"] = "{}"
        url = f"https://my.leviton.com/api/IotWhems/{panel_id}/iotCts"
        try:
            result = self.session.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                f"[v{self.version}] Get WHEMS CTs result {result.status_code}: {result.text}"
            )
            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid during API call get_Whems_CT. Status code: {result.status_code}")

            if result.status_code == 200:
                return result.json()
            
            clean_msg = self._get_clean_error_msg(result.text)
            _LOGGER.error(f"[v{self.version}] Unable to get WHEMS CTs! HTTP {result.status_code}: {clean_msg}")
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, LDATAAuthError):
                raise
            _LOGGER.exception(f"[v{self.version}] Exception while getting WHEMS CTs!")
        return None

    def _fetch_panels(self, url_template: str, panel_type: str) -> object:
        """Helper to fetch panels of a specific type (LDATA or WHEMS)."""
        allPanels = None
        for residenceId in self.residence_id_list:
            headers = {**defaultHeaders}
            headers["authorization"] = self.auth_token
            
            # Determine filter based on panel type
            if panel_type == "LDATA":
                headers["filter"] = '{"include":["residentialBreakers"]}'
            else:
                headers["filter"] = "{}"

            url = url_template.format(residenceId=residenceId)
            
            try:
                result = self.session.get(
                    url,
                    headers=headers,
                    timeout=15,
                )
                
                if result.status_code == 401:
                    raise LDATAAuthError(f"[v{self.version}] Auth token invalid (401) during API call get_{panel_type}_panels.")
                
                if result.status_code in (403, 406):
                     _LOGGER.warning(
                        f"[v{self.version}] Access forbidden or not acceptable (HTTP {result.status_code}) when getting {panel_type} panels for residence {residenceId}. "
                        "This may be a permission issue. Skipping."
                    )
                     continue 

                if result.status_code == 200:
                    _LOGGER.debug(
                        f"[v{self.version}] Get {panel_type} Panels result {result.status_code}: {result.text}"
                    )
                    
                    try:
                        returnPanels = result.json()
                    except json.JSONDecodeError:
                        _LOGGER.warning(
                            f"[v{self.version}] API returned invalid JSON for {panel_type} panels despite 200 OK. Response starts with: {result.text[:100]}..."
                        )
                        continue # Skip this residence/attempt and try the next one
                        
                    for panel in returnPanels:
                        panel["ModuleType"] = panel_type
                        
                        # Determine connection status BEFORE sending commands
                        is_connected = panel.get("connected", False)
                        # Special handling for DAU models
                        if panel.get("model") == "DAU" and panel.get("status") == "READY":
                            is_connected = True

                        # Only force an update if the panel is actually online.
                        # This avoids wasting API calls on offline devices, saving cost/load.
                        if is_connected:
                            try:
                                # Full 1→0→1 bandwidth toggle forces the panel to push
                                # fresh data to the cloud.  A single bandwidth:1 PUT is
                                # often too fast — the cloud returns stale cached values.
                                self._bandwidth_toggle(panel["id"], panel.get("ModuleType", "WHEMS"))
                            except requests.exceptions.RequestException as e:
                               _LOGGER.warning(f"[v{self.version}] Failed to request update from panel {panel.get('name', panel['id'])}: {e}")
                            except LDATAAuthError as e:
                                _LOGGER.warning(f"[v{self.version}] Auth failed during panel update for {panel.get('name', panel['id'])}: {e}")
                                raise
                        else:
                             _LOGGER.debug(f"[v{self.version}] Skipping force update for offline panel {panel.get('name', panel['id'])}")
                        
                        # Apply WHEMS specific mapping
                        if panel_type == "WHEMS":
                            panel["rmsVoltage"] = panel["rmsVoltageA"]
                            panel["rmsVoltage2"] = panel["rmsVoltageB"]
                            panel["updateVersion"] = panel["version"]
                            # Brief delay after toggle to let the cloud receive
                            # fresh values from the panel hardware before we fetch.
                            if is_connected:
                                import time as _time
                                _time.sleep(2)
                            panel["residentialBreakers"] = self.get_Whems_breakers(panel["id"])
                            panel["CTs"] = self.get_Whems_CT(panel["id"])
                        
                        if allPanels is None:
                            allPanels = []
                        allPanels.append(panel)
                
                else:
                    clean_msg = self._get_clean_error_msg(result.text)
                    _LOGGER.warning(f"[v{self.version}] Failed to get {panel_type} panels (HTTP {result.status_code}): {clean_msg}")

            except Exception as e:
                if isinstance(e, LDATAAuthError):
                    raise
                
                # STOP! Do not clear tokens for generic errors.
                _LOGGER.exception(f"[v{self.version}] Exception while getting {panel_type} Panels! Ignoring.")
        
        return allPanels

    def get_iotWhemsPanels(self) -> object:
        """Get the whemns modules for all the residences the user has access to."""
        return self._fetch_panels("https://my.leviton.com/api/Residences/{residenceId}/iotWhems", "WHEMS")

    def get_ldata_panels(self) -> object:
        """Get the ldata modules for all the residences the user has access to."""
        return self._fetch_panels("https://my.leviton.com/api/Residences/{residenceId}/residentialBreakerPanels", "LDATA")

    def _put_request(self, url: str, json_data: dict, context_str: str, referer: str = None) -> object:
        """Helper to handle PUT requests with standardized error handling."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        if referer:
            headers["referer"] = referer
        
        try:
            result = self.session.put(
                url,
                headers=headers,
                json=json_data,
                timeout=15,
            )
            
            if result.status_code == 200:
                return result

            if result.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth token invalid (HTTP {result.status_code}) during {context_str}")

            clean_msg = self._get_clean_error_msg(result.text)
            _LOGGER.error(f"[v{self.version}] Failed to execute {context_str}! HTTP {result.status_code}: {clean_msg}")
        
        except Exception as e:
            if isinstance(e, LDATAAuthError):
                raise
            _LOGGER.exception(f"[v{self.version}] Exception during {context_str}: {e}")
        
        return None

    def put_residential_breaker_panels(self, panel_id: str, panel_type: str) -> None:
        """Call PUT on the ResidentialBreakerPanels API this must be done to force an update of the power values."""
        if panel_type == "LDATA":
            url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}"
        else:
            url = f"https://my.leviton.com/api/IotWhems/{panel_id}"
        
        # Call the new helper
        self._put_request(url, {"bandwidth": 1}, "put_residential_breaker_panels")

    def remote_off(self, breaker_id):
        """Turn off a breaker."""
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        referer = f"https://my.leviton.com/home/residential-breakers/{breaker_id}/settings"
        
        # Call the new helper
        return self._put_request(url, {"remoteTrip": True}, "remote_off", referer=referer)

    def remote_on(self, breaker_id):
        """Turn on a breaker."""
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        referer = f"https://my.leviton.com/home/residential-breakers/{breaker_id}/settings"
        
        # Call the new helper
        return self._put_request(url, {"remoteOn": True}, "remote_on", referer=referer)

    def none_to_zero(self, data_dict, key) -> float:
        """Convert a value to a float and replace None with 0.0."""
        try:
            value = data_dict[key]
        except (KeyError, TypeError, AttributeError):
            return 0.0
        if value is None:
            return 0.0
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    def _none_or_float(self, data_dict, key) -> float | None:
        """Convert a value to float, returning None if the key is missing or the value is None.

        Unlike none_to_zero, this preserves the distinction between "API
        returned None / missing" and "API returned 0.0".  Used during
        parse_panels so that breakers whose power/current was not present in
        the REST response are not falsely initialised to 0.
        """
        try:
            value = data_dict[key]
        except (KeyError, TypeError, AttributeError):
            return None
        if value is None:
            return None
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    def _check_zero_transition(
        self,
        breaker_id: str,
        new_power: float,
        new_current: float,
        old_power: float,
        old_current: float,
        source: str = "?",
        power_from_msg: bool = True,
        current_from_msg: bool = True,
        panel_id: str | None = None,
    ) -> bool:
        """Unified zero-transition guard for breaker power AND current.

        Returns True if the new values should be ACCEPTED, or False if they
        should be HELD at their previous non-zero values.

        The key insight: WS often sends power and current INDEPENDENTLY.
        A message with just {"power": 0} should NOT be accepted immediately
        just because the cached current is still non-zero.

        Logic:
          • A breaker is "loaded" when old_power > 0 OR old_current > 0.
          • If loaded and ANY arriving field is zero while NONE of the arriving
            fields are non-zero, count toward zero confirmation.
          • If ANY arriving field is non-zero, reset the counter — real load.
          • Accept the zero transition only after _ZERO_CONFIRM_THRESHOLD
            consecutive zero-indicating updates.
          • The counter decays if too much time passes between zero readings,
            preventing slow accumulation across bandwidth toggle cycles.
          • Zero-counter increments are suppressed while the breaker's panel
            is in a bandwidth toggle (the cloud sends transient zeros).

        power_from_msg / current_from_msg: indicates whether that value was
        actually present in the WS/REST message (True) or is a cached
        carry-forward from the breaker dict (False).
        """
        was_loaded = abs(old_power) > 0 or abs(old_current) > 0.01

        if not was_loaded:
            # Already at zero — nothing to protect
            self._breaker_zero_count[breaker_id] = 0
            return True

        # Determine what the arriving fields tell us.
        # Only look at fields that actually came in the message.
        arriving_values = []
        if power_from_msg:
            arriving_values.append(abs(new_power))
        if current_from_msg:
            arriving_values.append(abs(new_current))

        if not arriving_values:
            # No electrical fields arrived — nothing to check
            return True

        any_arriving_nonzero = any(v > 0.01 for v in arriving_values)
        all_arriving_zero = all(v < 0.01 for v in arriving_values)

        if any_arriving_nonzero:
            # Real load confirmed — reset counter, accept
            self._breaker_zero_count[breaker_id] = 0
            return True

        if all_arriving_zero:
            # ── Bandwidth-toggle suppression ──
            # If this breaker's panel is currently in a bandwidth toggle,
            # the cloud is likely sending transient zeros.  Reject without
            # incrementing the counter so these don't accumulate.
            if panel_id and panel_id in self._panels_in_bandwidth_toggle:
                _LOGGER.debug(
                    f"[v{self.version}] {source}: Suppressing zero for breaker "
                    f"{breaker_id} during bandwidth toggle (panel {panel_id})"
                )
                return False  # REJECT — hold old values, don't count

            # ── Time-based decay ──
            # If the last zero was too long ago, reset the counter.
            # This prevents slow accumulation across unrelated events.
            now = time.time()
            last_zero_time = self._breaker_zero_last_time.get(breaker_id, 0)
            if last_zero_time > 0 and (now - last_zero_time) > self._ZERO_DECAY_SECONDS:
                _LOGGER.debug(
                    f"[v{self.version}] {source}: Zero counter for breaker "
                    f"{breaker_id} decayed ({now - last_zero_time:.1f}s since last zero)"
                )
                self._breaker_zero_count[breaker_id] = 0

            # Every field that arrived is zero — count toward confirmation
            count = self._breaker_zero_count.get(breaker_id, 0) + 1
            self._breaker_zero_count[breaker_id] = count
            self._breaker_zero_last_time[breaker_id] = now
            if count < self._ZERO_CONFIRM_THRESHOLD:
                _LOGGER.debug(
                    f"[v{self.version}] {source}: Holding breaker {breaker_id} "
                    f"at {old_power}W/{old_current}A "
                    f"(zero {count}/{self._ZERO_CONFIRM_THRESHOLD})"
                )
                return False  # REJECT — hold old values
            else:
                _LOGGER.debug(
                    f"[v{self.version}] {source}: Accepting zero for breaker "
                    f"{breaker_id} after {self._ZERO_CONFIRM_THRESHOLD} consecutive updates"
                )
                self._breaker_zero_count[breaker_id] = 0
                return True  # ACCEPT — genuinely off

        # Shouldn't reach here, but accept if we do
        return True

    def _apply_breaker_update(
        self,
        breaker_id: str,
        existing: dict,
        raw: dict,
        source: str = "?",
        three_phase: bool | None = None,
    ) -> bool:
        """Apply a breaker update from any source (REST, WS direct, WS embedded).
        
        Handles leg-swap mapping, partial update caching, unified zero-transition
        protection, and field updates. Mutates `existing` in place.
        
        Args:
            breaker_id: The breaker ID (for zero-transition tracking).
            existing: The current breaker dict (will be mutated).
            raw: The new data dict (from REST API response or WS payload).
            source: Label for logging ("REST", "WS", "WS-bulk").
            three_phase: Whether the panel uses three-phase voltage calculation.
                         Defaults to self._three_phase if not specified.
            
        Returns:
            True if power was updated (for totalPower recalculation).
        """
        if three_phase is None:
            three_phase = self._three_phase
        # Cached values for partial update handling
        # Coerce None → 0 so arithmetic below never fails; initial parse_panels
        # may store None when the API omits power/current fields.
        cached_p1 = existing.get("power1") or 0
        cached_p2 = existing.get("power2") or 0
        leg = existing.get("leg", 1)
        
        # --- Power fields with leg swap ---
        if leg == 1:
            if "power" in raw:
                p1 = float(raw["power"]) if raw["power"] is not None else cached_p1
            else:
                p1 = cached_p1
            if "power2" in raw:
                p2 = float(raw["power2"]) if raw["power2"] is not None else cached_p2
            else:
                p2 = cached_p2
        else:
            # Leg 2: power -> power2, power2 -> power1 (swapped)
            if "power" in raw:
                p2 = float(raw["power"]) if raw["power"] is not None else cached_p2
            else:
                p2 = cached_p2
            if "power2" in raw:
                p1 = float(raw["power2"]) if raw["power2"] is not None else cached_p1
            else:
                p1 = cached_p1
        
        # --- Current fields with leg swap ---
        cached_c1 = existing.get("current1") or 0
        cached_c2 = existing.get("current2") or 0
        if leg == 1:
            c1 = float(raw["rmsCurrent"]) if raw.get("rmsCurrent") is not None and "rmsCurrent" in raw else cached_c1
            c2 = float(raw["rmsCurrent2"]) if raw.get("rmsCurrent2") is not None and "rmsCurrent2" in raw else cached_c2
        else:
            c2 = float(raw["rmsCurrent"]) if raw.get("rmsCurrent") is not None and "rmsCurrent" in raw else cached_c2
            c1 = float(raw["rmsCurrent2"]) if raw.get("rmsCurrent2") is not None and "rmsCurrent2" in raw else cached_c1
        
        # --- Detect which fields arrived ---
        has_power_field = "power" in raw or "power2" in raw
        has_current_field = "rmsCurrent" in raw or "rmsCurrent2" in raw
        has_voltage_field = "rmsVoltage" in raw or "rmsVoltage2" in raw
        has_frequency_field = "lineFrequency" in raw or "lineFrequency2" in raw
        has_any_electrical = has_power_field or has_current_field
        
        # --- Candidate values ---
        cand_power = (p1 + p2) if has_power_field else (existing.get("power") or 0)
        poles = existing.get("poles", 1)
        cand_current = ((c1 + c2) / 2 if poles == 2 else c1 + c2) if has_current_field else (existing.get("current") or 0)
        
        # --- Unified zero-transition protection ---
        if has_any_electrical:
            accept_update = self._check_zero_transition(
                breaker_id, cand_power, cand_current,
                existing.get("power") or 0, existing.get("current") or 0,
                source=source,
                power_from_msg=has_power_field,
                current_from_msg=has_current_field,
                panel_id=existing.get("panel_id"),
            )
        else:
            accept_update = True
        
        power_changed = False
        if accept_update:
            if has_power_field:
                existing["power"] = cand_power
                existing["power1"] = p1
                existing["power2"] = p2
                power_changed = True
            if has_current_field:
                existing["current"] = cand_current
                existing["current1"] = c1
                existing["current2"] = c2
            
            # Voltage (same leg swap)
            if has_voltage_field:
                cached_v1 = existing.get("voltage1", 0)
                cached_v2 = existing.get("voltage2", 0)
                if leg == 1:
                    v1 = float(raw["rmsVoltage"]) if raw.get("rmsVoltage") is not None and "rmsVoltage" in raw else cached_v1
                    v2 = float(raw["rmsVoltage2"]) if raw.get("rmsVoltage2") is not None and "rmsVoltage2" in raw else cached_v2
                else:
                    v2 = float(raw["rmsVoltage"]) if raw.get("rmsVoltage") is not None and "rmsVoltage" in raw else cached_v2
                    v1 = float(raw["rmsVoltage2"]) if raw.get("rmsVoltage2") is not None and "rmsVoltage2" in raw else cached_v1
                existing["voltage1"] = v1
                existing["voltage2"] = v2
                if (not three_phase) or (poles == 1):
                    existing["voltage"] = v1 + v2
                else:
                    existing["voltage"] = (v1 * 0.866025403784439) + (v2 * 0.866025403784439)
            
            # Frequency (same leg swap)
            if has_frequency_field:
                cached_f1 = existing.get("frequency1", 0)
                cached_f2 = existing.get("frequency2", 0)
                if leg == 1:
                    f1 = float(raw["lineFrequency"]) if raw.get("lineFrequency") is not None and "lineFrequency" in raw else cached_f1
                    f2 = float(raw["lineFrequency2"]) if raw.get("lineFrequency2") is not None and "lineFrequency2" in raw else cached_f2
                else:
                    f2 = float(raw["lineFrequency"]) if raw.get("lineFrequency") is not None and "lineFrequency" in raw else cached_f2
                    f1 = float(raw["lineFrequency2"]) if raw.get("lineFrequency2") is not None and "lineFrequency2" in raw else cached_f1
                existing["frequency1"] = f1
                existing["frequency2"] = f2
                if poles == 2:
                    existing["frequency"] = (f1 + f2) / 2
                else:
                    existing["frequency"] = f1
        else:
            # REJECTED — revert cached power values
            if has_power_field:
                existing["power1"] = cached_p1
                existing["power2"] = cached_p2
        
        # Always update non-electrical state fields
        if raw.get("currentState"):
            existing["state"] = raw["currentState"]
        if raw.get("connected") is not None:
            existing["connected"] = raw["connected"]
        if raw.get("remoteState") is not None:
            existing["remoteState"] = raw["remoteState"]
            if existing["remoteState"] == "":
                existing["remoteState"] = "RemoteON"
        
        # Capture energy counters (hardware-measured, not yet exposed as sensors)
        if "energyConsumption" in raw or "energyConsumption2" in raw:
            cached_ec1 = existing.get("consumption1", 0)
            cached_ec2 = existing.get("consumption2", 0)
            if "energyConsumption" in raw:
                existing["consumption1"] = float(raw["energyConsumption"]) if raw["energyConsumption"] is not None else cached_ec1
            if "energyConsumption2" in raw:
                existing["consumption2"] = float(raw["energyConsumption2"]) if raw["energyConsumption2"] is not None else cached_ec2
            existing["consumption"] = existing["consumption1"] + existing["consumption2"]
        
        if "energyImport" in raw or "energyImport2" in raw:
            cached_ei1 = existing.get("import1", 0)
            cached_ei2 = existing.get("import2", 0)
            if "energyImport" in raw:
                existing["import1"] = float(raw["energyImport"]) if raw["energyImport"] is not None else cached_ei1
            if "energyImport2" in raw:
                existing["import2"] = float(raw["energyImport2"]) if raw["energyImport2"] is not None else cached_ei2
            existing["import"] = existing["import1"] + existing["import2"]
        
        return power_changed

    def _apply_ct_update(self, existing: dict, raw: dict) -> None:
        """Apply a CT update from any source (REST, WS direct, WS embedded).
        
        Handles partial update caching for all CT fields.
        Mutates `existing` in place.
        """
        # Power
        if "activePower" in raw or "activePower2" in raw:
            cached_p1, cached_p2 = existing.get("power1", 0), existing.get("power2", 0)
            if "activePower" in raw:
                existing["power1"] = float(raw["activePower"]) if raw["activePower"] is not None else cached_p1
            if "activePower2" in raw:
                existing["power2"] = float(raw["activePower2"]) if raw["activePower2"] is not None else cached_p2
            existing["power"] = existing["power1"] + existing["power2"]
        
        # Energy consumption
        if "energyConsumption" in raw or "energyConsumption2" in raw:
            cached_c1, cached_c2 = existing.get("consumption1", 0), existing.get("consumption2", 0)
            if "energyConsumption" in raw:
                existing["consumption1"] = float(raw["energyConsumption"]) if raw["energyConsumption"] is not None else cached_c1
            if "energyConsumption2" in raw:
                existing["consumption2"] = float(raw["energyConsumption2"]) if raw["energyConsumption2"] is not None else cached_c2
            existing["consumption"] = existing["consumption1"] + existing["consumption2"]
        
        # Energy import
        if "energyImport" in raw or "energyImport2" in raw:
            cached_i1, cached_i2 = existing.get("import1", 0), existing.get("import2", 0)
            if "energyImport" in raw:
                existing["import1"] = float(raw["energyImport"]) if raw["energyImport"] is not None else cached_i1
            if "energyImport2" in raw:
                existing["import2"] = float(raw["energyImport2"]) if raw["energyImport2"] is not None else cached_i2
            existing["import"] = existing["import1"] + existing["import2"]
        
        # Current
        if "rmsCurrent" in raw or "rmsCurrent2" in raw:
            cached_cur1, cached_cur2 = existing.get("current1", 0), existing.get("current2", 0)
            if "rmsCurrent" in raw:
                existing["current1"] = float(raw["rmsCurrent"]) if raw["rmsCurrent"] is not None else cached_cur1
            if "rmsCurrent2" in raw:
                existing["current2"] = float(raw["rmsCurrent2"]) if raw["rmsCurrent2"] is not None else cached_cur2
            existing["current"] = (existing["current1"] + existing["current2"]) / 2

    def _recalc_total_power(self, status_data: dict, panel_id: str) -> None:
        """Recalculate totalPower for a single panel from its breaker values."""
        breakers = status_data.get("breakers", {})
        total = 0.0
        for b_data in breakers.values():
            if b_data.get("panel_id") == panel_id:
                try:
                    p = b_data.get("power")
                    if p is not None:
                        total += float(p)
                except (ValueError, TypeError):
                    pass
        status_data[panel_id + "totalPower"] = total

    def status(self):
        """Get the breakers from the API."""
        try:
            # First, try to validate our existing token
            if not self.refresh_auth():
                # If no token, or it's invalid, we MUST fail.
                _LOGGER.debug(f"[v{self.version}] Token validation failed. Forcing re-auth.")
                raise LDATAAuthError(f"[v{self.version}] Token validation failed. Please re-authenticate.")

        except LDATAAuthError:
            # Re-raise LDATAAuthError to be caught by the coordinator
            _LOGGER.warning(f"[v{self.version}] Authentication error in status().")
            raise
        except requests.exceptions.RequestException as ex:
             # This is a network/DNS error, raise it for UpdateFailed
            
            # Extract response details if the exception wraps a response
            msg = str(ex)
            if hasattr(ex, "response") and ex.response is not None:
                 clean_msg = self._get_clean_error_msg(ex.response.text)
                 msg = f"{ex.response.status_code} {ex.response.reason} - {clean_msg}"
            
            _LOGGER.warning(f"[v{self.version}] Network error in status(): {msg}")
            raise
        except Exception as ex:
            _LOGGER.error(f"[v{self.version}] Unknown error during auth: {ex}")
            # Wrap unknown error
            raise Exception(f"Unknown error during auth: {ex}") from ex

        if self.auth_token is None or self.auth_token == "":
            _LOGGER.error(f"[v{self.version}] Still no auth token after all attempts.")
            raise Exception("Authentication failed, no auth token.")
        
        # We now have a valid auth_token (either from refresh or new login)
        
        # Make sure we have a residential Account
        if self.account_id is None or self.account_id == "":
            _LOGGER.debug(f"[v{self.version}] Get Account ID!")
            if not self.get_residential_account():
                 _LOGGER.error(f"[v{self.version}] Could not get Account ID.")
                 raise Exception("Could not get LDATA Account ID.")
        
        # Lookup the residential id from the account.
        if self.residence_id_list is None or len(self.residence_id_list) == 0:
            _LOGGER.debug(f"[v{self.version}] Get Residence ID!")
            self.get_residences()
            if self.residence_id_list is None or len(self.residence_id_list) == 0:
                # User does not have multiple residences, lets try just the single residence
                self.get_residence()
            self.get_residencePermissions()
        
        if self.residence_id_list:
            self.residence_id_list = [x for x in self.residence_id_list if x is not None]
            self.residence_id_list = list(set(self.residence_id_list))

        if self.residence_id_list is None or len(self.residence_id_list) == 0:
            _LOGGER.error(f"[v{self.version}] Could not get Residence ID.")
            raise Exception("Could not get LDATA Residence ID.")
        
        # Get the breaker panels.
        panels_json = self.get_ldata_panels()
        whems_panels_json = self.get_iotWhemsPanels()
        if panels_json is None:
            panels_json = whems_panels_json
        elif whems_panels_json is not None:
            for panel in whems_panels_json:
                panels_json.append(panel)
        
        if panels_json is None:
            _LOGGER.warning(f"[v{self.version}] No panels found or API returned no panel data.")
            # Return empty structure
            return self.parse_panels(panels_json)

        return self.parse_panels(panels_json)

    def parse_panels(self, panels_json) -> object:
        """Parse the panel json data."""
        status_data: dict[str, typing.Any] = {}
        breakers: dict[str, typing.Any] = {}
        cts: dict[str, typing.Any] = {}
        panels: list[typing.Any] = []
        status_data["breakers"] = breakers
        status_data["cts"] = cts
        status_data["panels"] = panels
        if panels_json is None:
            return status_data
        
        # Safely get options, as self.entry might be None during config flow
        # Refresh the cached three-phase setting from options (may have changed)
        if self.entry:
            self._three_phase = self.entry.options.get(
                THREE_PHASE, self.entry.data.get(THREE_PHASE, THREE_PHASE_DEFAULT)
            )
        three_phase = self._three_phase

        for panel in panels_json:
            panel_data = {}
            panel_data["firmware"] = panel.get("updateVersion", "unknown")
            panel_data["model"] = panel.get("model", "unknown")
            panel_data["id"] = panel.get("id")
            panel_data["name"] = panel.get("name", "Unknown Panel")
            panel_data["serialNumber"] = panel.get("id")
            
            if not panel_data["id"]:
                _LOGGER.warning(f"[v{self.version}] Skipping panel with missing ID: {panel}")
                continue
            panel_data["panel_type"] = panel.get("ModuleType", "WHEMS")
            panel_data["connected"] = panel.get("connected", False)
            if panel.get("model") == "DAU" and panel.get("status") == "READY":
                panel_data["connected"] = True
            
            # Detect if this panel needs REST polling for breaker/CT data.
            # LWHEM firmware >= 2.0 no longer sends breaker data via WebSocket.
            # We use firmware version as an initial hint, then confirm via WS detection.
            fw_str = panel.get("updateVersion", "0")
            try:
                fw_major = int(fw_str.split(".")[0])
            except (ValueError, IndexError):
                fw_major = 0
            
            # WS-first strategy: ALL panels start assuming WebSocket delivers
            # breaker/CT data. REST polling is only enabled after auto-detection
            # CT polling: only enabled when CTs are discovered for this panel.
            # Breakers no longer need REST polling — WS delivers energyConsumption.
            if panel["id"] not in self._panel_needs_rest_poll:
                self._panel_needs_rest_poll[panel["id"]] = False
                self._ws_iotwhem_count[panel["id"]] = 0
            _LOGGER.info(
                f"[v{self.version}] Panel '{panel.get('name', panel['id'])}' "
                f"({panel_data['panel_type']}) firmware {fw_str} "
                f"— WebSocket for breaker data, CT polling enabled if CTs present"
            )
            if three_phase is False:
                panel_data["voltage"] = (
                    float(panel["rmsVoltage"]) + float(panel["rmsVoltage2"])
                ) / 2.0
            else:
                panel_data["voltage"] = (
                    float(panel["rmsVoltage"]) * 0.866025403784439
                ) + (float(panel["rmsVoltage2"]) * 0.866025403784439)
            panel_data["voltage1"] = float(panel["rmsVoltage"])
            panel_data["voltage2"] = float(panel["rmsVoltage2"])
            panel_data["frequency1"] = float(self.none_to_zero(panel, "frequencyA"))
            panel_data["frequency2"] = float(self.none_to_zero(panel, "frequencyB"))
            if panel_data["frequency1"] == 0:
                panel_data["frequency1"] = 0
                panel_data["frequency2"] = 0
                if panel.get("residentialBreakers"): # Add check if breakers exist
                    for breaker in panel["residentialBreakers"]:
                        if breaker["position"] in _LEG1_POSITIONS:
                            if float(self.none_to_zero(breaker, "lineFrequency")) > 0:
                                panel_data["frequency1"] = float(
                                    self.none_to_zero(breaker, "lineFrequency")
                                )
                            if float(self.none_to_zero(breaker, "lineFrequency2")) > 0:
                                panel_data["frequency2"] = float(
                                    self.none_to_zero(breaker, "lineFrequency2")
                                )
                        else:
                            if float(self.none_to_zero(breaker, "lineFrequency")) > 0:
                                panel_data["frequency2"] = float(
                                    self.none_to_zero(breaker, "lineFrequency")
                                )
                            if float(self.none_to_zero(breaker, "lineFrequency2")) > 0:
                                panel_data["frequency1"] = float(
                                    self.none_to_zero(breaker, "lineFrequency2")
                                )
                        if panel_data["frequency1"] != 0 and panel_data["frequency2"] != 0:
                            break
            if panel_data["frequency2"] == 0:
                panel_data["frequency2"] = panel_data["frequency1"]
            panel_data["frequency"] = (
                float(panel_data["frequency1"]) + float(panel_data["frequency2"])
            ) / 2
            panels.append(panel_data)
            # Setup the CT list.
            if "CTs" in panel and panel["CTs"]: # Add check if CTs exist and is not None
                _LOGGER.debug(f"[v{self.version}] Panel {panel.get('name', panel['id'])}: Found {len(panel['CTs'])} CTs in API response")
                # Enable CT REST polling for this panel — CTs need bandwidth toggle
                self._panel_needs_rest_poll[panel["id"]] = True
                for ct in panel["CTs"]:
                    if ct["usageType"] != "NOT_USED":
                        # Create the CT data
                        ct_data = {}
                        ct_data["name"] = ct["usageType"]
                        ct_data["id"] = str(ct["id"])
                        ct_data["panel_id"] = panel["id"]
                        ct_data["channel"] = str(ct["channel"])
                        # Store individual power values for WebSocket partial update caching
                        ct_data["power1"] = self.none_to_zero(ct, "activePower")
                        ct_data["power2"] = self.none_to_zero(ct, "activePower2")
                        ct_data["power"] = ct_data["power1"] + ct_data["power2"]
                        # Store individual consumption values for WebSocket partial update caching
                        ct_data["consumption1"] = self.none_to_zero(ct, "energyConsumption")
                        ct_data["consumption2"] = self.none_to_zero(ct, "energyConsumption2")
                        ct_data["consumption"] = ct_data["consumption1"] + ct_data["consumption2"]
                        # Store individual import values for WebSocket partial update caching
                        ct_data["import1"] = self.none_to_zero(ct, "energyImport")
                        ct_data["import2"] = self.none_to_zero(ct, "energyImport2")
                        ct_data["import"] = ct_data["import1"] + ct_data["import2"]
                        ct_data["current"] = (
                            self.none_to_zero(ct, "rmsCurrent")
                            + self.none_to_zero(ct, "rmsCurrent2")
                        ) / 2
                        ct_data["current1"] = self.none_to_zero(ct, "rmsCurrent")
                        ct_data["current2"] = self.none_to_zero(ct, "rmsCurrent2")
                        # Add the CT to the list.
                        cts[ct_data["id"]] = ct_data
            else:
                _LOGGER.debug(f"[v{self.version}] Panel {panel.get('name', panel['id'])} ({panel.get('ModuleType', 'unknown')}): No CTs key or empty CTs (CTs key present: {'CTs' in panel}, value: {type(panel.get('CTs')).__name__})")
            totalPower = 0.0
            if "residentialBreakers" in panel and panel["residentialBreakers"]: # Add check
                for breaker in panel["residentialBreakers"]:
                    if (
                        breaker["model"] is not None
                        and breaker["model"] != "NONE-2"
                        and breaker["model"] != "NONE-1"
                    ):
                        breaker_data = {}
                        breaker_data["panel_id"] = panel["id"]
                        breaker_data["rating"] = breaker["currentRating"]
                        breaker_data["position"] = breaker["position"]
                        breaker_data["name"] = breaker["name"]
                        breaker_data["state"] = breaker["currentState"]
                        breaker_data["id"] = breaker["id"]
                        breaker_data["model"] = breaker["model"]
                        breaker_data["poles"] = breaker["poles"]
                        breaker_data["serialNumber"] = breaker["serialNumber"]
                        breaker_data["hardware"] = breaker["hwVersion"]
                        breaker_data["firmware"] = breaker["firmwareVersionMeter"]
                        if breaker["canRemoteOn"] is not None:
                            breaker_data["canRemoteOn"] = breaker["canRemoteOn"]
                        else:
                            breaker_data["canRemoteOn"] = False
                        if breaker["remoteState"] is not None:
                            breaker_data["remoteState"] = breaker["remoteState"]
                            if breaker_data["remoteState"] == "":
                                breaker_data["remoteState"] = "RemoteON"
                        else:
                            breaker_data["remoteState"] = "RemoteON"
                        _p1_raw = self._none_or_float(breaker, "power")
                        _p2_raw = self._none_or_float(breaker, "power2")
                        if _p1_raw is None and _p2_raw is None:
                            breaker_data["power"] = None
                        else:
                            breaker_data["power"] = (_p1_raw or 0.0) + (_p2_raw or 0.0)
                        if (three_phase is False) or (breaker["poles"] == 1):
                            breaker_data["voltage"] = self.none_to_zero(
                                breaker, "rmsVoltage"
                            ) + self.none_to_zero(breaker, "rmsVoltage2")
                        else:
                            breaker_data["voltage"] = (
                                self.none_to_zero(breaker, "rmsVoltage") * 0.866025403784439
                            ) + (
                                self.none_to_zero(breaker, "rmsVoltage2")
                                * 0.866025403784439
                            )

                        if breaker["poles"] == 2:
                            breaker_data["frequency"] = (
                                self.none_to_zero(breaker, "lineFrequency")
                                + self.none_to_zero(breaker, "lineFrequency2")
                            ) / 2.0
                            _c1_raw = self._none_or_float(breaker, "rmsCurrent")
                            _c2_raw = self._none_or_float(breaker, "rmsCurrent2")
                            if _c1_raw is None and _c2_raw is None:
                                breaker_data["current"] = None
                            else:
                                breaker_data["current"] = (
                                    (_c1_raw or 0.0) + (_c2_raw or 0.0)
                                ) / 2
                        else:
                            breaker_data["frequency"] = self.none_to_zero(
                                breaker, "lineFrequency"
                            )
                            _c1_raw = self._none_or_float(breaker, "rmsCurrent")
                            _c2_raw = self._none_or_float(breaker, "rmsCurrent2")
                            if _c1_raw is None and _c2_raw is None:
                                breaker_data["current"] = None
                            else:
                                breaker_data["current"] = (_c1_raw or 0.0) + (_c2_raw or 0.0)
                        if breaker["position"] in _LEG1_POSITIONS:
                            breaker_data["leg"] = 1
                            breaker_data["power1"] = self._none_or_float(breaker, "power")
                            breaker_data["power2"] = self._none_or_float(breaker, "power2")
                            breaker_data["voltage1"] = self.none_to_zero(
                                breaker, "rmsVoltage"
                            )
                            breaker_data["voltage2"] = self.none_to_zero(
                                breaker, "rmsVoltage2"
                            )
                            breaker_data["current1"] = self._none_or_float(
                                breaker, "rmsCurrent"
                            )
                            breaker_data["current2"] = self._none_or_float(
                                breaker, "rmsCurrent2"
                            )
                            breaker_data["frequency1"] = self.none_to_zero(
                                breaker, "lineFrequency"
                            )
                            breaker_data["frequency2"] = self.none_to_zero(
                                breaker, "lineFrequency2"
                            )
                        else:
                            breaker_data["leg"] = 2
                            breaker_data["power1"] = self._none_or_float(breaker, "power2")
                            breaker_data["power2"] = self._none_or_float(breaker, "power")
                            breaker_data["voltage1"] = self.none_to_zero(
                                breaker, "rmsVoltage2"
                            )
                            breaker_data["voltage2"] = self.none_to_zero(
                                breaker, "rmsVoltage"
                            )
                            breaker_data["current1"] = self._none_or_float(
                                breaker, "rmsCurrent2"
                            )
                            breaker_data["current2"] = self._none_or_float(
                                breaker, "rmsCurrent"
                            )
                            breaker_data["frequency1"] = self.none_to_zero(
                                breaker, "lineFrequency2"
                            )
                            breaker_data["frequency2"] = self.none_to_zero(
                                breaker, "lineFrequency"
                            )
                        # Capture energy counters (if present on this breaker).
                        # These are hardware-measured cumulative values — more
                        # accurate than power×time integration. Stored for data
                        # capture/logging; not yet exposed as sensor entities.
                        breaker_data["consumption1"] = self.none_to_zero(breaker, "energyConsumption")
                        breaker_data["consumption2"] = self.none_to_zero(breaker, "energyConsumption2")
                        breaker_data["consumption"] = breaker_data["consumption1"] + breaker_data["consumption2"]
                        breaker_data["import1"] = self.none_to_zero(breaker, "energyImport")
                        breaker_data["import2"] = self.none_to_zero(breaker, "energyImport2")
                        breaker_data["import"] = breaker_data["import1"] + breaker_data["import2"]
                        
                        # Add the breaker to the list.
                        breakers[breaker["id"]] = breaker_data
                        try:
                            breaker_power = breaker_data["power"]
                            if breaker_power is not None:
                                totalPower += float(breaker_power)
                        except (ValueError, TypeError):
                            totalPower += 0
            status_data[panel["id"] + "totalPower"] = totalPower
            
            # Detect hardware energy counters for this panel.
            # If any breaker has a non-zero energyConsumption, the panel supports
            # hardware counters and we can use them for daily energy tracking.
            # If not, fall back to power×time integration.
            has_hw = False
            for b_id, b_data in breakers.items():
                if b_data.get("panel_id") == panel["id"]:
                    ec = breaker.get("energyConsumption") if hasattr(breaker, 'get') else None
                    # Check our parsed data — consumption > 0 means counters exist
                    if b_data.get("consumption", 0) > 0 or b_data.get("consumption1", 0) > 0:
                        has_hw = True
                        break
            self._panel_has_hw_counters[panel["id"]] = has_hw
            if has_hw:
                _LOGGER.info(
                    f"[v{self.version}] Panel '{panel.get('name', panel['id'])}': "
                    f"hardware energy counters detected — using for daily energy"
                )
            else:
                _LOGGER.info(
                    f"[v{self.version}] Panel '{panel.get('name', panel['id'])}': "
                    f"no hardware energy counters — using power×time fallback for daily energy"
                )
        
        # Save cache for WS
        self.status_data = status_data
        status_data["breakers"] = breakers
        status_data["cts"] = cts
        status_data["panels"] = panels

        _LOGGER.debug(f"[v{self.version}] parse_panels complete: {len(panels)} panels, {len(breakers)} breakers, {len(cts)} CTs")

        return status_data

    def _construct_auth_payload(self):
        """Construct the correct auth payload for WebSocket handshake."""
        from datetime import datetime, timezone
        
        # Case 1: We have the full response from a fresh login
        if self.full_auth_response:
            # full_auth_response is the login response which IS the token object
            return {"token": self.full_auth_response}
        
        # Case 2: We only have the stored auth_token and userid (e.g. from refresh)
        return {
            "token": {
                "id": self.auth_token,
                "userId": self.userid,
                "ttl": 5184000, 
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "scopes": None
            }
        }

    def _bandwidth_toggle(self, panel_id: str, panel_type: str = "WHEMS"):
        """Toggle bandwidth 1→0→1 to force the panel to refresh its energy counters.
        
        The Leviton web app does this exact sequence before fetching CT data.
        Just sending bandwidth:1 repeatedly doesn't trigger a new reading —
        the panel needs to see the 0→1 transition to push fresh
        energyConsumption/energyImport values to the cloud.
        
        While the toggle is in progress, the zero-transition guard suppresses
        zero-counter increments for breakers on this panel, because the
        bandwidth:0 step causes the cloud to send transient zeros.
        """
        # Mark this panel as "in toggle" so the zero guard suppresses
        # zero-counter increments for its breakers during the brief
        # bandwidth:0 window.
        self._panels_in_bandwidth_toggle.add(panel_id)

        if panel_type == "LDATA":
            url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}"
        else:
            url = f"https://my.leviton.com/api/IotWhems/{panel_id}"
        
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        
        try:
            # Step 1: bandwidth:1 (wake up)
            r1 = self.session.put(url, headers=headers, json={"bandwidth": 1}, timeout=5)
            if r1.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth expired during bandwidth toggle (step 1): {r1.status_code}")
            # Step 2: bandwidth:0 (turn off)
            r2 = self.session.put(url, headers=headers, json={"bandwidth": 0}, timeout=5)
            if r2.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth expired during bandwidth toggle (step 2): {r2.status_code}")
            # Step 3: bandwidth:1 (turn back on — this 0→1 transition triggers the refresh)
            r3 = self.session.put(url, headers=headers, json={"bandwidth": 1}, timeout=5)
            if r3.status_code in (401, 403, 406):
                raise LDATAAuthError(f"[v{self.version}] Auth expired during bandwidth toggle (step 3): {r3.status_code}")
            _LOGGER.debug(f"[v{self.version}] Bandwidth toggle 1→0→1 for {panel_type} panel {panel_id}")
        except LDATAAuthError:
            raise
        except Exception as e:
            _LOGGER.debug(f"[v{self.version}] Bandwidth toggle for panel {panel_id}: {e}")
        finally:
            # Clear the toggle flag.  Use discard() so it's safe even if
            # the flag was already removed (shouldn't happen, but defensive).
            self._panels_in_bandwidth_toggle.discard(panel_id)

    def refresh_breaker_data(self) -> bool:
        """Re-fetch breaker data from the REST API and merge into status_data.
        
        FALLBACK mechanism for panels without hardware energy counters.
        Only activates for panels where _panel_needs_rest_poll is True
        (older firmware, or WS not delivering breaker data).
        
        Returns True if data was successfully refreshed.
        """
        if not self.status_data or not self.status_data.get("panels"):
            return False
        
        if not self.auth_token:
            return False
        
        # Check if any panel needs REST polling
        if not any(self._panel_needs_rest_poll.values()):
            return False
        
        # Serialize with CT poll to prevent bandwidth:0 toggle from corrupting
        # breaker data mid-fetch.
        acquired = self._rest_poll_lock.acquire(timeout=30)
        if not acquired:
            _LOGGER.warning(f"[v{self.version}] Breaker poll timed out waiting for lock — skipping this cycle")
            return False
        try:
            return self._refresh_breaker_data_locked()
        finally:
            self._rest_poll_lock.release()

    def _refresh_breaker_data_locked(self) -> bool:
        """Inner implementation of refresh_breaker_data, called under _rest_poll_lock.
        
        On panels with hardware energy counters, skips the breaker REST fetch
        (those get data via WS) but still does the bandwidth toggle and CT fetch
        since CTs always need the toggle to refresh their energy counters.
        """
        
        new_status_data = self.status_data.copy()
        breakers = new_status_data.get("breakers", {}).copy()
        cts = new_status_data.get("cts", {}).copy()
        updated = False
        panels_with_power_change = set()
        
        for panel_data in new_status_data.get("panels", []):
            panel_id = panel_data.get("id")
            panel_type = panel_data.get("panel_type", "WHEMS")
            
            if not panel_id or not self._panel_needs_rest_poll.get(panel_id, False):
                continue
            
            has_hw = self._panel_has_hw_counters.get(panel_id, False)
            
            try:
                self._bandwidth_toggle(panel_id, panel_type)
                
                # Fetch fresh breaker data for ALL panels.
                # Power/current from REST keeps watts/amps sensors alive
                # even when the IotWhem WS doesn't deliver per-breaker
                # power data.  The zero-transition guard in the sensor
                # layer handles any transient zeros from the bandwidth
                # toggle — no need to filter at the data layer.
                raw_breakers = self.get_Whems_breakers(panel_id)
                if raw_breakers:
                    for breaker in raw_breakers:
                        if (
                            breaker.get("model") is not None
                            and breaker["model"] != "NONE-2"
                            and breaker["model"] != "NONE-1"
                        ):
                            b_id = breaker["id"]
                            if b_id in breakers:
                                existing = breakers[b_id].copy()
                                power_changed = self._apply_breaker_update(
                                    b_id, existing, breaker, source="REST",
                                )
                                if power_changed:
                                    panels_with_power_change.add(existing.get("panel_id"))
                                breakers[b_id] = existing
                                updated = True
                
                # Fetch fresh CT data
                raw_cts = self.get_Whems_CT(panel_id)
                if raw_cts:
                    for ct in raw_cts:
                        if ct.get("usageType") != "NOT_USED":
                            ct_id = str(ct["id"])
                            if ct_id in cts:
                                existing_ct = cts[ct_id].copy()
                                self._apply_ct_update(existing_ct, ct)
                                cts[ct_id] = existing_ct
                                updated = True
                
            except LDATAAuthError:
                raise
            except Exception as e:
                _LOGGER.warning(f"[v{self.version}] Error refreshing data for panel {panel_id}: {e}")
        
        if updated:
            new_status_data["breakers"] = breakers
            new_status_data["cts"] = cts
            for pid in panels_with_power_change:
                if pid:
                    self._recalc_total_power(new_status_data, pid)
            self.status_data = new_status_data
        
        return updated

    @property
    def needs_rest_poll(self) -> bool:
        """Return True if any panel requires REST polling for breaker/CT data."""
        return any(self._panel_needs_rest_poll.values())

    def panel_has_hw_counters(self, panel_id: str) -> bool:
        """Return True if the given panel has hardware energy counters."""
        return self._panel_has_hw_counters.get(panel_id, False)

    def refresh_ct_data(self) -> bool:
        """Re-fetch only CT data from the REST API and merge into status_data.
        
        FALLBACK mechanism — only runs for panels where WS auto-detection has
        confirmed that WebSocket does not deliver energyConsumption/energyImport.
        
        Lightweight alternative to refresh_breaker_data that only polls the
        /iotCts endpoint. Uses bandwidth toggle (1→0→1) to force the panel
        to push fresh energy counter values to the cloud.
        
        Returns True if data was successfully refreshed.
        """
        if not self.status_data or not self.status_data.get("panels"):
            return False
        
        if not self.auth_token:
            return False
        
        # Serialize with breaker poll so bandwidth:0 toggle doesn't corrupt
        # a concurrent breaker GET.
        acquired = self._rest_poll_lock.acquire(timeout=30)
        if not acquired:
            _LOGGER.warning(f"[v{self.version}] CT poll timed out waiting for lock — skipping this cycle")
            return False
        try:
            return self._refresh_ct_data_locked()
        finally:
            self._rest_poll_lock.release()

    def _refresh_ct_data_locked(self) -> bool:
        """Inner implementation of refresh_ct_data, called under _rest_poll_lock."""
        
        new_status_data = self.status_data.copy()
        cts = new_status_data.get("cts", {}).copy()
        updated = False
        
        for panel_data in new_status_data.get("panels", []):
            panel_id = panel_data.get("id")
            
            if not panel_id or not self._panel_needs_rest_poll.get(panel_id, False):
                continue
            
            try:
                panel_type = panel_data.get("panel_type", "WHEMS")
                self._bandwidth_toggle(panel_id, panel_type)
                
                raw_cts = self.get_Whems_CT(panel_id)
                if raw_cts:
                    for ct in raw_cts:
                        if ct.get("usageType") != "NOT_USED":
                            ct_id = str(ct["id"])
                            if ct_id in cts:
                                existing_ct = cts[ct_id].copy()
                                self._apply_ct_update(existing_ct, ct)
                                cts[ct_id] = existing_ct
                                updated = True
                
            except LDATAAuthError:
                raise
            except Exception as e:
                _LOGGER.warning(f"[v{self.version}] Error refreshing CT data for panel {panel_id}: {e}")
        
        if updated:
            new_status_data["cts"] = cts
            self.status_data = new_status_data
        
        return updated

    def _update_from_websocket(self, payload):
        """Update the internal status_data cache from a WebSocket notification.
        
        PARTIAL UPDATE HANDLING:
        WebSocket updates may only contain one of activePower/activePower2.
        We cache the individual values (power1, power2) so that when only one
        value comes in, we use the cached value for the other instead of 0.
        """
        if not self.status_data:
            return None

        model_name = payload.get("modelName")
        data = payload.get("data")
        
        if not data:
            return None

        # COPY-ON-WRITE STRATEGY:
        # We must create a new top-level dictionary for self.status_data
        # so that the Coordinator detects a reference change and updates listeners.
        # We also need to copy the nested dictionaries we are modifying.
        
        new_status_data = self.status_data.copy()
        updated = False

        # Handle ResidentialBreaker (The most common update)
        if model_name == "ResidentialBreaker":
             # Power/current payloads may omit 'id' from data — fall back
             # to modelId from the notification envelope.
             breaker_id = data.get("id") or payload.get("modelId")
             if breaker_id and breaker_id in new_status_data["breakers"]:
                  breakers = new_status_data["breakers"].copy()
                  breaker = breakers[breaker_id].copy()
                  
                  power_changed = self._apply_breaker_update(breaker_id, breaker, data, source="WS")
                  
                  breakers[breaker_id] = breaker
                  new_status_data["breakers"] = breakers
                  
                  # Recalculate totalPower for the breaker's panel if power changed
                  if power_changed:
                      panel_id = breaker.get("panel_id")
                      if panel_id:
                          self._recalc_total_power(new_status_data, panel_id)
                  
                  updated = True

        # Handle IotCt (CT Clamps)
        elif model_name == "IotCt":
             ct_id = str(data.get("id") or payload.get("modelId", ""))
             if ct_id and ct_id in new_status_data["cts"]:
                  cts = new_status_data["cts"].copy()
                  ct = cts[ct_id].copy()
                  self._apply_ct_update(ct, data)
                  cts[ct_id] = ct
                  new_status_data["cts"] = cts
                  updated = True
                  
        # Handle IotWhem (The Panel itself)
        elif model_name == "IotWhem":
             panel_id = data.get("id")
             has_breaker_data = "ResidentialBreaker" in data
             has_ct_data = "IotCt" in data
             
             # --- Auto-detection of REST polling need ---
             # WS-first strategy: track whether IotWhem WS messages contain
             # breaker ELECTRICAL data (power/current/voltage).
             # The cloud sends two kinds of embedded breaker updates:
             #   1. Status-only: {env, bleRSSI, connected, lastUpdated} — NOT useful
             #   2. Electrical:  {power, rmsCurrent, rmsVoltage, ...} — useful
             # Only type (2) should count as "WS is delivering breaker data".
             has_electrical_data = False
             if has_breaker_data:
                 for b_check in data["ResidentialBreaker"]:
                     if any(k in b_check for k in ("power", "power2", "rmsCurrent", "rmsCurrent2", "rmsVoltage", "rmsVoltage2")):
                         has_electrical_data = True
                         break
             
             if panel_id and panel_id in self._ws_iotwhem_count:
                 if has_electrical_data:
                     self._ws_last_breaker_data_time[panel_id] = time.time()
                     self._ws_iotwhem_count[panel_id] = 0
                 else:
                     self._ws_iotwhem_count[panel_id] = self._ws_iotwhem_count.get(panel_id, 0) + 1
                     # Log for diagnostics but don't enable breaker REST polling —
                     # breaker energyConsumption arrives via WS, no REST needed.
                     if self._ws_iotwhem_count[panel_id] == self._WS_DETECTION_THRESHOLD:
                         _LOGGER.debug(
                             f"[v{self.version}] Panel {panel_id}: {self._ws_iotwhem_count[panel_id]} "
                             f"IotWhem WS messages without breaker electrical data (expected for FW 2.0+ — "
                             f"breaker data arrives via individual subscriptions)"
                         )
             
             if has_breaker_data:
                  breakers = new_status_data["breakers"].copy()
                  panels_with_power_change = set()
                  for b_data in data["ResidentialBreaker"]:
                       b_id = b_data.get("id")
                       if b_id and b_id in breakers:
                            breaker = breakers[b_id].copy()
                            power_changed = self._apply_breaker_update(
                                b_id, breaker, b_data, source="WS-bulk"
                            )
                            if power_changed:
                                panels_with_power_change.add(breaker.get("panel_id"))
                            breakers[b_id] = breaker
                            updated = True
                  if updated:
                      new_status_data["breakers"] = breakers
                      for pid in panels_with_power_change:
                          if pid:
                              self._recalc_total_power(new_status_data, pid)

             if "IotCt" in data:
                  cts = new_status_data["cts"].copy()
                  for ct_data_item in data["IotCt"]:
                       ct_id = str(ct_data_item.get("id"))
                       if ct_id and ct_id in cts:
                            ct = cts[ct_id].copy()
                            self._apply_ct_update(ct, ct_data_item)
                            cts[ct_id] = ct
                            updated = True
                  if updated:
                      new_status_data["cts"] = cts

             # Handle panel-level properties (connected, voltage, frequency)
             panel_id = data.get("id")
             if panel_id and new_status_data.get("panels"):
                  panels = new_status_data["panels"].copy()
                  for i, panel in enumerate(panels):
                       if panel.get("id") == panel_id:
                            panel = panel.copy()
                            
                            # Update connected status
                            if "connected" in data:
                                panel["connected"] = data["connected"]
                            
                            # Update voltage
                            if "rmsVoltage" in data or "rmsVoltage2" in data or "rmsVoltageA" in data or "rmsVoltageB" in data:
                                # Handle both naming conventions
                                v1 = data.get("rmsVoltage") or data.get("rmsVoltageA")
                                v2 = data.get("rmsVoltage2") or data.get("rmsVoltageB")
                                
                                if v1 is not None:
                                    panel["voltage1"] = float(v1)
                                if v2 is not None:
                                    panel["voltage2"] = float(v2)
                                
                                if panel.get("voltage1") is not None and panel.get("voltage2") is not None:
                                    panel["voltage"] = panel["voltage1"] + panel["voltage2"]
                            
                            # Update frequency
                            if "frequencyA" in data or "frequencyB" in data:
                                if data.get("frequencyA") is not None:
                                    panel["frequency1"] = float(data["frequencyA"])
                                if data.get("frequencyB") is not None:
                                    panel["frequency2"] = float(data["frequencyB"])
                                
                                if panel.get("frequency1") is not None and panel.get("frequency2") is not None:
                                    panel["frequency"] = (panel["frequency1"] + panel["frequency2"]) / 2
                            
                            panels[i] = panel
                            new_status_data["panels"] = panels
                            updated = True
                            break

        if updated:
            self.status_data = new_status_data
            return True
            
        return None

    async def async_run_websocket(self, update_callback, connection_callback=None):
        """Run the WebSocket connection loop — PRIMARY data source.
        
        WS-FIRST Strategy:
        - WebSocket is always the preferred data transport
        - All panels (regardless of firmware) start with WS-only
        - REST polling is ONLY enabled as a fallback after auto-detection
          confirms WS is not delivering breaker data for a specific panel
        
        Keepalive (based on official Leviton app):
        - PUT bandwidth:1 every 50 seconds (keeps WS alive)
        - GET /apiversion every 10 seconds (keeps server session alive)
        - Subscribe once at start, re-subscribe if no data for 60 seconds
        """
        uri = "wss://socket.cloud.leviton.com/"
        reconnect_delay = 10
        max_delay = 300
        
        BANDWIDTH_PUT_INTERVAL = 50      # PUT bandwidth:1 every 50 seconds to keep cloud active
        # The cloud decays bandwidth:1 to :2 within ~2 seconds. The official
        # app sends every 50s but has the UI open which generates additional
        # activity. Without the app UI, we need more frequent PUTs to keep
        # the cloud pushing breaker data via WS.
        APIVERSION_HEARTBEAT_INTERVAL = 10  # GET /apiversion every 10 seconds (keeps server session alive)
        STALE_DATA_THRESHOLD = 60        # Re-subscribe if no data for 60 seconds
        PROACTIVE_RECONNECT = 3300       # Proactively reconnect every 55 minutes (before server timeout)
        
        _LOGGER.debug(f"[v{self.version}] WebSocket task starting...")
        
        # Track if this is the initial connection (for logging purposes)
        initial_connection = True
        
        # Helper to safely call connection callback
        def notify_connection(connected: bool):
            if connection_callback:
                try:
                    connection_callback(connected)
                except Exception as e:
                    _LOGGER.error(f"[v{self.version}] Connection callback error: {e}")
        
        while not self._shutdown_requested:
            try:
                # Ensure we have a valid token
                if not self.auth_token:
                    _LOGGER.debug(f"[v{self.version}] No auth token, waiting...")
                    notify_connection(False)
                    await asyncio.sleep(10)
                    continue
                
                # Use a single session for both WebSocket AND HTTP calls
                async with aiohttp.ClientSession(
                    headers={
                        "User-Agent": defaultHeaders["user-agent"],
                        "Accept-Language": defaultHeaders["Accept-Language"],
                        "Accept-Encoding": defaultHeaders["Accept-Encoding"],
                    }
                ) as session:
                    
                    # Get ALL panels with their types for bandwidth keepalive
                    panel_info = []
                    if self.status_data and self.status_data.get("panels"):
                        panel_info = [
                            (p.get("id"), p.get("panel_type", "WHEMS"))
                            for p in self.status_data["panels"]
                            if p.get("id")
                        ]
                    
                    # Bandwidth PUT function - this is what keeps the WebSocket alive
                    # v1.54.2 HAR shows the app sends TWO bandwidth:1 PUTs back-to-back
                    # every 50 seconds. Must PUT to EVERY panel using the correct endpoint.
                    async def bandwidth_put():
                        if not panel_info:
                            return
                        headers = {
                            "Authorization": self.auth_token,
                            "Content-Type": "application/json",
                            "Origin": "https://myapp.leviton.com",
                            "Referer": "https://myapp.leviton.com/",
                            "Sec-Fetch-Dest": "empty",
                            "Sec-Fetch-Mode": "cors",
                            "Sec-Fetch-Site": "same-site",
                            "DNT": "1",
                        }
                        # Send TWO bandwidth:1 PUTs per panel (matches v1.54.2 app behavior)
                        for _round in range(2):
                            for panel_id, panel_type in panel_info:
                                try:
                                    if panel_type == "LDATA":
                                        url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}"
                                    else:
                                        url = f"https://my.leviton.com/api/IotWhems/{panel_id}"
                                    async with session.put(
                                        url,
                                        headers=headers,
                                        json={"bandwidth": 1},
                                        timeout=aiohttp.ClientTimeout(total=10)
                                    ) as resp:
                                        _LOGGER.debug(f"[v{self.version}] Bandwidth PUT {panel_type} panel {panel_id} (round {_round+1}): {resp.status}")
                                except aiohttp.ClientConnectionResetError:
                                    _LOGGER.debug(f"[v{self.version}] Bandwidth PUT panel {panel_id}: connection reset (expected)")
                                except asyncio.CancelledError:
                                    raise
                                except Exception as e:
                                    _LOGGER.debug(f"[v{self.version}] Bandwidth PUT panel {panel_id} failed: {e}")
                    
                    # API version heartbeat - the Leviton web app polls this every ~10s.
                    # This keeps the server-side session warm so the cloud continues
                    # pushing data and honoring the bandwidth:1 setting for v2 firmware.
                    async def apiversion_heartbeat():
                        try:
                            async with session.get(
                                "https://my.leviton.com/apiversion",
                                headers={
                                    "Authorization": self.auth_token,
                                    "Origin": "https://myapp.leviton.com",
                                    "Referer": "https://myapp.leviton.com/",
                                    "Accept": "application/json, text/plain, */*",
                                    "Sec-Fetch-Dest": "empty",
                                    "Sec-Fetch-Mode": "cors",
                                    "Sec-Fetch-Site": "same-site",
                                },
                                timeout=aiohttp.ClientTimeout(total=10)
                            ) as resp:
                                _LOGGER.debug(f"[v{self.version}] API version heartbeat: {resp.status}")
                        except asyncio.CancelledError:
                            raise
                        except Exception as e:
                            _LOGGER.debug(f"[v{self.version}] API version heartbeat failed: {e}")
                    
                    # Initial bandwidth PUT
                    await bandwidth_put()
                    
                    # Initial apiversion heartbeat
                    await apiversion_heartbeat()
                    
                    try:
                        ws = await session.ws_connect(
                            uri, 
                            headers={
                                "Origin": "https://myapp.leviton.com",
                                "Cache-Control": "no-cache",
                                "Pragma": "no-cache",
                                "Sec-WebSocket-Extensions": "permessage-deflate",
                                "Sec-Fetch-Dest": "empty",
                                "Sec-Fetch-Mode": "websocket",
                                "Sec-Fetch-Site": "cross-site",
                                "DNT": "1",
                                "Sec-GPC": "1",
                            },
                            compress=15,
                        )
                    except Exception as e:
                        _LOGGER.warning(f"[v{self.version}] WS connect failed: {e}")
                        notify_connection(False)
                        await asyncio.sleep(reconnect_delay)
                        reconnect_delay = min(reconnect_delay * 2, max_delay)
                        continue
                    
                    if initial_connection:
                        _LOGGER.debug(f"[v{self.version}] WebSocket connected.")
                    else:
                        _LOGGER.debug(f"[v{self.version}] WebSocket reconnected.")
                    
                    try:
                        # 1. Authenticate
                        auth_payload = self._construct_auth_payload()
                        try:
                            if ws.closed:
                                _LOGGER.debug(f"[v{self.version}] WS closed before auth")
                                continue
                            await ws.send_json(auth_payload)
                        except (aiohttp.ClientConnectionResetError, ConnectionResetError):
                            _LOGGER.warning(f"[v{self.version}] Connection reset during auth")
                            continue
                        
                        # 2. Wait for Ready
                        is_ready = False
                        try:
                            deadline = asyncio.get_event_loop().time() + 10
                            while not is_ready:
                                remaining = deadline - asyncio.get_event_loop().time()
                                if remaining <= 0:
                                    raise asyncio.TimeoutError()
                                
                                msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
                                if msg.type == aiohttp.WSMsgType.TEXT:
                                    data = json.loads(msg.data)
                                    if data.get("status") == "ready":
                                        is_ready = True
                                        if initial_connection:
                                            _LOGGER.debug(f"[v{self.version}] WebSocket authenticated.")
                                        else:
                                            _LOGGER.debug(f"[v{self.version}] WebSocket re-authenticated.")
                                        break
                                    elif "error" in data:
                                        _LOGGER.error(f"[v{self.version}] Auth error: {data}")
                                        break
                                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                                    break
                        except asyncio.TimeoutError:
                            _LOGGER.warning(f"[v{self.version}] WebSocket auth timed out.")
                            try:
                                await ws.close()
                            except aiohttp.ClientConnectionResetError:
                                pass
                            continue

                        if not is_ready:
                            try:
                                await ws.close()
                            except aiohttp.ClientConnectionResetError:
                                pass
                            continue
                        
                        # 3. Build and send subscriptions ONCE
                        retry_count = 0
                        while not self.status_data and retry_count < 5:
                            await asyncio.sleep(2)
                            retry_count += 1

                        subscriptions = []
                        for residence_id in self.residence_id_list:
                            try:
                                res_id = int(residence_id)
                            except (ValueError, TypeError):
                                res_id = residence_id
                            subscriptions.append({
                                "type": "subscribe",
                                "subscription": {"modelName": "Residence", "modelId": res_id}
                            })
                        
                        if self.status_data:
                            for panel in self.status_data.get("panels", []):
                                subscriptions.append({
                                    "type": "subscribe", 
                                    "subscription": {"modelName": "IotWhem", "modelId": panel["id"]}
                                })
                            
                            for b_id in self.status_data.get("breakers", {}):
                                subscriptions.append({
                                    "type": "subscribe",
                                    "subscription": {"modelName": "ResidentialBreaker", "modelId": b_id}
                                })
                            
                            for ct_id in self.status_data.get("cts", {}):
                                subscriptions.append({
                                    "type": "subscribe",
                                    "subscription": {"modelName": "IotCt", "modelId": int(ct_id)}
                                })
                        
                        async def send_subscriptions(is_initial=False):
                            try:
                                for sub in subscriptions:
                                    if ws.closed:
                                        _LOGGER.debug(f"[v{self.version}] send_subscriptions: ws already closed")
                                        return
                                    try:
                                        await ws.send_json(sub)
                                    except (aiohttp.ClientConnectionResetError, ConnectionResetError):
                                        _LOGGER.debug(f"[v{self.version}] send_subscriptions: connection reset during send")
                                        raise aiohttp.ClientConnectionResetError("Connection reset during send")
                                if is_initial:
                                    _LOGGER.debug(f"[v{self.version}] Sent {len(subscriptions)} subscriptions.")
                                else:
                                    _LOGGER.debug(f"[v{self.version}] Re-sent {len(subscriptions)} subscriptions.")
                            except aiohttp.ClientConnectionResetError:
                                _LOGGER.debug(f"[v{self.version}] send_subscriptions: connection reset")
                                raise
                            except asyncio.CancelledError:
                                raise
                        
                        try:
                            await send_subscriptions(is_initial=initial_connection)
                        except aiohttp.ClientConnectionResetError:
                            _LOGGER.debug(f"[v{self.version}] Connection reset during initial subscribe")
                            continue
                        notify_connection(True)
                        
                        # Mark initial connection complete after successful subscription
                        initial_connection = False

                        # 4. Main listen loop
                        message_count = 0
                        bandwidth_put_count = 0
                        heartbeat_count = 0
                        resubscribe_count = 0
                        start_time = asyncio.get_event_loop().time()
                        last_bandwidth_put_time = start_time
                        last_heartbeat_time = start_time
                        last_data_time = start_time
                        
                        while True:
                            current_time = asyncio.get_event_loop().time()
                            
                            # Bandwidth PUT every 20 seconds (this keeps WebSocket alive!)
                            if current_time - last_bandwidth_put_time >= BANDWIDTH_PUT_INTERVAL:
                                bandwidth_put_count += 1
                                last_bandwidth_put_time = current_time
                                async def _safe_bandwidth_put():
                                    try:
                                        await bandwidth_put()
                                    except (aiohttp.ClientConnectionResetError, ConnectionResetError):
                                        pass  # Expected during shutdown/reconnect
                                    except asyncio.CancelledError:
                                        pass
                                    except Exception:
                                        pass
                                asyncio.create_task(_safe_bandwidth_put())
                                _LOGGER.debug(f"[v{self.version}] Bandwidth PUT #{bandwidth_put_count} ({len(panel_info)} panels)")
                            
                            # API version heartbeat every 10 seconds (keeps server session alive for v2 firmware)
                            if current_time - last_heartbeat_time >= APIVERSION_HEARTBEAT_INTERVAL:
                                heartbeat_count += 1
                                last_heartbeat_time = current_time
                                async def _safe_heartbeat():
                                    try:
                                        await apiversion_heartbeat()
                                    except (aiohttp.ClientConnectionResetError, ConnectionResetError):
                                        pass
                                    except asyncio.CancelledError:
                                        pass
                                    except Exception:
                                        pass
                                asyncio.create_task(_safe_heartbeat())
                            
                            # Re-subscribe if no data for 60 seconds (max 5 per connection)
                            if current_time - last_data_time >= STALE_DATA_THRESHOLD:
                                resubscribe_count += 1
                                last_data_time = current_time
                                if resubscribe_count <= 5:
                                    _LOGGER.debug(f"[v{self.version}] No data for {STALE_DATA_THRESHOLD}s, re-subscribing (#{resubscribe_count})")
                                    try:
                                        await send_subscriptions()
                                    except aiohttp.ClientConnectionResetError:
                                        _LOGGER.debug(f"[v{self.version}] Connection reset during re-subscribe")
                                        break
                                else:
                                    _LOGGER.warning(f"[v{self.version}] Re-subscribe limit reached (#{resubscribe_count}), forcing reconnect")
                                    break
                            
                            # Proactive reconnect every 55 minutes (before server forces disconnect)
                            if current_time - start_time >= PROACTIVE_RECONNECT:
                                elapsed = current_time - start_time
                                _LOGGER.debug(f"[v{self.version}] Proactive reconnect after {elapsed:.0f}s ({message_count} msgs)")
                                break
                            
                            # Receive with timeout
                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
                            except asyncio.TimeoutError:
                                continue
                            except aiohttp.ClientConnectionResetError:
                                _LOGGER.debug(f"[v{self.version}] Connection reset during receive")
                                break
                            
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                message_count += 1
                                last_data_time = current_time
                                
                                if message_count % 100 == 0:
                                    elapsed = current_time - start_time
                                    _LOGGER.debug(f"[v{self.version}] WS: {message_count} msgs, {elapsed:.0f}s, {bandwidth_put_count} PUTs, {heartbeat_count} heartbeats")
                                
                                try:
                                    payload = json.loads(msg.data)
                                    if payload.get("type") == "notification":
                                        notification = payload.get("notification", {})
                                        data = notification.get("data", {})
                                        model = notification.get("modelName")
                                        model_id = notification.get("modelId", data.get("id", "?"))
                                        fields = [k for k in data.keys() if k not in ("id", "env", "connected", "lastUpdated")]
                                        if fields:
                                            _LOGGER.debug(
                                                f"[v{self.version}] WS {model} {model_id}: {', '.join(fields)}"
                                            )
                                        if self._update_from_websocket(notification):
                                            try:
                                                update_callback()
                                            except Exception as e:
                                                _LOGGER.error(f"[v{self.version}] Callback error: {e}")
                                except (ValueError, json.JSONDecodeError) as e:
                                    _LOGGER.warning(f"[v{self.version}] Invalid JSON: {e}")
                                    
                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                _LOGGER.error(f"[v{self.version}] WS error: {ws.exception()}")
                                break
                                
                            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE):
                                elapsed = current_time - start_time
                                _LOGGER.warning(f"[v{self.version}] WS closed after {elapsed:.0f}s")
                                break
                        
                    finally:
                        notify_connection(False)
                        if not ws.closed:
                            try:
                                await ws.close()
                            except aiohttp.ClientConnectionResetError:
                                pass
                        _LOGGER.debug(f"[v{self.version}] WS session ended")
                    
                    reconnect_delay = 10
            
            except (aiohttp.ClientError, ConnectionResetError) as ex:
                notify_connection(False)
                _LOGGER.warning(f"[v{self.version}] WS client error: {ex}. Reconnecting in {reconnect_delay}s...")
            except Exception as ex:
                notify_connection(False)
                _LOGGER.error(f"[v{self.version}] WS error: {type(ex).__name__}: {ex}. Reconnecting in {reconnect_delay}s...")
            
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_delay)
