"""The LDATAService object."""

import logging
import typing
import time
import socket
import re
import os
import json
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
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0",
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
        
        # Cache for the latest status data to support WebSocket updates
        self.status_data = None
        # Storage for full auth response to support WebSocket handshake
        self.full_auth_response = None
        # Flag for graceful shutdown
        self._shutdown_requested = False

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
        
        _LOGGER.debug(
            f"[v{self.version}] Authorization attempt result {result.status_code}: {result.text}"
        )

        if result.status_code == 200:
            json_data = result.json()
            self.auth_token = json_data["id"]
            self.userid = json_data["userId"]
            self.refresh_token = json_data["id"] # Store the auth token
            self.full_auth_response = json_data # Store full response for WebSocket
            _LOGGER.debug(f"[v{self.version}] Login successful. Storing auth token.")
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

        _LOGGER.debug(f"[v{self.version}] 2FA completion result {result.status_code}: {result.text}")

        if result.status_code == 200:
            json_data = result.json()
            self.auth_token = json_data["id"]
            self.userid = json_data["userId"]
            self.refresh_token = json_data["id"] # Store the auth token
            self.full_auth_response = json_data # Store full response for WebSocket
            _LOGGER.debug(f"[v{self.version}] 2FA login successful. Storing auth token.")
            return True
        
        # Failed 2FA
        clean_msg = self._get_clean_error_msg(result.text)
        _LOGGER.warning(f"[v{self.version}] 2FA completion failed. Response: {clean_msg}")
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
                result = requests.get(url, headers=headers, timeout=15)
                
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

    def get_Whems_breakers(self, panel_id: str) -> object:
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
            self.clear_tokens()
        return None

    def get_Whems_CT(self, panel_id: str) -> object:
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
            self.clear_tokens()
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
                                self.put_residential_breaker_panels(panel["id"], panel["ModuleType"])
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

    def none_to_zero(self, dict, key) -> float:
        """Convert a value to a float and replace None with 0.0."""
        result = 0.0
        try:
            value = dict[key]
        except (KeyError, TypeError, AttributeError):
            value = None
        if value is None:
            return result
        if value is KeyError:
            return result
        try:
            result = float(value)
        except (KeyError, TypeError, AttributeError):
            result = 0.0
        return result

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
        status_data: dict[str, typing.Any] = dict[str, typing.Any]()
        breakers: dict[str, typing.Any] = dict[str, typing.Any]()
        cts: dict[str, typing.Any] = dict[str, typing.Any]()
        panels: list[typing.Any] = list[typing.Any]()
        status_data["breakers"] = breakers
        status_data["cts"] = cts
        status_data["panels"] = panels
        if panels_json is None:
            return status_data
        
        # Safely get options, as self.entry might be None during config flow
        three_phase = THREE_PHASE_DEFAULT
        if self.entry:
            three_phase = self.entry.options.get(
                THREE_PHASE, self.entry.data.get(THREE_PHASE, THREE_PHASE_DEFAULT)
            )

        for panel in panels_json:
            panel_data = {}
            panel_data["firmware"] = panel["updateVersion"]
            panel_data["model"] = panel["model"]
            panel_data["id"] = panel["id"]
            panel_data["name"] = panel["name"]
            panel_data["serialNumber"] = panel["id"]
            panel_data["panel_type"] = panel.get("ModuleType", "WHEMS")
            panel_data["connected"] = panel.get("connected", False)
            if panel.get("model") == "DAU" and panel.get("status") == "READY":
                panel_data["connected"] = True
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
                        breaker_data["power"] = self.none_to_zero(
                            breaker, "power"
                        ) + self.none_to_zero(breaker, "power2")
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
                            breaker_data["current"] = (
                                self.none_to_zero(breaker, "rmsCurrent")
                                + self.none_to_zero(breaker, "rmsCurrent2")
                            ) / 2
                        else:
                            breaker_data["frequency"] = self.none_to_zero(
                                breaker, "lineFrequency"
                            )
                            breaker_data["current"] = self.none_to_zero(
                                breaker, "rmsCurrent"
                            ) + self.none_to_zero(breaker, "rmsCurrent2")
                        if breaker["position"] in _LEG1_POSITIONS:
                            breaker_data["leg"] = 1
                            breaker_data["power1"] = self.none_to_zero(breaker, "power")
                            breaker_data["power2"] = self.none_to_zero(breaker, "power2")
                            breaker_data["voltage1"] = self.none_to_zero(
                                breaker, "rmsVoltage"
                            )
                            breaker_data["voltage2"] = self.none_to_zero(
                                breaker, "rmsVoltage2"
                            )
                            breaker_data["current1"] = self.none_to_zero(
                                breaker, "rmsCurrent"
                            )
                            breaker_data["current2"] = self.none_to_zero(
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
                            breaker_data["power1"] = self.none_to_zero(breaker, "power2")
                            breaker_data["power2"] = self.none_to_zero(breaker, "power")
                            breaker_data["voltage1"] = self.none_to_zero(
                                breaker, "rmsVoltage2"
                            )
                            breaker_data["voltage2"] = self.none_to_zero(
                                breaker, "rmsVoltage"
                            )
                            breaker_data["current1"] = self.none_to_zero(
                                breaker, "rmsCurrent2"
                            )
                            breaker_data["current2"] = self.none_to_zero(
                                breaker, "rmsCurrent"
                            )
                            breaker_data["frequency1"] = self.none_to_zero(
                                breaker, "lineFrequency2"
                            )
                            breaker_data["frequency2"] = self.none_to_zero(
                                breaker, "lineFrequency"
                            )
                        # Add the breaker to the list.
                        breakers[breaker["id"]] = breaker_data
                        try:
                            breaker_power = float(breaker_data["power"])
                            totalPower += float(breaker_power)
                        except ValueError:
                            totalPower += 0
            status_data[panel["id"] + "totalPower"] = totalPower
        
        # Save cache for WS
        self.status_data = status_data
        status_data["breakers"] = breakers
        status_data["cts"] = cts
        status_data["panels"] = panels

        _LOGGER.debug(f"[v{self.version}] parse_panels complete: {len(panels)} panels, {len(breakers)} breakers, {len(cts)} CTs")

        return status_data

    def _construct_auth_payload(self):
        """Construct the correct auth payload for WebSocket handshake."""
        from datetime import datetime
        
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
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "scopes": None
            }
        }

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
             breaker_id = data.get("id")
             if breaker_id and breaker_id in new_status_data["breakers"]:
                  # Copy the specific breaker data before modifying
                  breakers = new_status_data["breakers"].copy()
                  breaker = breakers[breaker_id].copy()
                  
                  # Get cached values for partial update handling
                  cached_p1 = breaker.get("power1", 0)
                  cached_p2 = breaker.get("power2", 0)
                  
                  # Handle power/power2 fields
                  # WebSocket may send only one of these at a time
                  # Must respect leg position mapping (leg 2 positions swap power/power2)
                  leg = breaker.get("leg", 1)
                  
                  if leg == 1:
                      # Leg 1: power -> power1, power2 -> power2
                      if "power" in data:
                          p1 = float(data["power"]) if data["power"] is not None else cached_p1
                          breaker["power1"] = p1
                      else:
                          p1 = cached_p1
                      
                      if "power2" in data:
                          p2 = float(data["power2"]) if data["power2"] is not None else cached_p2
                          breaker["power2"] = p2
                      else:
                          p2 = cached_p2
                  else:
                      # Leg 2: power -> power2, power2 -> power1 (swapped)
                      if "power" in data:
                          p2 = float(data["power"]) if data["power"] is not None else cached_p2
                          breaker["power2"] = p2
                      else:
                          p2 = cached_p2
                      
                      if "power2" in data:
                          p1 = float(data["power2"]) if data["power2"] is not None else cached_p1
                          breaker["power1"] = p1
                      else:
                          p1 = cached_p1
                  
                  # Update total power if either field was present
                  if "power" in data or "power2" in data:
                      breaker["power"] = p1 + p2
                  
                  # Handle voltage (same leg mapping as power)
                  if "rmsVoltage" in data or "rmsVoltage2" in data:
                      cached_v1 = breaker.get("voltage1", 0)
                      cached_v2 = breaker.get("voltage2", 0)
                      
                      if leg == 1:
                          if "rmsVoltage" in data:
                              v1 = float(data["rmsVoltage"]) if data["rmsVoltage"] is not None else cached_v1
                              breaker["voltage1"] = v1
                          else:
                              v1 = cached_v1
                          if "rmsVoltage2" in data:
                              v2 = float(data["rmsVoltage2"]) if data["rmsVoltage2"] is not None else cached_v2
                              breaker["voltage2"] = v2
                          else:
                              v2 = cached_v2
                      else:
                          # Leg 2: swap voltage mapping
                          if "rmsVoltage" in data:
                              v2 = float(data["rmsVoltage"]) if data["rmsVoltage"] is not None else cached_v2
                              breaker["voltage2"] = v2
                          else:
                              v2 = cached_v2
                          if "rmsVoltage2" in data:
                              v1 = float(data["rmsVoltage2"]) if data["rmsVoltage2"] is not None else cached_v1
                              breaker["voltage1"] = v1
                          else:
                              v1 = cached_v1
                      
                      breaker["voltage"] = v1 + v2
                  
                  # Handle current (same leg mapping as power)
                  if "rmsCurrent" in data or "rmsCurrent2" in data:
                      cached_c1 = breaker.get("current1", 0)
                      cached_c2 = breaker.get("current2", 0)
                      
                      if leg == 1:
                          if "rmsCurrent" in data:
                              c1 = float(data["rmsCurrent"]) if data["rmsCurrent"] is not None else cached_c1
                              breaker["current1"] = c1
                          else:
                              c1 = cached_c1
                          if "rmsCurrent2" in data:
                              c2 = float(data["rmsCurrent2"]) if data["rmsCurrent2"] is not None else cached_c2
                              breaker["current2"] = c2
                          else:
                              c2 = cached_c2
                      else:
                          # Leg 2: swap current mapping
                          if "rmsCurrent" in data:
                              c2 = float(data["rmsCurrent"]) if data["rmsCurrent"] is not None else cached_c2
                              breaker["current2"] = c2
                          else:
                              c2 = cached_c2
                          if "rmsCurrent2" in data:
                              c1 = float(data["rmsCurrent2"]) if data["rmsCurrent2"] is not None else cached_c1
                              breaker["current1"] = c1
                          else:
                              c1 = cached_c1
                      
                      # Current total depends on poles
                      poles = breaker.get("poles", 1)
                      if poles == 2:
                          breaker["current"] = (c1 + c2) / 2
                      else:
                          breaker["current"] = c1 + c2
                  
                  # Handle frequency (same leg mapping as power)
                  if "lineFrequency" in data or "lineFrequency2" in data:
                      cached_f1 = breaker.get("frequency1", 0)
                      cached_f2 = breaker.get("frequency2", 0)
                      
                      if leg == 1:
                          if "lineFrequency" in data:
                              f1 = float(data["lineFrequency"]) if data["lineFrequency"] is not None else cached_f1
                              breaker["frequency1"] = f1
                          else:
                              f1 = cached_f1
                          if "lineFrequency2" in data:
                              f2 = float(data["lineFrequency2"]) if data["lineFrequency2"] is not None else cached_f2
                              breaker["frequency2"] = f2
                          else:
                              f2 = cached_f2
                      else:
                          # Leg 2: swap frequency mapping
                          if "lineFrequency" in data:
                              f2 = float(data["lineFrequency"]) if data["lineFrequency"] is not None else cached_f2
                              breaker["frequency2"] = f2
                          else:
                              f2 = cached_f2
                          if "lineFrequency2" in data:
                              f1 = float(data["lineFrequency2"]) if data["lineFrequency2"] is not None else cached_f1
                              breaker["frequency1"] = f1
                          else:
                              f1 = cached_f1
                      
                      # Frequency total depends on poles
                      poles = breaker.get("poles", 1)
                      if poles == 2:
                          breaker["frequency"] = (f1 + f2) / 2
                      else:
                          breaker["frequency"] = f1
                  
                  if "connected" in data: breaker["connected"] = data["connected"]
                  if "currentState" in data: breaker["state"] = data["currentState"]
                  if "remoteState" in data: breaker["remoteState"] = data["remoteState"]
                  
                  # Save back to the structure
                  breakers[breaker_id] = breaker
                  new_status_data["breakers"] = breakers
                  updated = True

        # Handle IotCt (CT Clamps)
        elif model_name == "IotCt":
             ct_id = str(data.get("id"))
             if ct_id and ct_id in new_status_data["cts"]:
                  cts = new_status_data["cts"].copy()
                  ct = cts[ct_id].copy()
                  
                  # Get cached values (or 0 if not yet cached)
                  cached_p1 = ct.get("power1", 0)
                  cached_p2 = ct.get("power2", 0)
                  
                  # Update only the values that are present in the payload
                  # Use cached value if not present
                  if "activePower" in data:
                      p1 = float(data["activePower"]) if data["activePower"] is not None else cached_p1
                      ct["power1"] = p1
                  else:
                      p1 = cached_p1
                      
                  if "activePower2" in data:
                      p2 = float(data["activePower2"]) if data["activePower2"] is not None else cached_p2
                      ct["power2"] = p2
                  else:
                      p2 = cached_p2
                  
                  # Total power is always sum of both (using cached values for missing)
                  if "activePower" in data or "activePower2" in data:
                      ct["power"] = p1 + p2
                  
                  # Handle energy consumption the same way
                  if "energyConsumption" in data or "energyConsumption2" in data:
                      cached_c1 = ct.get("consumption1", 0)
                      cached_c2 = ct.get("consumption2", 0)
                      
                      if "energyConsumption" in data:
                          c1 = float(data["energyConsumption"]) if data["energyConsumption"] is not None else cached_c1
                          ct["consumption1"] = c1
                      else:
                          c1 = cached_c1
                          
                      if "energyConsumption2" in data:
                          c2 = float(data["energyConsumption2"]) if data["energyConsumption2"] is not None else cached_c2
                          ct["consumption2"] = c2
                      else:
                          c2 = cached_c2
                      
                      ct["consumption"] = c1 + c2
                  
                  # Handle energy import (grid import) the same way
                  if "energyImport" in data or "energyImport2" in data:
                      cached_i1 = ct.get("import1", 0)
                      cached_i2 = ct.get("import2", 0)
                      
                      if "energyImport" in data:
                          i1 = float(data["energyImport"]) if data["energyImport"] is not None else cached_i1
                          ct["import1"] = i1
                      else:
                          i1 = cached_i1
                          
                      if "energyImport2" in data:
                          i2 = float(data["energyImport2"]) if data["energyImport2"] is not None else cached_i2
                          ct["import2"] = i2
                      else:
                          i2 = cached_i2
                      
                      ct["import"] = i1 + i2
                  
                  # Handle current the same way
                  if "rmsCurrent" in data or "rmsCurrent2" in data:
                      cached_cur1 = ct.get("current1", 0)
                      cached_cur2 = ct.get("current2", 0)
                      
                      if "rmsCurrent" in data:
                          cur1 = float(data["rmsCurrent"]) if data["rmsCurrent"] is not None else cached_cur1
                          ct["current1"] = cur1
                      else:
                          cur1 = cached_cur1
                          
                      if "rmsCurrent2" in data:
                          cur2 = float(data["rmsCurrent2"]) if data["rmsCurrent2"] is not None else cached_cur2
                          ct["current2"] = cur2
                      else:
                          cur2 = cached_cur2
                      
                      ct["current"] = (cur1 + cur2) / 2
                  
                  cts[ct_id] = ct
                  new_status_data["cts"] = cts
                  updated = True
                  
        # Handle IotWhem (The Panel itself)
        elif model_name == "IotWhem":
             if "ResidentialBreaker" in data:
                  breakers = new_status_data["breakers"].copy()
                  for b_data in data["ResidentialBreaker"]:
                       b_id = b_data.get("id")
                       if b_id and b_id in breakers:
                            breaker = breakers[b_id].copy()
                            
                            # Get cached values for partial update handling
                            cached_p1 = breaker.get("power1", 0)
                            cached_p2 = breaker.get("power2", 0)
                            
                            # Handle power/power2 fields
                            # Must respect leg position mapping (leg 2 positions swap power/power2)
                            leg = breaker.get("leg", 1)
                            
                            if leg == 1:
                                # Leg 1: power -> power1, power2 -> power2
                                if "power" in b_data:
                                    p1 = float(b_data["power"]) if b_data["power"] is not None else cached_p1
                                    breaker["power1"] = p1
                                else:
                                    p1 = cached_p1
                                
                                if "power2" in b_data:
                                    p2 = float(b_data["power2"]) if b_data["power2"] is not None else cached_p2
                                    breaker["power2"] = p2
                                else:
                                    p2 = cached_p2
                            else:
                                # Leg 2: power -> power2, power2 -> power1 (swapped)
                                if "power" in b_data:
                                    p2 = float(b_data["power"]) if b_data["power"] is not None else cached_p2
                                    breaker["power2"] = p2
                                else:
                                    p2 = cached_p2
                                
                                if "power2" in b_data:
                                    p1 = float(b_data["power2"]) if b_data["power2"] is not None else cached_p1
                                    breaker["power1"] = p1
                                else:
                                    p1 = cached_p1
                            
                            # Update total power if either field was present
                            if "power" in b_data or "power2" in b_data:
                                breaker["power"] = p1 + p2
                            
                            # Handle voltage (same leg mapping as power)
                            if "rmsVoltage" in b_data or "rmsVoltage2" in b_data:
                                cached_v1 = breaker.get("voltage1", 0)
                                cached_v2 = breaker.get("voltage2", 0)
                                
                                if leg == 1:
                                    if "rmsVoltage" in b_data:
                                        v1 = float(b_data["rmsVoltage"]) if b_data["rmsVoltage"] is not None else cached_v1
                                        breaker["voltage1"] = v1
                                    else:
                                        v1 = cached_v1
                                    if "rmsVoltage2" in b_data:
                                        v2 = float(b_data["rmsVoltage2"]) if b_data["rmsVoltage2"] is not None else cached_v2
                                        breaker["voltage2"] = v2
                                    else:
                                        v2 = cached_v2
                                else:
                                    if "rmsVoltage" in b_data:
                                        v2 = float(b_data["rmsVoltage"]) if b_data["rmsVoltage"] is not None else cached_v2
                                        breaker["voltage2"] = v2
                                    else:
                                        v2 = cached_v2
                                    if "rmsVoltage2" in b_data:
                                        v1 = float(b_data["rmsVoltage2"]) if b_data["rmsVoltage2"] is not None else cached_v1
                                        breaker["voltage1"] = v1
                                    else:
                                        v1 = cached_v1
                                
                                breaker["voltage"] = v1 + v2
                            
                            # Handle current (same leg mapping)
                            if "rmsCurrent" in b_data or "rmsCurrent2" in b_data:
                                cached_c1 = breaker.get("current1", 0)
                                cached_c2 = breaker.get("current2", 0)
                                
                                if leg == 1:
                                    if "rmsCurrent" in b_data:
                                        c1 = float(b_data["rmsCurrent"]) if b_data["rmsCurrent"] is not None else cached_c1
                                        breaker["current1"] = c1
                                    else:
                                        c1 = cached_c1
                                    if "rmsCurrent2" in b_data:
                                        c2 = float(b_data["rmsCurrent2"]) if b_data["rmsCurrent2"] is not None else cached_c2
                                        breaker["current2"] = c2
                                    else:
                                        c2 = cached_c2
                                else:
                                    if "rmsCurrent" in b_data:
                                        c2 = float(b_data["rmsCurrent"]) if b_data["rmsCurrent"] is not None else cached_c2
                                        breaker["current2"] = c2
                                    else:
                                        c2 = cached_c2
                                    if "rmsCurrent2" in b_data:
                                        c1 = float(b_data["rmsCurrent2"]) if b_data["rmsCurrent2"] is not None else cached_c1
                                        breaker["current1"] = c1
                                    else:
                                        c1 = cached_c1
                                
                                poles = breaker.get("poles", 1)
                                if poles == 2:
                                    breaker["current"] = (c1 + c2) / 2
                                else:
                                    breaker["current"] = c1 + c2
                            
                            # Handle frequency (same leg mapping)
                            if "lineFrequency" in b_data or "lineFrequency2" in b_data:
                                cached_f1 = breaker.get("frequency1", 0)
                                cached_f2 = breaker.get("frequency2", 0)
                                
                                if leg == 1:
                                    if "lineFrequency" in b_data:
                                        f1 = float(b_data["lineFrequency"]) if b_data["lineFrequency"] is not None else cached_f1
                                        breaker["frequency1"] = f1
                                    else:
                                        f1 = cached_f1
                                    if "lineFrequency2" in b_data:
                                        f2 = float(b_data["lineFrequency2"]) if b_data["lineFrequency2"] is not None else cached_f2
                                        breaker["frequency2"] = f2
                                    else:
                                        f2 = cached_f2
                                else:
                                    if "lineFrequency" in b_data:
                                        f2 = float(b_data["lineFrequency"]) if b_data["lineFrequency"] is not None else cached_f2
                                        breaker["frequency2"] = f2
                                    else:
                                        f2 = cached_f2
                                    if "lineFrequency2" in b_data:
                                        f1 = float(b_data["lineFrequency2"]) if b_data["lineFrequency2"] is not None else cached_f1
                                        breaker["frequency1"] = f1
                                    else:
                                        f1 = cached_f1
                                
                                poles = breaker.get("poles", 1)
                                if poles == 2:
                                    breaker["frequency"] = (f1 + f2) / 2
                                else:
                                    breaker["frequency"] = f1
                            
                            breakers[b_id] = breaker
                            updated = True
                  if updated:
                      new_status_data["breakers"] = breakers

             if "IotCt" in data:
                  cts = new_status_data["cts"].copy()
                  for ct_data in data["IotCt"]:
                       ct_id = str(ct_data.get("id"))
                       if ct_id and ct_id in cts:
                            ct = cts[ct_id].copy()
                            
                            # Get cached power values (or 0 if not yet cached)
                            cached_p1 = ct.get("power1", 0)
                            cached_p2 = ct.get("power2", 0)
                            
                            # Update only the values that are present
                            if "activePower" in ct_data:
                                p1 = float(ct_data["activePower"]) if ct_data["activePower"] is not None else cached_p1
                                ct["power1"] = p1
                            else:
                                p1 = cached_p1
                                
                            if "activePower2" in ct_data:
                                p2 = float(ct_data["activePower2"]) if ct_data["activePower2"] is not None else cached_p2
                                ct["power2"] = p2
                            else:
                                p2 = cached_p2
                            
                            # Total power uses cached values for missing
                            if "activePower" in ct_data or "activePower2" in ct_data:
                                ct["power"] = p1 + p2
                            
                            # Handle energy consumption
                            if "energyConsumption" in ct_data or "energyConsumption2" in ct_data:
                                cached_c1 = ct.get("consumption1", 0)
                                cached_c2 = ct.get("consumption2", 0)
                                
                                if "energyConsumption" in ct_data:
                                    c1 = float(ct_data["energyConsumption"]) if ct_data["energyConsumption"] is not None else cached_c1
                                    ct["consumption1"] = c1
                                else:
                                    c1 = cached_c1
                                    
                                if "energyConsumption2" in ct_data:
                                    c2 = float(ct_data["energyConsumption2"]) if ct_data["energyConsumption2"] is not None else cached_c2
                                    ct["consumption2"] = c2
                                else:
                                    c2 = cached_c2
                                
                                ct["consumption"] = c1 + c2
                            
                            # Handle energy import (grid import)
                            if "energyImport" in ct_data or "energyImport2" in ct_data:
                                cached_i1 = ct.get("import1", 0)
                                cached_i2 = ct.get("import2", 0)
                                
                                if "energyImport" in ct_data:
                                    i1 = float(ct_data["energyImport"]) if ct_data["energyImport"] is not None else cached_i1
                                    ct["import1"] = i1
                                else:
                                    i1 = cached_i1
                                    
                                if "energyImport2" in ct_data:
                                    i2 = float(ct_data["energyImport2"]) if ct_data["energyImport2"] is not None else cached_i2
                                    ct["import2"] = i2
                                else:
                                    i2 = cached_i2
                                
                                ct["import"] = i1 + i2
                            
                            # Handle current
                            if "rmsCurrent" in ct_data or "rmsCurrent2" in ct_data:
                                cached_cur1 = ct.get("current1", 0)
                                cached_cur2 = ct.get("current2", 0)
                                
                                if "rmsCurrent" in ct_data:
                                    cur1 = float(ct_data["rmsCurrent"]) if ct_data["rmsCurrent"] is not None else cached_cur1
                                    ct["current1"] = cur1
                                else:
                                    cur1 = cached_cur1
                                    
                                if "rmsCurrent2" in ct_data:
                                    cur2 = float(ct_data["rmsCurrent2"]) if ct_data["rmsCurrent2"] is not None else cached_cur2
                                    ct["current2"] = cur2
                                else:
                                    cur2 = cached_cur2
                                
                                ct["current"] = (cur1 + cur2) / 2
                            
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
        """Run the WebSocket connection loop.
        
        Strategy (based on official Leviton app):
        - PUT bandwidth:1 every 50 seconds (this is what keeps WebSocket alive!)
        - Subscribe once at start
        - Re-subscribe only if no data received for 120 seconds
        - No fallback polling - WebSocket only
        """
        uri = "wss://socket.cloud.leviton.com/"
        reconnect_delay = 10
        max_delay = 300
        
        BANDWIDTH_PUT_INTERVAL = 50      # PUT bandwidth:1 every 50 seconds (like official app)
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
                    # Must PUT to EVERY panel using the correct endpoint for its type
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
                            "Sec-GPC": "1",
                            "Priority": "u=0",
                        }
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
                                    _LOGGER.debug(f"[v{self.version}] Bandwidth PUT {panel_type} panel {panel_id}: {resp.status}")
                            except aiohttp.ClientConnectionResetError:
                                _LOGGER.debug(f"[v{self.version}] Bandwidth PUT panel {panel_id}: connection reset (expected)")
                            except asyncio.CancelledError:
                                raise
                            except Exception as e:
                                _LOGGER.debug(f"[v{self.version}] Bandwidth PUT panel {panel_id} failed: {e}")
                    
                    # Initial bandwidth PUT
                    await bandwidth_put()
                    
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
                        resubscribe_count = 0
                        start_time = asyncio.get_event_loop().time()
                        last_bandwidth_put_time = start_time
                        last_data_time = start_time
                        
                        while True:
                            current_time = asyncio.get_event_loop().time()
                            
                            # Bandwidth PUT every 50 seconds (this keeps WebSocket alive!)
                            if current_time - last_bandwidth_put_time >= BANDWIDTH_PUT_INTERVAL:
                                bandwidth_put_count += 1
                                last_bandwidth_put_time = current_time
                                # Create task with exception handler to prevent "exception never retrieved"
                                task = asyncio.create_task(bandwidth_put())
                                def handle_task_exception(t):
                                    try:
                                        if t.done() and not t.cancelled():
                                            t.exception()  # This retrieves and suppresses the exception
                                    except Exception:
                                        pass  # Suppress any exception
                                task.add_done_callback(handle_task_exception)
                                _LOGGER.debug(f"[v{self.version}] Bandwidth PUT #{bandwidth_put_count} ({len(panel_info)} panels)")
                            
                            # Re-subscribe if no data for 60 seconds
                            if current_time - last_data_time >= STALE_DATA_THRESHOLD:
                                resubscribe_count += 1
                                last_data_time = current_time
                                _LOGGER.debug(f"[v{self.version}] No data for {STALE_DATA_THRESHOLD}s, re-subscribing (#{resubscribe_count})")
                                try:
                                    await send_subscriptions()
                                except aiohttp.ClientConnectionResetError:
                                    _LOGGER.debug(f"[v{self.version}] Connection reset during re-subscribe")
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
                                    _LOGGER.debug(f"[v{self.version}] WS: {message_count} msgs, {elapsed:.0f}s, {bandwidth_put_count} PUTs")
                                
                                try:
                                    payload = json.loads(msg.data)
                                    if payload.get("type") == "notification":
                                        notification = payload.get("notification", {})
                                        if self._update_from_websocket(notification):
                                            _LOGGER.debug(f"[v{self.version}] WS Received Data for {notification.get('modelName')}")
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
