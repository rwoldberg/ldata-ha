"""The LDATAService object."""

import logging
import typing
import time
import socket
import re
import os
import json
import requests

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
        # Load refresh token (which is just our long-lived auth token)
        self.refresh_token = entry.data.get("refresh_token", "") if entry else ""
        self.userid = entry.data.get("userid", "") if entry else ""
        self.account_id = ""
        self.residence_id_list = []  # type: list[str]
        self.session = requests.Session()

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
                # Use self.session if you upgraded to persistent sessions, otherwise requests
                # result = self.session.get(url, headers=headers, timeout=15)
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
                    # We do NOT clear tokens for server errors.
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
                    # We do NOT clear tokens for network errors.
                    # Secondary DNS check (optional, if you added that helper function)
                    # self._test_internet_connectivity() 
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
            _LOGGER.error(f"[v{self.version}] Unable to get WHEMS breakers! (HTTP {result.status_code}): {clean_msg}")
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
            _LOGGER.error(f"[v{self.version}] Unable to get WHEMS CTs! (HTTP {result.status_code}): {clean_msg}")
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
                        
                        # Apply WHEMS specific mapping and fetching
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
            _LOGGER.error(f"[v{self.version}] Failed to execute {context_str}! (HTTP {result.status_code}): {clean_msg}")
        
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
        except Exception:  # pylint: disable=broad-except  # noqa: BLE001
            value = None
        if value is None:
            return result
        if value is KeyError:
            return result
        try:
            result = float(value)
        except Exception:  # pylint: disable=broad-except  # noqa: BLE001
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
            try:
                # This call forces the panel to update ensure that if one panel fails to respond, it doesn't stop the update for all other panels.
                self.put_residential_breaker_panels(panel["id"], panel["ModuleType"])
            except requests.exceptions.RequestException as e:
               _LOGGER.warning(f"[v{self.version}] Failed to request update from panel {panel.get('name', panel['id'])}: {e}")
                # Continue to the next panel even if this one failed.
            except LDATAAuthError as e:
                _LOGGER.warning(f"[v{self.version}] Auth failed during panel update for {panel.get('name', panel['id'])}: {e}")
                # Re-raise the auth error to stop the update
                raise
            panel_data = {}
            panel_data["firmware"] = panel["updateVersion"]
            panel_data["model"] = panel["model"]
            panel_data["id"] = panel["id"]
            panel_data["name"] = panel["name"]
            panel_data["serialNumber"] = panel["id"]
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
                for ct in panel["CTs"]:
                    if ct["usageType"] != "NOT_USED":
                        # Create the CT data
                        ct_data = {}
                        ct_data["name"] = ct["usageType"]
                        ct_data["id"] = str(ct["id"])
                        ct_data["panel_id"] = panel["id"]
                        ct_data["channel"] = str(ct["channel"])
                        ct_data["power"] = self.none_to_zero(
                            ct, "activePower"
                        ) + self.none_to_zero(ct, "activePower2")
                        ct_data["consumption"] = self.none_to_zero(
                            ct, "energyConsumption"
                        ) + self.none_to_zero(ct, "energyConsumption2")
                        ct_data["import"] = self.none_to_zero(
                            ct, "energyImport"
                        ) + self.none_to_zero(ct, "energyImport2")
                        ct_data["current"] = (
                            self.none_to_zero(ct, "rmsCurrent")
                            + self.none_to_zero(ct, "rmsCurrent2")
                        ) / 2
                        ct_data["current1"] = self.none_to_zero(ct, "rmsCurrent")
                        ct_data["current2"] = self.none_to_zero(ct, "rmsCurrent2")
                        # Add the CT to the list.
                        cts[ct_data["id"]] = ct_data
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
        status_data["breakers"] = breakers
        status_data["cts"] = cts
        status_data["panels"] = panels

        return status_data
