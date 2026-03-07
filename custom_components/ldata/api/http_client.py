"""HTTP Client for Leviton API."""

import asyncio
import logging
import re
import time
import aiohttp

from ..const import LOGGER_NAME
from .exceptions import LDATAAuthError, TwoFactorRequired

_LOGGER = logging.getLogger(LOGGER_NAME)

class LDATAHttpClient:
    """HTTP client for Leviton."""

    _last_login_attempt_time = 0.0

    def __init__(self, username, password, session: aiohttp.ClientSession, version: str) -> None:
        self.username = username
        self.password = password
        self.session = session
        self.version = version
        self.auth_token = ""
        self.refresh_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id_list = []
        self.full_auth_response = None
        
        self.default_headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) LDATA Integration",
            "host": "my.leviton.com",
            "Origin": "https://myapp.leviton.com",
            "Referer": "https://myapp.leviton.com/",
            "Connection": "keep-alive",
        }

    async def _test_internet_connectivity(self) -> str:
        try:
            loop = asyncio.get_running_loop()
            await loop.getaddrinfo("google.com", 80)
            return "ACTIVE"
        except Exception:
            return "DOWN"

    async def _handle_request_error(self, ex: Exception, context: str):
        net_status = await self._test_internet_connectivity()
        if net_status == "DOWN":
            _LOGGER.error("[v%s] Internet is DOWN. Cannot reach Leviton during %s.", self.version, context)
        else:
            _LOGGER.error("[v%s] Leviton API unreachable during %s: %s", self.version, context, ex)

    def _get_clean_error_msg(self, response_text: str) -> str:
        msg = re.sub('<[^<]+?>', '', response_text)
        return re.sub(r'\s+', ' ', msg).strip()

    async def _check_rate_limit(self) -> None:
        current_time = time.time()
        time_since = current_time - LDATAHttpClient._last_login_attempt_time
        if time_since < 10.0:
            wait_time = 10.0 - time_since
            _LOGGER.warning("[v%s] Rate limiting login. Waiting %.1fs.", self.version, wait_time)
            await asyncio.sleep(wait_time)
        LDATAHttpClient._last_login_attempt_time = time.time()

    def clear_tokens(self) -> None:
        self.auth_token = ""
        self.refresh_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id_list = []
        self.full_auth_response = None

    async def auth_with_credentials(self) -> bool:
        await self._check_rate_limit()
        data = {"email": self.username, "password": self.password}
        try:
            async with self.session.post(
                "https://my.leviton.com/api/Person/login?include=user",
                headers=self.default_headers, json=data, timeout=aiohttp.ClientTimeout(total=15)
            ) as result:
                if result.status == 200:
                    json_data = await result.json()
                    self.auth_token = self.refresh_token = json_data["id"]
                    self.userid = json_data["userId"]
                    self.full_auth_response = json_data
                    return True
                text = await result.text()
                if result.status in (401, 406):
                    if "Requirescode." in text:
                        raise TwoFactorRequired
                    raise LDATAAuthError(f"[v{self.version}] Invalid credentials")
                raise LDATAAuthError(f"Login failed: {result.status}")
        except aiohttp.ClientError as ex:
            await self._handle_request_error(ex, "login")
            raise

    async def complete_2fa(self, code: str) -> bool:
        await self._check_rate_limit()
        data = {"email": self.username, "password": self.password, "code": code}
        try:
            async with self.session.post(
                "https://my.leviton.com/api/Person/login?include=user",
                headers=self.default_headers, json=data, timeout=aiohttp.ClientTimeout(total=15)
            ) as result:
                if result.status == 200:
                    json_data = await result.json()
                    self.auth_token = self.refresh_token = json_data["id"]
                    self.userid = json_data["userId"]
                    self.full_auth_response = json_data
                    return True
                raise LDATAAuthError(f"[v{self.version}] Invalid 2FA code")
        except aiohttp.ClientError as ex:
            await self._handle_request_error(ex, "2fa")
            raise

    async def refresh_auth(self) -> bool:
        if not self.refresh_token or not self.userid:
            self.clear_tokens()
            return False
        self.auth_token = self.refresh_token
        headers = {**self.default_headers, "authorization": self.auth_token}
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"
        
        for attempts in range(3):
            try:
                async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                    if result.status == 200:
                        if not self.account_id:
                            json_data = await result.json()
                            for item in (json_data or []):
                                acct = item.get("residentialAccountId")
                                if acct is not None:
                                    self.account_id = acct
                                    break
                        return True
                    if result.status in (401, 403, 406):
                        if attempts < 2:
                            await asyncio.sleep(5)
                            continue
                        self.clear_tokens()
                        raise LDATAAuthError("Token expired")
            except aiohttp.ClientError as ex:
                if attempts < 2:
                    await asyncio.sleep(5)
                    continue
                await self._handle_request_error(ex, "refresh_auth")
                raise
        return False

    async def get_residential_account(self) -> bool:
        if self.account_id: return True
        headers = {**self.default_headers, "authorization": self.auth_token}
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status == 200:
                    json_data = await result.json()
                    for item in (json_data or []):
                        acct = item.get("residentialAccountId")
                        if acct is not None:
                            self.account_id = acct
                            # Grab userId from the same item if present
                            self.userid = item.get("userId", self.userid)
                            return True
            self.clear_tokens()
        except Exception as ex:
            _LOGGER.debug("[v%s] Error getting residential account: %s", self.version, ex)
            self.clear_tokens()
        return False

    async def get_residencePermissions(self) -> bool:
        headers = {**self.default_headers, "authorization": self.auth_token}
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status == 200:
                    for account in await result.json():
                        if account.get("residenceId") not in self.residence_id_list:
                            self.residence_id_list.append(account["residenceId"])
                    return True
        except Exception as ex:
            _LOGGER.debug("[v%s] Error getting residence permissions: %s", self.version, ex)
        return False

    async def get_residences(self) -> bool:
        headers = {**self.default_headers, "authorization": self.auth_token}
        url = f"https://my.leviton.com/api/ResidentialAccounts/{self.account_id}/residences"
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status == 200:
                    json_data = await result.json()
                    if json_data:
                        self.residence_id_list.append(json_data[0]["id"])
                        return True
        except Exception as ex:
            _LOGGER.debug("[v%s] Error getting residences: %s", self.version, ex)
        return False

    async def get_residence(self) -> bool:
        headers = {**self.default_headers, "authorization": self.auth_token}
        url = f"https://my.leviton.com/api/ResidentialAccounts/{self.account_id}"
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status == 200:
                    self.residence_id_list.append((await result.json()).get("primaryResidenceId"))
                    return True
            self.clear_tokens()
        except Exception as ex:
            _LOGGER.debug("[v%s] Error getting residence: %s", self.version, ex)
            self.clear_tokens()
        return False

    async def get_Whems_breakers(self, panel_id: str) -> list | None:
        url = f"https://my.leviton.com/api/IotWhems/{panel_id}/residentialBreakers"
        return await self._get_request(url)

    async def get_Whems_CT(self, panel_id: str) -> list | None:
        url = f"https://my.leviton.com/api/IotWhems/{panel_id}/iotCts"
        return await self._get_request(url)

    async def get_ldata_panels(self, residence_id: str) -> list | None:
        """Fetch LDATA panels (residentialBreakerPanels) for a residence."""
        url = f"https://my.leviton.com/api/Residences/{residence_id}/residentialBreakerPanels"
        headers = {**self.default_headers, "authorization": self.auth_token, "filter": '{"include":["residentialBreakers"]}'}
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status in (401, 403, 406):
                    raise LDATAAuthError("Auth token invalid during LDATA panel fetch")
                if result.status == 200:
                    return await result.json()
        except LDATAAuthError: raise
        except Exception as ex:
            _LOGGER.debug("[v%s] GET LDATA panels failed for residence %s: %s", self.version, residence_id, ex)
        return None

    async def get_whems_panels(self, residence_id: str) -> list | None:
        """Fetch WHEMS panels (iotWhems) for a residence."""
        url = f"https://my.leviton.com/api/Residences/{residence_id}/iotWhems"
        headers = {**self.default_headers, "authorization": self.auth_token, "filter": "{}"}
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status in (401, 403, 406):
                    raise LDATAAuthError("Auth token invalid during WHEMS panel fetch")
                if result.status == 200:
                    return await result.json()
        except LDATAAuthError: raise
        except Exception as ex:
            _LOGGER.debug("[v%s] GET WHEMS panels failed for residence %s: %s", self.version, residence_id, ex)
        return None

    async def get_panel(self, panel_id: str, panel_type: str) -> dict | None:
        url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}" if panel_type == "LDATA" else f"https://my.leviton.com/api/IotWhems/{panel_id}"
        headers = {**self.default_headers, "authorization": self.auth_token, "filter": "{}"}
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status in (401, 403, 406):
                    raise LDATAAuthError("Auth token invalid")
                if result.status == 200:
                    return await result.json()
        except LDATAAuthError: raise
        except Exception as ex:
            _LOGGER.debug("[v%s] GET panel failed for %s: %s", self.version, panel_id, ex)
        return None

    async def _get_request(self, url: str) -> list | None:
        headers = {**self.default_headers, "authorization": self.auth_token, "filter": "{}"}
        try:
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status in (401, 403, 406):
                    raise LDATAAuthError("Auth token invalid")
                if result.status == 200:
                    return await result.json()
        except LDATAAuthError: raise
        except Exception as ex:
            _LOGGER.debug("[v%s] GET request failed for %s: %s", self.version, url, ex)
        return None

    async def put_bandwidth(self, panel_id: str, panel_type: str, bandwidth: int) -> None:
        url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}" if panel_type == "LDATA" else f"https://my.leviton.com/api/IotWhems/{panel_id}"
        headers = {**self.default_headers, "authorization": self.auth_token}
        try:
            async with self.session.put(url, headers=headers, json={"bandwidth": bandwidth}, timeout=aiohttp.ClientTimeout(total=5)): pass
        except Exception as ex:
            _LOGGER.debug("[v%s] Bandwidth toggle failed for panel %s: %s", self.version, panel_id, ex)

    async def remote_trip(self, breaker_id: str, action: str) -> bool:
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        headers = {**self.default_headers, "authorization": self.auth_token, "referer": f"https://my.leviton.com/home/residential-breakers/{breaker_id}/settings"}
        payload = {"remoteTrip": True} if action == "off" else {"remoteOn": True}
        try:
            async with self.session.put(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status == 200: return True
                if result.status in (401, 403, 406): raise LDATAAuthError("Auth token invalid")
        except LDATAAuthError: raise
        except Exception as ex:
            _LOGGER.debug("[v%s] Remote trip failed for breaker %s: %s", self.version, breaker_id, ex)
        return False

    async def set_blink_led(self, breaker_id: str, enabled: bool) -> bool:
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        headers = {**self.default_headers, "authorization": self.auth_token}
        try:
            async with self.session.put(url, headers=headers, json={"blinkLED": enabled}, timeout=aiohttp.ClientTimeout(total=15)) as result:
                if result.status == 200: return True
                if result.status in (401, 403, 406): raise LDATAAuthError("Auth token invalid")
        except LDATAAuthError: raise
        except Exception as ex:
            _LOGGER.debug("[v%s] Set blinkLED failed for breaker %s: %s", self.version, breaker_id, ex)
        return False