"""The LDATAService object."""

import logging
import typing

import requests

from .const import _LEG1_POSITIONS, LOGGER_NAME, THREE_PHASE, THREE_PHASE_DEFAULT

defaultHeaders = {
    "Accept": "*/*",
    "Content-Type": "application/json",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "host": "my.leviton.com",
}

_LOGGER = logging.getLogger(LOGGER_NAME)


class LDATAService:
    """The LDATAService object."""

    def __init__(self, username, password, entry) -> None:
        """Init LDATAService."""
        self.username = username
        self.password = password
        self.entry = entry
        self.auth_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id_list = []  # type: list[str]

    def clear_tokens(self) -> None:
        """Clear the tokens to force a re-login."""
        self.auth_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id_list = []

    def auth(self) -> bool:
        """Authenticate to the server."""
        headers = {**defaultHeaders}
        data = {"email": self.username, "password": self.password}
        # Try logging in 3 times due to controller timeout
        login = 0
        while login < 3:
            result = requests.post(
                "https://my.leviton.com/api/Person/login?include=user",
                headers=headers,
                json=data,
                timeout=15,
            )
            _LOGGER.debug(
                "Authorization result %d: %s", result.status_code, result.text
            )

            if result.status_code == 200:
                self.auth_token = result.json()["id"]
                self.userid = result.json()["userId"]
                return True
            login += 1

        return False

    def get_residential_account(self) -> bool:
        """Get the Residential Account for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"

        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                "Get Residential Account result %d: %s", result.status_code, result.text
            )
            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                # Search for the residential account id
                for item in result_json:
                    if "residentialAccountId" in item:
                        self.account_id = item["residentialAccountId"]
                        if self.account_id is not None:
                            break
                if self.account_id is not None:
                    return True
            _LOGGER.exception("Unable to get Residential Account!")
            self.clear_tokens()
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Residential Account!")
            self.clear_tokens()

        return False

    def get_residencePermissions(self) -> bool:
        """Get the additional residences for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/Person/{self.userid}/residentialPermissions"
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                "Get Residence Permissions result %d: %s",
                result.status_code,
                result.text,
            )
            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                for account in result_json:
                    if account["residenceId"] is not None:
                        self.residence_id_list.append(account["residenceId"])
                return True
            _LOGGER.exception("Unable to get Residence Permissions!")
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Residence Permissions!")
        return False

    def get_residences(self) -> bool:
        """Get the Residential Account for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/ResidentialAccounts/{self.account_id}/residences"
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                "Get Residences Account result %d: %s", result.status_code, result.text
            )
            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                self.residence_id_list.append(result_json[0]["id"])
                return True
            _LOGGER.exception("Unable to get Residences!")
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Residences!")
        return False

    def get_residence(self) -> bool:
        """Get the Residential Account for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = f"https://my.leviton.com/api/ResidentialAccounts/{self.account_id}"
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                "Get Residence Account result %d: %s", result.status_code, result.text
            )
            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                self.residence_id_list.append(result_json["primaryResidenceId"])
                return True
            _LOGGER.exception("Unable to get Residence!")
            self.clear_tokens()
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Residence!")
            self.clear_tokens()
        return False

    def get_Whems_breakers(self, panel_id: str) -> object:
        """Get the whemns modules for the residence."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["filter"] = "{}"
        url = f"https://my.leviton.com/api/IotWhems/{panel_id}/residentialBreakers"
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                "Get WHEMS breakers result %d: %s", result.status_code, result.text
            )
            if result.status_code == 200:
                return result.json()
            _LOGGER.exception("Unable to WHEMS breakers!")
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get WHEMS breakers!")
            self.clear_tokens()
        return None

    def get_Whems_CT(self, panel_id: str) -> object:
        """Get the whemns CTs for the panel module."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["filter"] = "{}"
        url = f"https://my.leviton.com/api/IotWhems/{panel_id}/iotCts"
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            _LOGGER.debug(
                "Get WHEMS CTs result %d: %s", result.status_code, result.text
            )
            if result.status_code == 200:
                return result.json()
            _LOGGER.exception("Unable to WHEMS CTs!")
        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get WHEMS CTs!")
            self.clear_tokens()
        return None

    def get_iotWhemsPanels(self) -> object:
        """Get the whemns modules for all the residences the user has access to."""
        allPanels = None
        for residenceId in self.residence_id_list:
            headers = {**defaultHeaders}
            headers["authorization"] = self.auth_token
            headers["filter"] = "{}"
            url = f"https://my.leviton.com/api/Residences/{residenceId}/iotWhems"
            try:
                result = requests.get(
                    url,
                    headers=headers,
                    timeout=15,
                )
                _LOGGER.debug(
                    "Get WHEMS Panels result %d: %s", result.status_code, result.text
                )
                if result.status_code == 200:
                    returnPanels = result.json()
                    for panel in returnPanels:
                        panel["ModuleType"] = "WHEMS"
                        # Make the data look like an LDATA module
                        panel["rmsVoltage"] = panel["rmsVoltageA"]
                        panel["rmsVoltage2"] = panel["rmsVoltageB"]
                        panel["updateVersion"] = panel["version"]
                        panel["residentialBreakers"] = self.get_Whems_breakers(
                            panel["id"]
                        )
                        panel["CTs"] = self.get_Whems_CT(panel["id"])
                        if allPanels is None:
                            allPanels = []
                        allPanels.append(panel)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unable to get WHEMS Panels!")
                self.clear_tokens()
        return allPanels

    def get_ldata_panels(self) -> object:
        """Get the ldata modules for all the residences the user has access to."""
        allPanels = None
        for residenceId in self.residence_id_list:
            headers = {**defaultHeaders}
            headers["authorization"] = self.auth_token
            headers["filter"] = '{"include":["residentialBreakers"]}'
            url = f"https://my.leviton.com/api/Residences/{residenceId}/residentialBreakerPanels"
            try:
                result = requests.get(
                    url,
                    headers=headers,
                    timeout=15,
                )
                _LOGGER.debug(
                    "Get Panels result %d: %s", result.status_code, result.text
                )
                if result.status_code == 200:
                    returnPanels = result.json()
                    for panel in returnPanels:
                        panel["ModuleType"] = "LDATA"
                        if allPanels is None:
                            allPanels = []
                        allPanels.append(panel)
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unable to get Panels!")
                self.clear_tokens()
        return allPanels

    def put_residential_breaker_panels(self, panel_id: str, panel_type: str) -> None:
        """Call PUT  on the ResidentialBreakerPanels API this must be done to force an update of the power values."""
        # https://my.leviton.com/api/IotWhems/1000_002F_A3B4
        if panel_type == "LDATA":
            url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}"
        else:
            url = f"https://my.leviton.com/api/IotWhems/{panel_id}"
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        data = {"bandwidth": 1}
        requests.put(
            url,
            headers=headers,
            json=data,
            timeout=15,
        )

    def remote_off(self, breaker_id):
        """Turn off a breaker."""
        # Call PUT on the ResidentialBreakerPanels/{breaker_id}.  The data is remoteTrip set to true, this will trip the breaker.
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["referer"] = (
            f"https://my.leviton.com/home/residential-breakers/{breaker_id}/settings"
        )
        data = {"remoteTrip": True}
        return requests.put(
            url,
            headers=headers,
            json=data,
            timeout=15,
        )

    def remote_on(self, breaker_id):
        """Turn on a breaker."""
        # Call PUT on the ResidentialBreakerPanels/{breaker_id}.  The data is remoteOn set to true, this will turn on the breaker if it has remote on capabailities
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["referer"] = (
            f"https://my.leviton.com/home/residential-breakers/{breaker_id}/settings"
        )
        data = {"remoteOn": True}
        return requests.put(
            url,
            headers=headers,
            json=data,
            timeout=15,
        )

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
        # Make sure we are logged in.
        if self.auth_token is None or self.auth_token == "":
            _LOGGER.debug("Not authenticated yet!")
            self.auth()
        if self.auth_token is None or self.auth_token == "":
            return None
        # Make sure we have a residential Account
        if self.account_id is None or self.account_id == "":
            _LOGGER.debug("Get Account ID!")
            self.get_residential_account()
        if self.account_id is None or self.account_id == "":
            return None
        # Lookup the residential id from the account.
        if self.residence_id_list is None or len(self.residence_id_list) == 0:
            _LOGGER.debug("Get Residence ID!")
            self.get_residences()
            if self.residence_id_list is None or len(self.residence_id_list) == 0:
                # User does not have multiple residences, lets try just the single residence
                self.get_residence()
            self.get_residencePermissions()
        if self.residence_id_list is None or len(self.residence_id_list) == 0:
            return None
        # Get the breaker panels.
        panels_json = self.get_ldata_panels()
        whems_panels_json = self.get_iotWhemsPanels()
        if panels_json is None:
            panels_json = whems_panels_json
        elif whems_panels_json is not None:
            for panel in whems_panels_json:
                panels_json.append(panel)

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
        three_phase = self.entry.options.get(
            THREE_PHASE, self.entry.data.get(THREE_PHASE, THREE_PHASE_DEFAULT)
        )
        for panel in panels_json:
            try:
                # This call forces the panel to update ensure that if one panel fails to respond, it doesn't stop the update for all other panels.
                self.put_residential_breaker_panels(panel["id"], panel["ModuleType"])
            except requests.exceptions.RequestException as e:
               _LOGGER.warning(f"Failed to request update from panel {panel.get('name', panel['id'])}: {e}")
                # Continue to the next panel even if this one failed.
            panel_data = {}
            panel_data["firmware"] = panel["updateVersion"]
            panel_data["model"] = panel["model"]
            panel_data["id"] = panel["id"]
            panel_data["name"] = panel["name"]
            panel_data["serialNumber"] = panel["id"]
            panel_data["connected"] = panel.get("connected", False)
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
            if "CTs" in panel:
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
