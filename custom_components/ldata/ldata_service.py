"""The LDATAService object."""
import logging

import requests

from .const import _LEG1_POSITIONS

defaultHeaders = {
    "Accept": "*/*",
    "Content-Type": "application/json",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "host": "my.leviton.com",
}

_LOGGER = logging.getLogger(__name__)


class LDATAService:
    """The LDATAService object."""

    def __init__(self, username, password) -> None:
        """Init LDATAService."""
        self.username = username
        self.password = password
        self.auth_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id = ""

    def clear_tokens(self) -> None:
        """Clear the tokens to force a re-login."""
        self.auth_token = ""
        self.userid = ""
        self.account_id = ""
        self.residence_id = ""

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
            # _LOGGER.debug(result.request.body)
            _LOGGER.debug(result.status_code)
            _LOGGER.debug(result.text)

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
            # _LOGGER.debug(result.request.body)
            _LOGGER.debug(result.status_code)
            _LOGGER.debug(result.text)
            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                self.account_id = result_json[0]["residentialAccountId"]
                return True
            _LOGGER.exception("Unable to get Residential Account!")
            self.clear_tokens()
        except Exception as ex:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Residential Account! %s", ex)
            self.clear_tokens()

        return False

    def get_residence(self) -> bool:
        """Get the Residential Account for the user."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        url = "https://my.leviton.com/api/ResidentialAccounts/{}/residences".format(
            self.account_id
        )
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            # _LOGGER.debug(result.request.body)
            _LOGGER.debug(result.status_code)
            _LOGGER.debug(result.text)
            result_json = result.json()
            if result.status_code == 200 and len(result_json) > 0:
                self.residence_id = result_json[0]["id"]
                return True
            _LOGGER.exception("Unable to get Residence!")
            self.clear_tokens()
        except Exception as ex:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Residence! %s", ex)
            self.clear_tokens()

        return False

    def get_panels(self) -> object:
        """Get the breaker panels for the residence."""
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers["filter"] = '{"include":["residentialBreakers"]}'
        url = (
            " https://my.leviton.com/api/Residences/{}/residentialBreakerPanels".format(
                self.residence_id
            )
        )
        try:
            result = requests.get(
                url,
                headers=headers,
                timeout=15,
            )
            # _LOGGER.debug(result.request.body)
            _LOGGER.debug(result.status_code)
            _LOGGER.debug(result.text)

            if result.status_code == 200:
                return result.json()
            _LOGGER.exception("Unable to get Panels!")
            self.clear_tokens()
        except Exception as ex:  # pylint: disable=broad-except
            _LOGGER.exception("Unable to get Panels! %s", ex)
            self.clear_tokens()

        return None

    def put_residential_breaker_panels(self, panel_id: str) -> None:
        """call PUT  on the ResidentialBreakerPanels API this must be done to force an update of the power values."""
        url = f"https://my.leviton.com/api/ResidentialBreakerPanels/{panel_id}"
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        data = {"bandwidth": 1}
        requests.put(
            url,
            headers=headers,
            json=data,
            timeout=15,
        )

    def turn_off(self, breaker_id):
        """Turn off a breaker."""
        # Call PUT on the ResidentialBreakerPanels/{breaker_id}.  The data is remoteTrip set to true, this will trip the breaker.
        url = f"https://my.leviton.com/api/ResidentialBreakers/{breaker_id}"
        headers = {**defaultHeaders}
        headers["authorization"] = self.auth_token
        headers[
            "referer"
        ] = f"https://my.leviton.com/home/residential-breakers/{breaker_id}/settings"
        data = {"remoteTrip": True}
        result = requests.put(
            url,
            headers=headers,
            json=data,
            timeout=15,
        )
        return result

    def status(self):
        """Get the breakers from the API."""
        _LOGGER.debug(self.auth_token)
        # Make sure we are logged in.
        if self.auth_token is None or self.auth_token == "":
            _LOGGER.debug("Not authenticated yet!")
            self.auth()
        if self.auth_token is None or self.auth_token == "":
            return
        # Make sure we have a residential Account
        if self.account_id is None or self.account_id == "":
            _LOGGER.debug("Get Account ID!")
            self.get_residential_account()
        if self.account_id is None or self.account_id == "":
            return
        # Lookup the residential id from the account.
        if self.residence_id is None or self.residence_id == "":
            _LOGGER.debug("Get Residence ID!")
            self.get_residence()
        if self.residence_id is None or self.residence_id == "":
            return
        # Get the breaker panels.
        panels_html = self.get_panels()
        status_data = {}
        breakers = {}
        panels = []
        if panels_html is not None:
            for panel in panels_html:
                self.put_residential_breaker_panels(panel["id"])
                panel_data = {}
                panel_data["firmware"] = panel["updateVersion"]
                panel_data["model"] = panel["model"]
                panel_data["id"] = panel["id"]
                panel_data["name"] = panel["name"]
                panel_data["serialNumber"] = panel["id"]
                panel_data["voltage"] = (
                    float(panel["rmsVoltage"]) + float(panel["rmsVoltage2"])
                ) / 2.0
                panel_data["voltage1"] = float(panel["rmsVoltage"])
                panel_data["voltage2"] = float(panel["rmsVoltage2"])
                panels.append(panel_data)
                _LOGGER.debug(panel)
                for breaker in panel["residentialBreakers"]:
                    _LOGGER.debug(breaker)
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
                        breaker_data["power"] = float(breaker["power"]) + float(
                            breaker["power2"]
                        )
                        breaker_data["voltage"] = float(breaker["rmsVoltage"]) + float(
                            breaker["rmsVoltage2"]
                        )
                        breaker_data["current"] = float(breaker["rmsCurrent"]) + float(
                            breaker["rmsCurrent2"]
                        )
                        if breaker["poles"] == 2:
                            breaker_data["frequency"] = (
                                float(breaker["lineFrequency"])
                                + float(breaker["lineFrequency2"])
                            ) / 2.0
                        else:
                            breaker_data["frequency"] = float(breaker["lineFrequency"])
                        if breaker["position"] in _LEG1_POSITIONS:
                            breaker_data["leg"] = 1
                            breaker_data["power1"] = float(breaker["power"])
                            breaker_data["power2"] = float(breaker["power2"])
                            breaker_data["voltage1"] = float(breaker["rmsVoltage"])
                            breaker_data["voltage2"] = float(breaker["rmsVoltage2"])
                            breaker_data["current1"] = float(breaker["rmsCurrent"])
                            breaker_data["current2"] = float(breaker["rmsCurrent2"])
                            breaker_data["frequency1"] = float(breaker["lineFrequency"])
                            breaker_data["frequency2"] = float(
                                breaker["lineFrequency2"]
                            )
                        else:
                            breaker_data["leg"] = 2
                            breaker_data["power1"] = float(breaker["power2"])
                            breaker_data["power2"] = float(breaker["power"])
                            breaker_data["voltage1"] = float(breaker["rmsVoltage2"])
                            breaker_data["voltage2"] = float(breaker["rmsVoltage"])
                            breaker_data["current1"] = float(breaker["rmsCurrent2"])
                            breaker_data["current2"] = float(breaker["rmsCurrent"])
                            breaker_data["frequency1"] = float(
                                breaker["lineFrequency2"]
                            )
                            breaker_data["frequency2"] = float(breaker["lineFrequency"])
                        # Add the breaker to the list.
                        breakers[breaker["id"]] = breaker_data

        status_data["breakers"] = breakers
        status_data["panels"] = panels

        return status_data
