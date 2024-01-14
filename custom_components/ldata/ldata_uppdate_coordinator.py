"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""
from datetime import timedelta
import logging

import async_timeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, LOGGER_NAME
from .ldata_service import LDATAService

_LOGGER = logging.getLogger(LOGGER_NAME)


class LDATAUpdateCoordinator(DataUpdateCoordinator):
    """LDATAUpdateCoordinator to handle fetching new data about the LDATA module."""

    def __init__(
        self, hass: HomeAssistant, user, password, update_interval, entry
    ) -> None:
        """Initialize the coordinator and set up the Controller object."""
        self._hass = hass
        self.user = user
        self._service = LDATAService(user, password, entry)
        self._available = True
        self.service_data = None

        # Set the update interval to half the input value, the update function will only refresh its data every other time.
        # Hopefully this will help the interface from thinking the sensors are no longer present if for some reason
        # It takes longer than expected to pull the data from the website. 
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval/2),
        )

    async def _async_update_data(self):
        """Fetch data from LDATA Controller."""
        try:
            returnData = self.service_data
            if self.service_data is None:
                async with async_timeout.timeout(30):
                    self.service_data = await self._hass.async_add_executor_job(
                        self._service.status  # Fetch new status
                    )
                returnData = self.service_data
            else:
                self.service_data = None
            return returnData
        except Exception as ex:
            self._available = False  # Mark as unavailable
            _LOGGER.warning(
                "Error communicating with LDATA for %s: %s", self.user, str(ex)
            )
            raise UpdateFailed(
                f"Error communicating with LDATA for {self.user}"
            ) from ex

    @property
    def service(self) -> LDATAService:
        """Return the LDATA service."""
        return self._service
