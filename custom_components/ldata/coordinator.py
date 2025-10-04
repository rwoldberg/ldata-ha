"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""

import asyncio
from datetime import timedelta
import logging

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
        self.config_entry = entry  # Add this line to store the config entry

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )

    async def _async_update_data(self):
        """Fetch data from LDATA Controller."""
        returnData = None
        try:
            async with asyncio.timeout(30):
                returnData = await self._hass.async_add_executor_job(
                    self._service.status  # Fetch new status
                )
                # Check the "log_raw_data" option before logging
                if self.config_entry.options.get("log_raw_data", False):
                    _LOGGER.warning("Leviton API Data: %s", returnData)
        except Exception as ex:
            self._available = False  # Mark as unavailable
            _LOGGER.warning(
                "Error communicating with LDATA for %s: %s", self.user, str(ex)
            )
            raise UpdateFailed(
                f"Error communicating with LDATA for {self.user}"
            ) from ex
        return returnData

    @property
    def service(self) -> LDATAService:
        """Return the LDATA service."""
        return self._service
