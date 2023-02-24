"""LDATAUpdateCoordinator class to handle fetching new data about the LDATA module."""
from datetime import timedelta
import logging

import async_timeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .ldata_service import LDATAService

_LOGGER = logging.getLogger(__name__)


class LDATAUpdateCoordinator(DataUpdateCoordinator):
    """LDATAUpdateCoordinator to handle fetching new data about the LDATA module."""

    def __init__(self, hass: HomeAssistant, user, password, update_interval) -> None:
        """Initialize the coordinator and set up the Controller object."""
        self._hass = hass
        self.user = user
        self._service = LDATAService(user, password)
        self._available = True

        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )

    async def _async_update_data(self):
        """Fetch data from LDATA Controller."""
        try:
            async with async_timeout.timeout(30):
                data = await self._hass.async_add_executor_job(
                    self._service.status  # Fetch new status
                )
                return data
        except Exception as ex:
            self._available = False  # Mark as unavailable
            _LOGGER.warning(str(ex))
            _LOGGER.warning("Error communicating with LDATA for %s", self.user)
            raise UpdateFailed(
                f"Error communicating with LDATA for {self.user}"
            ) from ex

    @property
    def service(self) -> LDATAService:
        """Return the LDATA service."""
        return self._service
