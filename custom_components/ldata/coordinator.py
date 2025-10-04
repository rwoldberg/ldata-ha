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
        self.config_entry = entry

        # The config_entry parameter is now passed to the parent class
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
            config_entry=entry,
        )

    async def _async_update_data(self):
        """Fetch data from LDATA Controller."""
        returnData = None
        try:
            async with asyncio.timeout(30):
                returnData = await self._hass.async_add_executor_job(
                    self._service.status  # Fetch new status
                )

                options = self.config_entry.options
                
                if options.get("log_all_raw", False):
                    _LOGGER.warning("Leviton API Full Data: %s", returnData)
                
                elif fields_to_log_str := options.get("log_fields", ""):
                    fields_to_log = [f.strip() for f in fields_to_log_str.split(',') if f.strip()]
                    log_output = {}

                    for ct_id, ct_data in returnData.get('cts', {}).items():
                        for field in fields_to_log:
                            if field in ct_data:
                                key_name = f"CT_{ct_id}_{field}"
                                log_output[key_name] = ct_data[field]
                    
                    if log_output:
                        _LOGGER.warning("Leviton Selected Raw Data: %s", log_output)

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
