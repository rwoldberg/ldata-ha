"""Where the load center card's files are served from.

The card (www/ldata-panel-card.js) and its artwork are served straight from
this integration's own folder, so nothing has to be copied into config/www.
The Lovelace resource and the sidebar panel both load the card from the URL
returned by async_serve_card(), so a browser fetches and runs the file once
however the card is reached.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
from pathlib import Path

from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN, LOGGER_NAME
from .ldata_service import VERSION

FRONTEND_URL_PATH = "/ldata_static"
PANEL_CARD_FILENAME = "ldata-panel-card.js"
CARD_URL = f"{FRONTEND_URL_PATH}/{PANEL_CARD_FILENAME}"

_LOGGER = logging.getLogger(LOGGER_NAME)

_URL_KEY = "_card_url"
_LOCK_KEY = "_card_lock"


def card_digest(path: Path) -> str | None:
    """Return a short content hash of the panel card, or None if unreadable."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:10]
    except OSError:
        return None


async def async_serve_card(hass: HomeAssistant) -> str | None:
    """Serve the www/ folder and return the URL to load the card from.

    The folder is served with long-lived cache headers, so the ?v= query is
    what makes browsers fetch a changed card. It carries a hash of the file as
    well as the release number, which also covers a card edited between
    releases.

    Safe to call any number of times: the folder is registered and the file
    hashed once per Home Assistant run. Returns None when the folder is
    missing (a broken install), in which case there is no card to load.
    """
    domain_data = hass.data.setdefault(DOMAIN, {})
    lock = domain_data.setdefault(_LOCK_KEY, asyncio.Lock())
    async with lock:
        if _URL_KEY in domain_data:
            return domain_data[_URL_KEY]

        www_dir = Path(__file__).parent / "www"
        if not await hass.async_add_executor_job(www_dir.is_dir):
            _LOGGER.warning(
                "LDATA www directory not found at %s — panel card won't load", www_dir
            )
            domain_data[_URL_KEY] = None
            return None

        try:
            await hass.http.async_register_static_paths(
                [StaticPathConfig(FRONTEND_URL_PATH, str(www_dir), True)]
            )
        except RuntimeError:
            _LOGGER.debug("LDATA static path already registered at %s", FRONTEND_URL_PATH)

        digest = await hass.async_add_executor_job(
            card_digest, www_dir / PANEL_CARD_FILENAME
        )
        url = f"{CARD_URL}?v={VERSION}-{digest}" if digest else f"{CARD_URL}?v={VERSION}"
        domain_data[_URL_KEY] = url
        return url
