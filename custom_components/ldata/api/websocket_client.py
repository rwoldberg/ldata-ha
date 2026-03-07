"""WebSocket Client for Leviton API."""

import asyncio
import json
import logging
import aiohttp

from ..const import LOGGER_NAME, WS_HEARTBEAT_INTERVAL
from .http_client import LDATAHttpClient

_LOGGER = logging.getLogger(LOGGER_NAME)

class LDATAWebsocketClient:
    """Handles WebSocket connections to Leviton."""

    def __init__(self, http_client: LDATAHttpClient, service) -> None:
        self.http = http_client
        self.service = service # Reference to LDATAService to read status_data
        self._shutdown_requested = False
        self.uri = "wss://socket.cloud.leviton.com/"

    def _construct_auth_payload(self):
        from datetime import datetime, timezone
        if self.http.full_auth_response:
            return {"token": self.http.full_auth_response}
        return {
            "token": {
                "id": self.http.auth_token,
                "userId": self.http.userid,
                "ttl": 5184000, 
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "scopes": None
            }
        }

    async def _ws_authenticate(self, ws):
        try:
            await ws.send_json(self._construct_auth_payload())
        except Exception:
            return False
            
        loop = asyncio.get_running_loop()
        deadline = loop.time() + 10
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0: raise asyncio.TimeoutError()
            msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get("status") == "ready": return True
                if "error" in data: return False
            elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                return False

    async def _ws_send_subscriptions(self, ws):
        subscriptions = []
        for res_id in self.http.residence_id_list:
            formatted_id = int(res_id) if str(res_id).isdigit() else res_id
            subscriptions.append({"type": "subscribe", "subscription": {"modelName": "Residence", "modelId": formatted_id}})
        
        if self.service.status_data:
            for panel in self.service.status_data.get("panels", []):
                subscriptions.append({"type": "subscribe", "subscription": {"modelName": "IotWhem", "modelId": panel["id"]}})
            for b_id in self.service.status_data.get("breakers", {}):
                subscriptions.append({"type": "subscribe", "subscription": {"modelName": "ResidentialBreaker", "modelId": b_id}})
            for ct_id in self.service.status_data.get("cts", {}):
                subscriptions.append({"type": "subscribe", "subscription": {"modelName": "IotCt", "modelId": int(ct_id)}})
        
        for sub in subscriptions:
            if ws.closed:
                return False
            try:
                await ws.send_json(sub)
            except (aiohttp.ClientConnectionResetError, ConnectionResetError):
                return False
        return True

    async def async_run_websocket(self, update_callback, connection_callback=None):
        reconnect_delay = 10
        max_delay = 300
        
        def notify_connection(connected: bool):
            if connection_callback:
                try: connection_callback(connected)
                except Exception: pass
        
        while not self._shutdown_requested:
            try:
                if not self.http.auth_token:
                    notify_connection(False)
                    await asyncio.sleep(10)
                    continue
                
                try:
                    ws = await self.http.session.ws_connect(self.uri, headers=self.http.default_headers, compress=15)
                except Exception:
                    notify_connection(False)
                    await asyncio.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, max_delay)
                    continue
                
                _heartbeat_task: asyncio.Task | None = None
                try:
                    if not await self._ws_authenticate(ws): continue
                    
                    retry_count = 0
                    while not self.service.status_data and retry_count < 5:
                        await asyncio.sleep(2)
                        retry_count += 1
                        
                    if not await self._ws_send_subscriptions(ws): continue
                    notify_connection(True)
                    
                    # Heartbeat tasks
                    async def apiversion_heartbeat():
                        try: await self.http.session.get("https://my.leviton.com/apiversion", headers={**self.http.default_headers, "authorization": self.http.auth_token}, timeout=aiohttp.ClientTimeout(total=10))
                        except Exception: pass

                    loop = asyncio.get_running_loop()
                    start_time = loop.time()
                    last_heartbeat_time = start_time
                    last_data_time = start_time
                    resubscribe_count = 0
                    
                    while True:
                        current_time = loop.time()
                        
                        if current_time - last_heartbeat_time >= WS_HEARTBEAT_INTERVAL:
                            last_heartbeat_time = current_time
                            if _heartbeat_task is None or _heartbeat_task.done():
                                _heartbeat_task = asyncio.create_task(apiversion_heartbeat())
                        
                        if current_time - last_data_time >= 60:
                            resubscribe_count += 1
                            last_data_time = current_time
                            if resubscribe_count <= 5:
                                if not await self._ws_send_subscriptions(ws): break
                            else: break
                        
                        if current_time - start_time >= 3300: break # Proactive reconnect
                        
                        try:
                            msg = await asyncio.wait_for(ws.receive(), timeout=15.0)
                        except asyncio.TimeoutError:
                            continue
                        except Exception:
                            break
                        
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            last_data_time = current_time
                            try:
                                payload = json.loads(msg.data)
                                if payload.get("type") == "notification":
                                    if self.service._update_from_websocket(payload.get("notification", {})):
                                        try: update_callback()
                                        except Exception: pass
                            except Exception: pass
                        elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSE):
                            break
                finally:
                    notify_connection(False)
                    if _heartbeat_task and not _heartbeat_task.done():
                        _heartbeat_task.cancel()
                    if not ws.closed:
                        try: await ws.close()
                        except Exception: pass
                reconnect_delay = 10
            except Exception:
                notify_connection(False)
            
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, max_delay)
