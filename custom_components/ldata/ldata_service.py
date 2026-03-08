"""The LDATAService Data Orchestrator."""

import logging
import typing
import time
import asyncio
import os
import json


from .const import _LEG1_POSITIONS, LOGGER_NAME, THREE_PHASE, THREE_PHASE_DEFAULT
from .api.exceptions import LDATAAuthError, TwoFactorRequired
from .api.http_client import LDATAHttpClient
from .api.websocket_client import LDATAWebsocketClient

try:
    with open(os.path.join(os.path.dirname(__file__), 'manifest.json')) as f:
        manifest_data = json.load(f)
        VERSION = manifest_data.get('version', 'Unknown')
except Exception:
    VERSION = "Unknown"

_LOGGER = logging.getLogger(LOGGER_NAME)

class LDATAService:
    """The LDATAService Data Orchestrator.

    Handles data normalization, zero-transition protection, and gap logic.
    HTTP and WebSocket transport are delegated to api/http_client and
    api/websocket_client respectively.
    """

    def __init__(self, username, password, entry, session) -> None:
        """Init LDATAService."""
        self.entry = entry
        
        self.http = LDATAHttpClient(username, password, session, VERSION)
        self.ws = LDATAWebsocketClient(self.http, self)
        
        if entry:
            self.http.refresh_token = entry.data.get("refresh_token", "")
            self.http.userid = entry.data.get("userid", "")
            # Three-phase voltage calculation mode — cached from options so all
            # update paths (REST, WS direct, WS embedded) use the same formula.
            self._three_phase = entry.options.get(
                THREE_PHASE, entry.data.get(THREE_PHASE, THREE_PHASE_DEFAULT)
            )
        else:
            self._three_phase = THREE_PHASE_DEFAULT
            
        # Lock to serialize REST poll operations. The breaker poll and CT poll
        # both interact with the bandwidth setting. Without serialization the
        # CT toggle (bandwidth:0) can corrupt a concurrent breaker GET.
        self._rest_poll_lock = asyncio.Lock()
        # Cache for the latest status data — shared by WebSocket and REST updates
        self.status_data = None
        
        # Per-panel REST polling flags.
        # WS-first: panels start with REST disabled. If WS doesn't deliver
        # breaker data within the grace period, REST polling activates as fallback.
        self._panel_needs_rest_poll: dict[str, bool] = {}
        # Track whether panels have hardware energy counters (energyConsumption).
        # When False, breaker daily sensors fall back to power×time integration.
        self._panel_has_hw_counters: dict[str, bool] = {}
        # Per-panel CT REST polling flag (independent of breaker REST poll).
        # CT energy counters require a bandwidth toggle to refresh.
        self._panel_needs_ct_poll: dict[str, bool] = {}
        # Track how many IotWhem WS messages we've seen per panel without breaker data
        self._ws_iotwhem_count: dict[str, int] = {}
        # Track when WS last delivered breaker data per panel (for coordinator)
        self._ws_last_breaker_data_time: dict[str, float] = {}
        # Panel type lookup: "LDATA" for old v1 panels, "WHEMS" for v2 panels.
        # Used to scope energy counter guards to unreliable v1 panels only.
        self._panel_type: dict[str, str] = {}

        # ── Unified zero-transition protection ────────────────────────
        # On V2 firmware the cloud sporadically sends zero power *and/or*
        # zero rmsCurrent for breakers that actually carry a stable load.
        # We protect BOTH power and current together: once loaded, all
        # electrical fields are frozen until the breaker reports zero for
        # BOTH power AND current for N consecutive updates.
        self._breaker_zero_count: dict[str, int] = {}
        self._ZERO_CONFIRM_THRESHOLD = 3
        # Timestamp of last zero-counter increment per breaker. If too much
        # wall-clock time passes between increments, the counter resets.
        self._breaker_zero_last_time: dict[str, float] = {}
        self._ZERO_DECAY_SECONDS = 180.0
        # Panels currently undergoing a bandwidth toggle. While a panel is
        # in this set, zero-counter increments are suppressed so the transient
        # zeros caused by bandwidth:0 don't accumulate.
        self._panels_in_bandwidth_toggle: set[str] = set()

        # ── Energy counter monotonic protection ──────────────────────
        # Lifetime energy counters should only increase. Transient drops
        # (reconnect bursts, partial payloads) are rejected. But genuine
        # counter resets (firmware update, factory reset) are persistent —
        # if the same breaker+field reports a lower value for N consecutive
        # updates, we accept it as a real reset.
        self._energy_decrease_count: dict[str, int] = {}
        self._ENERGY_DECREASE_ACCEPT_THRESHOLD = 5

    @property
    def auth_token(self): return self.http.auth_token
    @property
    def refresh_token(self): return self.http.refresh_token
    @property
    def userid(self): return self.http.userid
    @property
    def version(self): return self.http.version
    @property
    def _shutdown_requested(self): return self.ws._shutdown_requested
    @_shutdown_requested.setter
    def _shutdown_requested(self, value): self.ws._shutdown_requested = value

    async def auth_with_credentials(self) -> bool:
        return await self.http.auth_with_credentials()

    async def complete_2fa(self, code: str) -> bool:
        return await self.http.complete_2fa(code)

    async def async_run_websocket(self, update_callback, connection_callback=None):
        return await self.ws.async_run_websocket(update_callback, connection_callback)

    async def remote_off(self, breaker_id: str):
        return await self.http.remote_trip(breaker_id, "off")

    async def remote_on(self, breaker_id: str):
        return await self.http.remote_trip(breaker_id, "on")

    async def set_blink_led(self, breaker_id: str, enabled: bool):
        return await self.http.set_blink_led(breaker_id, enabled)

    async def status(self):
        """Fetch full panel/breaker/CT data from the Leviton cloud API.

        This is only called for the initial data fetch at startup. After that,
        WebSocket handles all live updates, with REST polling as a fallback
        only for panels where WS doesn't deliver breaker/CT data.
        """
        try:
            if not await self.http.refresh_auth():
                raise LDATAAuthError(f"[v{self.version}] Token validation failed.")
        except LDATAAuthError: raise

        if not self.http.account_id:
            if not await self.http.get_residential_account():
                 raise Exception("Could not get LDATA Account ID.")
        
        if not self.http.residence_id_list:
            await self.http.get_residences()
            if not self.http.residence_id_list:
                await self.http.get_residence()
            await self.http.get_residencePermissions()
        
        self.http.residence_id_list = list(set([x for x in self.http.residence_id_list if x is not None]))

        if not self.http.residence_id_list:
            raise Exception("Could not get LDATA Residence ID.")
        
        panels_json = None
        for res_id in self.http.residence_id_list:
            # Fetch LDATA panels via http_client (auth-error aware)
            try:
                ldata_panels = await self.http.get_ldata_panels(res_id)
                if ldata_panels:
                    for p in ldata_panels:
                        p["ModuleType"] = "LDATA"
                    panels_json = ldata_panels
            except LDATAAuthError:
                raise
            except Exception as ex:
                _LOGGER.warning("[v%s] Failed to fetch LDATA panels for residence %s: %s", self.version, res_id, ex)
            
            # Fetch WHEMS panels via http_client (auth-error aware)
            try:
                whem_data = await self.http.get_whems_panels(res_id)
                if whem_data:
                    for p in whem_data: 
                        p["ModuleType"] = "WHEMS"
                        p["rmsVoltage"] = p.get("rmsVoltageA")
                        p["rmsVoltage2"] = p.get("rmsVoltageB")
                        p["updateVersion"] = p.get("version")
                        p["residentialBreakers"] = await self.http.get_Whems_breakers(p["id"])
                        p["CTs"] = await self.http.get_Whems_CT(p["id"])
                    if panels_json is None:
                        panels_json = whem_data
                    else:
                        panels_json.extend(whem_data)
            except LDATAAuthError:
                raise
            except Exception as ex:
                _LOGGER.warning("[v%s] Failed to fetch WHEMS panels for residence %s: %s", self.version, res_id, ex)

        return self.parse_panels(panels_json)

    def _parse_float(self, data_dict, key, default=None):
        try:
            val = data_dict.get(key)
            return float(val) if val is not None else default
        except (ValueError, TypeError, AttributeError):
            return default

    def parse_panels(self, panels_json) -> object:
        status_data: dict[str, typing.Any] = {"breakers": {}, "cts": {}, "panels": []}
        breakers: dict[str, typing.Any] = {}
        cts: dict[str, typing.Any] = {}
        status_data["breakers"] = breakers
        status_data["cts"] = cts
        
        if not panels_json: 
            return status_data

        three_phase = self._three_phase

        for panel in panels_json:
            panel_id = panel.get("id")
            if not panel_id: continue
            
            panel_data = {
                "firmware": panel.get("updateVersion", "unknown"),
                "model": panel.get("model", "unknown"),
                "id": panel_id,
                "name": panel.get("name", "Unknown Panel"),
                "serialNumber": panel_id,
                "panel_type": panel.get("ModuleType", "WHEMS"),
                "connected": panel.get("connected", False),
                "overVoltage": panel.get("overVoltage", False),
                "underVoltage": panel.get("underVoltage", False),
                "rssi": self._parse_float(panel, "rssi")
            }
            if panel.get("model") == "DAU" and panel.get("status") == "READY":
                panel_data["connected"] = True
            
            if panel_id not in self._panel_needs_rest_poll:
                self._panel_needs_rest_poll[panel_id] = False
                self._panel_needs_ct_poll[panel_id] = False
                self._ws_iotwhem_count[panel_id] = 0
            
            self._panel_type[panel_id] = panel.get("ModuleType", "WHEMS")

            panel_data["voltage1"] = self._parse_float(panel, "rmsVoltage", 0.0)
            panel_data["voltage2"] = self._parse_float(panel, "rmsVoltage2", 0.0)
            if not three_phase:
                panel_data["voltage"] = (panel_data["voltage1"] + panel_data["voltage2"]) / 2.0
            else:
                panel_data["voltage"] = (panel_data["voltage1"] * 0.866025403784439) + (panel_data["voltage2"] * 0.866025403784439)

            panel_data["frequency1"] = self._parse_float(panel, "frequencyA", 0.0)
            panel_data["frequency2"] = self._parse_float(panel, "frequencyB", 0.0)
            if panel_data["frequency1"] == 0 and panel.get("residentialBreakers"):
                for breaker in panel["residentialBreakers"]:
                    if breaker.get("position", 0) in _LEG1_POSITIONS:
                        if self._parse_float(breaker, "lineFrequency", 0.0) > 0:
                            panel_data["frequency1"] = self._parse_float(breaker, "lineFrequency", 0.0)
                        if self._parse_float(breaker, "lineFrequency2", 0.0) > 0:
                            panel_data["frequency2"] = self._parse_float(breaker, "lineFrequency2", 0.0)
                    else:
                        if self._parse_float(breaker, "lineFrequency", 0.0) > 0:
                            panel_data["frequency2"] = self._parse_float(breaker, "lineFrequency", 0.0)
                        if self._parse_float(breaker, "lineFrequency2", 0.0) > 0:
                            panel_data["frequency1"] = self._parse_float(breaker, "lineFrequency2", 0.0)
                    if panel_data["frequency1"] != 0 and panel_data["frequency2"] != 0:
                        break
                        
            if panel_data["frequency2"] == 0:
                panel_data["frequency2"] = panel_data["frequency1"]
            panel_data["frequency"] = (panel_data["frequency1"] + panel_data["frequency2"]) / 2.0

            if panel.get("CTs"):
                self._panel_needs_rest_poll[panel_id] = True
                self._panel_needs_ct_poll[panel_id] = True
                for ct in panel["CTs"]:
                    if ct.get("usageType") != "NOT_USED":
                        ct_data = {}
                        ct_data["name"] = ct["usageType"]
                        ct_data["id"] = str(ct["id"])
                        ct_data["panel_id"] = panel_id
                        ct_data["channel"] = str(ct.get("channel", ""))
                        ct_data["power1"] = self._parse_float(ct, "activePower", 0.0)
                        ct_data["power2"] = self._parse_float(ct, "activePower2", 0.0)
                        ct_data["power"] = ct_data["power1"] + ct_data["power2"]
                        ct_data["consumption1"] = self._parse_float(ct, "energyConsumption", 0.0)
                        ct_data["consumption2"] = self._parse_float(ct, "energyConsumption2", 0.0)
                        ct_data["consumption"] = ct_data["consumption1"] + ct_data["consumption2"]
                        ct_data["import1"] = self._parse_float(ct, "energyImport", 0.0)
                        ct_data["import2"] = self._parse_float(ct, "energyImport2", 0.0)
                        ct_data["import"] = ct_data["import1"] + ct_data["import2"]
                        ct_data["current1"] = self._parse_float(ct, "rmsCurrent", 0.0)
                        ct_data["current2"] = self._parse_float(ct, "rmsCurrent2", 0.0)
                        ct_data["current"] = (ct_data["current1"] + ct_data["current2"]) / 2.0
                        cts[ct_data["id"]] = ct_data

            total_power = 0.0
            if panel.get("residentialBreakers"):
                for breaker in panel["residentialBreakers"]:
                    if breaker.get("model") not in (None, "NONE-2", "NONE-1"):
                        breaker_data = {
                            "panel_id": panel_id,
                            "rating": breaker.get("currentRating"),
                            "position": breaker.get("position"),
                            "name": breaker.get("name"),
                            "state": breaker.get("currentState"),
                            "id": breaker.get("id"),
                            "model": breaker.get("model"),
                            "poles": breaker.get("poles"),
                            "serialNumber": breaker.get("serialNumber"),
                            "hardware": breaker.get("hwVersion"),
                            "firmware": breaker.get("firmwareVersionMeter"),
                            "canRemoteOn": breaker.get("canRemoteOn", False),
                            "remoteState": breaker.get("remoteState", "RemoteON") or "RemoteON",
                            "operationalState": breaker.get("operationalState", "Normal"),
                            "overCurrent": breaker.get("overCurrent", False),
                            "overVoltage": breaker.get("overVoltage", False),
                            "underVoltage": breaker.get("underVoltage", False),
                            "blinkLED": breaker.get("blinkLED", False)
                        }
                        
                        _ble_rssi = self._parse_float(breaker, "bleRSSI", None)
                        breaker_data["bleRSSI"] = _ble_rssi if _ble_rssi is not None and _ble_rssi < 0 else None
                        
                        _p1 = self._parse_float(breaker, "power", None)
                        _p2 = self._parse_float(breaker, "power2", None)
                        breaker_data["power"] = (_p1 or 0.0) + (_p2 or 0.0) if _p1 is not None or _p2 is not None else None
                        
                        if not three_phase or breaker.get("poles") == 1:
                            breaker_data["voltage"] = self._parse_float(breaker, "rmsVoltage", 0.0) + self._parse_float(breaker, "rmsVoltage2", 0.0)
                        else:
                            breaker_data["voltage"] = (self._parse_float(breaker, "rmsVoltage", 0.0) * 0.866025403784439) + (self._parse_float(breaker, "rmsVoltage2", 0.0) * 0.866025403784439)

                        if breaker.get("poles") == 2:
                            breaker_data["frequency"] = (self._parse_float(breaker, "lineFrequency", 0.0) + self._parse_float(breaker, "lineFrequency2", 0.0)) / 2.0
                            _c1 = self._parse_float(breaker, "rmsCurrent", None)
                            _c2 = self._parse_float(breaker, "rmsCurrent2", None)
                            breaker_data["current"] = ((_c1 or 0.0) + (_c2 or 0.0)) / 2.0 if _c1 is not None or _c2 is not None else None
                        else:
                            breaker_data["frequency"] = self._parse_float(breaker, "lineFrequency", 0.0)
                            _c1 = self._parse_float(breaker, "rmsCurrent", None)
                            _c2 = self._parse_float(breaker, "rmsCurrent2", None)
                            breaker_data["current"] = (_c1 or 0.0) + (_c2 or 0.0) if _c1 is not None or _c2 is not None else None
                        
                        if breaker.get("position") in _LEG1_POSITIONS:
                            breaker_data["leg"] = 1
                            breaker_data["power1"], breaker_data["power2"] = _p1, _p2
                            breaker_data["voltage1"] = self._parse_float(breaker, "rmsVoltage", 0.0)
                            breaker_data["voltage2"] = self._parse_float(breaker, "rmsVoltage2", 0.0)
                            breaker_data["current1"], breaker_data["current2"] = _c1, _c2
                            breaker_data["frequency1"] = self._parse_float(breaker, "lineFrequency", 0.0)
                            breaker_data["frequency2"] = self._parse_float(breaker, "lineFrequency2", 0.0)
                        else:
                            breaker_data["leg"] = 2
                            breaker_data["power1"], breaker_data["power2"] = _p2, _p1
                            breaker_data["voltage1"] = self._parse_float(breaker, "rmsVoltage2", 0.0)
                            breaker_data["voltage2"] = self._parse_float(breaker, "rmsVoltage", 0.0)
                            breaker_data["current1"], breaker_data["current2"] = _c2, _c1
                            breaker_data["frequency1"] = self._parse_float(breaker, "lineFrequency2", 0.0)
                            breaker_data["frequency2"] = self._parse_float(breaker, "lineFrequency", 0.0)
                        
                        breaker_data["consumption1"] = self._parse_float(breaker, "energyConsumption", 0.0)
                        breaker_data["consumption2"] = self._parse_float(breaker, "energyConsumption2", 0.0)
                        breaker_data["consumption"] = breaker_data["consumption1"] + breaker_data["consumption2"]
                        breaker_data["import1"] = self._parse_float(breaker, "energyImport", 0.0)
                        breaker_data["import2"] = self._parse_float(breaker, "energyImport2", 0.0)
                        breaker_data["import"] = breaker_data["import1"] + breaker_data["import2"]
                        
                        breakers[breaker["id"]] = breaker_data
                        if breaker_data["power"] is not None:
                            total_power += breaker_data["power"]

            status_data[panel_id + "totalPower"] = total_power
            
            has_hw = False
            for b_data in breakers.values():
                if b_data.get("panel_id") == panel_id and (b_data.get("consumption", 0) > 0 or b_data.get("consumption1", 0) > 0):
                    has_hw = True
                    break
            self._panel_has_hw_counters[panel_id] = has_hw

            status_data["panels"].append(panel_data)

        self.status_data = status_data
        return status_data

    async def _bandwidth_toggle(self, panel_id: str, panel_type: str = "WHEMS"):
        """Toggle bandwidth 1→0→1 to force CT energy counter refresh."""
        self._panels_in_bandwidth_toggle.add(panel_id)
        try:
            await self.http.put_bandwidth(panel_id, panel_type, 1)
            await self.http.put_bandwidth(panel_id, panel_type, 0)
            await self.http.put_bandwidth(panel_id, panel_type, 1)
        finally:
            self._panels_in_bandwidth_toggle.discard(panel_id)

    def _check_zero_transition(self, breaker_id: str, new_power: float, new_current: float, old_power: float, old_current: float, source: str = "?", power_from_msg: bool = True, current_from_msg: bool = True, panel_id: str | None = None) -> bool:
        """Unified zero-transition guard.

        Returns True if the electrical update should be accepted, False if it
        should be suppressed (breaker was loaded, arrived values are all zero,
        and the consecutive-zero count hasn't reached the confirmation threshold).
        """
        was_loaded = abs(old_power) > 0 or abs(old_current) > 0.01
        if not was_loaded:
            self._breaker_zero_count[breaker_id] = 0
            return True

        arriving_values = []
        if power_from_msg: arriving_values.append(abs(new_power))
        if current_from_msg: arriving_values.append(abs(new_current))

        if not arriving_values: return True
        if any(v > 0.01 for v in arriving_values):
            self._breaker_zero_count[breaker_id] = 0
            return True

        if panel_id and panel_id in self._panels_in_bandwidth_toggle:
            return False

        now = time.time()
        if (now - self._breaker_zero_last_time.get(breaker_id, 0)) > self._ZERO_DECAY_SECONDS:
            self._breaker_zero_count[breaker_id] = 0

        count = self._breaker_zero_count.get(breaker_id, 0) + 1
        self._breaker_zero_count[breaker_id] = count
        self._breaker_zero_last_time[breaker_id] = now
        
        if count < self._ZERO_CONFIRM_THRESHOLD: return False
        
        self._breaker_zero_count[breaker_id] = 0
        return True

    def _guard_energy_counter(self, key: str, new_val: float, cached_val: float) -> float:
        """Monotonic guard for a single energy counter field.

        Returns new_val if it's >= cached, or if the counter has been
        consistently lower for enough consecutive updates to indicate a
        genuine hardware reset. Otherwise returns cached_val.
        """
        if new_val >= cached_val:
            # Normal case — counter increased or stayed the same
            self._energy_decrease_count.pop(key, None)
            return new_val

        # Counter decreased — track consecutive drops
        count = self._energy_decrease_count.get(key, 0) + 1
        self._energy_decrease_count[key] = count

        if count >= self._ENERGY_DECREASE_ACCEPT_THRESHOLD:
            # Persistent decrease — accept as genuine counter reset
            self._energy_decrease_count.pop(key, None)
            _LOGGER.info(
                "[v%s] Energy counter %s accepted decrease after %d consecutive "
                "readings: %.3f -> %.3f (likely genuine reset)",
                self.version, key, count, cached_val, new_val,
            )
            return new_val

        # Transient decrease — hold cached value
        return cached_val

    def _apply_breaker_update(self, breaker_id: str, existing: dict, raw: dict, source: str = "?") -> bool:
        """Apply a raw breaker update (from WS or REST) to the existing cached breaker dict.

        Handles leg-aware field mapping, zero-transition protection, and
        selective field updates. Returns True if power changed (caller should
        recalculate panel total).
        """
        def _field(key, cached):
            if key in raw and raw[key] is not None: return float(raw[key])
            return cached

        cached_p1 = existing.get("power1") or 0
        cached_p2 = existing.get("power2") or 0
        leg = existing.get("leg", 1)
        
        if leg == 1:
            p1 = _field("power", cached_p1)
            p2 = _field("power2", cached_p2)
        else:
            p2 = _field("power", cached_p2)
            p1 = _field("power2", cached_p1)
        
        cached_c1 = existing.get("current1") or 0
        cached_c2 = existing.get("current2") or 0
        if leg == 1:
            c1 = _field("rmsCurrent", cached_c1)
            c2 = _field("rmsCurrent2", cached_c2)
        else:
            c2 = _field("rmsCurrent", cached_c2)
            c1 = _field("rmsCurrent2", cached_c1)
        
        has_power_field = "power" in raw or "power2" in raw
        has_current_field = "rmsCurrent" in raw or "rmsCurrent2" in raw
        has_voltage_field = "rmsVoltage" in raw or "rmsVoltage2" in raw
        has_frequency_field = "lineFrequency" in raw or "lineFrequency2" in raw
        has_any_electrical = has_power_field or has_current_field
        
        cand_power = (p1 + p2) if has_power_field else (existing.get("power") or 0)
        poles = existing.get("poles", 1)
        cand_current = ((c1 + c2) / 2 if poles == 2 else c1 + c2) if has_current_field else (existing.get("current") or 0)
        
        if has_any_electrical:
            accept_update = self._check_zero_transition(
                breaker_id, cand_power, cand_current,
                existing.get("power") or 0, existing.get("current") or 0,
                source=source, power_from_msg=has_power_field, current_from_msg=has_current_field,
                panel_id=existing.get("panel_id"),
            )
        else:
            accept_update = True
        
        power_changed = False
        if accept_update:
            if has_power_field:
                existing["power"] = cand_power
                existing["power1"] = p1
                existing["power2"] = p2
                power_changed = True
            if has_current_field:
                existing["current"] = cand_current
                existing["current1"] = c1
                existing["current2"] = c2
            
            if has_voltage_field:
                cached_v1 = existing.get("voltage1", 0)
                cached_v2 = existing.get("voltage2", 0)
                if leg == 1:
                    v1 = _field("rmsVoltage", cached_v1)
                    v2 = _field("rmsVoltage2", cached_v2)
                else:
                    v2 = _field("rmsVoltage", cached_v2)
                    v1 = _field("rmsVoltage2", cached_v1)
                existing["voltage1"] = v1
                existing["voltage2"] = v2
                if (not self._three_phase) or (poles == 1):
                    existing["voltage"] = v1 + v2
                else:
                    existing["voltage"] = (v1 * 0.866025403784439) + (v2 * 0.866025403784439)
            
            if has_frequency_field:
                cached_f1 = existing.get("frequency1", 0)
                cached_f2 = existing.get("frequency2", 0)
                if leg == 1:
                    f1 = _field("lineFrequency", cached_f1)
                    f2 = _field("lineFrequency2", cached_f2)
                else:
                    f2 = _field("lineFrequency", cached_f2)
                    f1 = _field("lineFrequency2", cached_f1)
                existing["frequency1"] = f1
                existing["frequency2"] = f2
                if poles == 2:
                    existing["frequency"] = (f1 + f2) / 2
                else:
                    existing["frequency"] = f1
        else:
            if has_power_field:
                existing["power1"] = cached_p1
                existing["power2"] = cached_p2
        
        if raw.get("currentState"): existing["state"] = raw["currentState"]
        if raw.get("connected") is not None: existing["connected"] = raw["connected"]
        if raw.get("remoteState") is not None:
            existing["remoteState"] = raw["remoteState"]
            if existing["remoteState"] == "": existing["remoteState"] = "RemoteON"
        
        if "operationalState" in raw: existing["operationalState"] = raw["operationalState"]
        if "overCurrent" in raw: existing["overCurrent"] = raw["overCurrent"]
        if "overVoltage" in raw: existing["overVoltage"] = raw["overVoltage"]
        if "underVoltage" in raw: existing["underVoltage"] = raw["underVoltage"]
        if "blinkLED" in raw: existing["blinkLED"] = raw["blinkLED"]
        if "bleRSSI" in raw and raw["bleRSSI"] is not None:
            try:
                val = float(raw["bleRSSI"])
                if val < 0: existing["bleRSSI"] = val
            except (ValueError, TypeError): pass
        # --- NEW BREAKER RIEMANN SUM DRIFT LOGIC ---
        import time
        now = time.time()
        last_time = existing.get("last_power_time")
        if last_time:
            time_diff_hours = (now - last_time) / 3600.0
            power_w = existing.get("power", 0)
            
            if power_w > 0:
                kw = power_w / 1000.0
                existing["drift_accumulator_consumption"] = existing.get("drift_accumulator_consumption", 0.0) + (kw * time_diff_hours)
            elif power_w < 0:
                kw = abs(power_w) / 1000.0
                existing["drift_accumulator_import"] = existing.get("drift_accumulator_import", 0.0) + (kw * time_diff_hours)
                
        existing["last_power_time"] = now
        
        # ── Energy counter updates (lifetime — must be monotonically increasing) ──
        panel_id = existing.get("panel_id")
        use_energy_guard = self._panel_type.get(panel_id) == "LDATA"

        # CONSUMPTION TRUE-UP
        if "energyConsumption" in raw or "energyConsumption2" in raw:
            cached_ec1 = existing.get("consumption1", 0)
            cached_ec2 = existing.get("consumption2", 0)
            old_base_cons = cached_ec1 + cached_ec2
            
            if "energyConsumption" in raw:
                new_ec1 = float(raw["energyConsumption"]) if raw["energyConsumption"] is not None else cached_ec1
                existing["consumption1"] = self._guard_energy_counter(breaker_id + ":ec1", new_ec1, cached_ec1) if use_energy_guard else new_ec1
            if "energyConsumption2" in raw:
                new_ec2 = float(raw["energyConsumption2"]) if raw["energyConsumption2"] is not None else cached_ec2
                existing["consumption2"] = self._guard_energy_counter(breaker_id + ":ec2", new_ec2, cached_ec2) if use_energy_guard else new_ec2
            
            new_base_cons = existing.get("consumption1", 0) + existing.get("consumption2", 0)
            
            # Smooth True-Up
            if new_base_cons > old_base_cons:
                hardware_delta = new_base_cons - old_base_cons
                current_drift = existing.get("drift_accumulator_consumption", 0.0)
                existing["drift_accumulator_consumption"] = max(0.0, current_drift - hardware_delta)
                
        # Apply consumption = Baseline Hardware Counter + Software Drift
        base_consumption = existing.get("consumption1", 0) + existing.get("consumption2", 0)
        existing["consumption"] = base_consumption + existing.get("drift_accumulator_consumption", 0.0)
        
        # IMPORT TRUE-UP
        if "energyImport" in raw or "energyImport2" in raw:
            cached_ei1 = existing.get("import1", 0)
            cached_ei2 = existing.get("import2", 0)
            old_base_imp = cached_ei1 + cached_ei2
            
            if "energyImport" in raw:
                new_ei1 = float(raw["energyImport"]) if raw["energyImport"] is not None else cached_ei1
                existing["import1"] = self._guard_energy_counter(breaker_id + ":ei1", new_ei1, cached_ei1) if use_energy_guard else new_ei1
            if "energyImport2" in raw:
                new_ei2 = float(raw["energyImport2"]) if raw["energyImport2"] is not None else cached_ei2
                existing["import2"] = self._guard_energy_counter(breaker_id + ":ei2", new_ei2, cached_ei2) if use_energy_guard else new_ei2
            
            new_base_imp = existing.get("import1", 0) + existing.get("import2", 0)
            
            # Smooth True-Up
            if new_base_imp > old_base_imp:
                hardware_delta = new_base_imp - old_base_imp
                current_drift = existing.get("drift_accumulator_import", 0.0)
                existing["drift_accumulator_import"] = max(0.0, current_drift - hardware_delta)
                
        # Apply import = Baseline Hardware Counter + Software Drift
        base_import = existing.get("import1", 0) + existing.get("import2", 0)
        existing["import"] = base_import + existing.get("drift_accumulator_import", 0.0)
        
        return power_changed

    def _apply_ct_update(self, existing: dict, raw: dict) -> None:
        import time
        now = time.time()
        
        if "activePower" in raw or "activePower2" in raw:
            cached_p1, cached_p2 = existing.get("power1", 0), existing.get("power2", 0)
            if "activePower" in raw: existing["power1"] = float(raw["activePower"]) if raw["activePower"] is not None else cached_p1
            if "activePower2" in raw: existing["power2"] = float(raw["activePower2"]) if raw["activePower2"] is not None else cached_p2
            existing["power"] = existing["power1"] + existing["power2"]
            
            # RIEMANN SUM INTEGRAL LOGIC
            last_time = existing.get("last_power_time")
            if last_time:
                time_diff_hours = (now - last_time) / 3600.0
                power_w = existing["power"]
                
                # CORRECTED DIRECTIONAL LOGIC
                if power_w > 0:
                    # Positive power: Pulling from grid -> Add ONLY to Consumption
                    kw = power_w / 1000.0
                    existing["drift_accumulator_consumption"] = existing.get("drift_accumulator_consumption", 0.0) + (kw * time_diff_hours)
                elif power_w < 0:
                    # Negative power: Exporting to grid -> Add ONLY to Import
                    kw = abs(power_w) / 1000.0
                    existing["drift_accumulator_import"] = existing.get("drift_accumulator_import", 0.0) + (kw * time_diff_hours)
                
            existing["last_power_time"] = now

        ct_panel_id = existing.get("panel_id")
        use_ct_guard = self._panel_type.get(ct_panel_id) == "LDATA"

        # CONSUMPTION TRUE-UP
        if "energyConsumption" in raw or "energyConsumption2" in raw:
            ct_id = existing.get("id", "?")
            cached_c1, cached_c2 = existing.get("consumption1", 0), existing.get("consumption2", 0)
            old_base_cons = cached_c1 + cached_c2
            
            if "energyConsumption" in raw:
                new_c1 = float(raw["energyConsumption"]) if raw["energyConsumption"] is not None else cached_c1
                existing["consumption1"] = self._guard_energy_counter("ct:" + ct_id + ":ec1", new_c1, cached_c1) if use_ct_guard else new_c1
            if "energyConsumption2" in raw:
                new_c2 = float(raw["energyConsumption2"]) if raw["energyConsumption2"] is not None else cached_c2
                existing["consumption2"] = self._guard_energy_counter("ct:" + ct_id + ":ec2", new_c2, cached_c2) if use_ct_guard else new_c2
            
            new_base_cons = existing.get("consumption1", 0) + existing.get("consumption2", 0)
            
            # Smooth True-Up: Deduct the exact hardware catch-up amount
            if new_base_cons > old_base_cons:
                hardware_delta = new_base_cons - old_base_cons
                current_drift = existing.get("drift_accumulator_consumption", 0.0)
                existing["drift_accumulator_consumption"] = max(0.0, current_drift - hardware_delta)
                _LOGGER.info("[CT TRUE-UP] Hardware caught up by %.3f kWh. Reduced software drift from %.3f to %.3f", hardware_delta, current_drift, existing["drift_accumulator_consumption"])

        # Apply consumption = Baseline Hardware + Software Drift
        base_consumption = existing.get("consumption1", 0) + existing.get("consumption2", 0)
        existing["consumption"] = base_consumption + existing.get("drift_accumulator_consumption", 0.0)
        
        # IMPORT TRUE-UP
        if "energyImport" in raw or "energyImport2" in raw:
            ct_id = existing.get("id", "?")
            cached_i1, cached_i2 = existing.get("import1", 0), existing.get("import2", 0)
            old_base_imp = cached_i1 + cached_i2
            
            if "energyImport" in raw:
                new_i1 = float(raw["energyImport"]) if raw["energyImport"] is not None else cached_i1
                existing["import1"] = self._guard_energy_counter("ct:" + ct_id + ":ei1", new_i1, cached_i1) if use_ct_guard else new_i1
            if "energyImport2" in raw:
                new_i2 = float(raw["energyImport2"]) if raw["energyImport2"] is not None else cached_i2
                existing["import2"] = self._guard_energy_counter("ct:" + ct_id + ":ei2", new_i2, cached_i2) if use_ct_guard else new_i2
            
            new_base_imp = existing.get("import1", 0) + existing.get("import2", 0)
            
            # Smooth True-Up: Deduct the exact hardware catch-up amount
            if new_base_imp > old_base_imp:
                hardware_delta = new_base_imp - old_base_imp
                current_drift = existing.get("drift_accumulator_import", 0.0)
                existing["drift_accumulator_import"] = max(0.0, current_drift - hardware_delta)
                _LOGGER.info("[CT IMPORT TRUE-UP] Hardware caught up by %.3f kWh. Reduced software drift from %.3f to %.3f", hardware_delta, current_drift, existing["drift_accumulator_import"])
            
        # Apply import = Baseline Hardware + Software Drift
        base_import = existing.get("import1", 0) + existing.get("import2", 0)
        existing["import"] = base_import + existing.get("drift_accumulator_import", 0.0)
        
        if "rmsCurrent" in raw or "rmsCurrent2" in raw:
            cached_cur1, cached_cur2 = existing.get("current1", 0), existing.get("current2", 0)
            if "rmsCurrent" in raw: existing["current1"] = float(raw["rmsCurrent"]) if raw["rmsCurrent"] is not None else cached_cur1
            if "rmsCurrent2" in raw: existing["current2"] = float(raw["rmsCurrent2"]) if raw["rmsCurrent2"] is not None else cached_cur2
            existing["current"] = (existing["current1"] + existing["current2"]) / 2

    def _recalc_total_power(self, status_data: dict, panel_id: str) -> None:
        breakers = status_data.get("breakers", {})
        total = 0.0
        for b_data in breakers.values():
            if b_data.get("panel_id") == panel_id:
                try:
                    p = b_data.get("power")
                    if p is not None: total += float(p)
                except (ValueError, TypeError): pass
        status_data[panel_id + "totalPower"] = total

    def _update_from_websocket(self, payload):
        """Process a WebSocket notification and merge into status_data.

        Handles three model types: ResidentialBreaker (single breaker update),
        IotCt (single CT update), and IotWhem (bulk panel update that may
        contain embedded breaker and CT arrays).
        """
        if not self.status_data: return None

        model_name = payload.get("modelName")
        data = payload.get("data")
        if not data: return None

        try:
            log_id = data.get("id") or payload.get("modelId", "")
            log_keys = [k for k in data.keys() if k not in ("id", "modelId", "class", "ResidentialBreaker", "IotCt")]
            if log_keys:
                _LOGGER.debug("[v%s] WS %s %s: %s", self.version, model_name, log_id, ", ".join(log_keys))
            if "ResidentialBreaker" in data:
                _LOGGER.debug("[v%s] WS %s %s: ResidentialBreaker", self.version, model_name, log_id)
            if "IotCt" in data:
                _LOGGER.debug("[v%s] WS %s %s: IotCt", self.version, model_name, log_id)
        except Exception:
            pass

        new_status_data = self.status_data.copy()
        updated = False

        if model_name == "ResidentialBreaker":
             breaker_id = data.get("id") or payload.get("modelId")
             if breaker_id and breaker_id in new_status_data["breakers"]:
                  breakers = new_status_data["breakers"].copy()
                  breaker = breakers[breaker_id].copy()
                  
                  panel_id = breaker.get("panel_id")

                  power_changed = self._apply_breaker_update(breaker_id, breaker, data, source="WS")
                  breakers[breaker_id] = breaker
                  new_status_data["breakers"] = breakers
                  if power_changed:
                      if panel_id: self._recalc_total_power(new_status_data, panel_id)
                  updated = True

        elif model_name == "IotCt":
             ct_id = str(data.get("id") or payload.get("modelId", ""))
             if ct_id and ct_id in new_status_data["cts"]:
                  cts = new_status_data["cts"].copy()
                  ct = cts[ct_id].copy()
                  self._apply_ct_update(ct, data)
                  cts[ct_id] = ct
                  new_status_data["cts"] = cts
                  updated = True
                  
        elif model_name == "IotWhem":
             panel_id = data.get("id")
             has_breaker_data = "ResidentialBreaker" in data
             has_electrical_data = False
             if has_breaker_data:
                 for b_check in data["ResidentialBreaker"]:
                     if any(k in b_check for k in ("power", "power2", "rmsCurrent", "rmsCurrent2", "rmsVoltage", "rmsVoltage2")):
                         has_electrical_data = True
                         break
             
             if panel_id and panel_id in self._ws_iotwhem_count:
                 if has_electrical_data:
                     self._ws_last_breaker_data_time[panel_id] = time.time()
                     self._ws_iotwhem_count[panel_id] = 0
                 else:
                     self._ws_iotwhem_count[panel_id] = self._ws_iotwhem_count.get(panel_id, 0) + 1
             
             if has_breaker_data:
                  breakers = new_status_data["breakers"].copy()
                  panels_with_power_change = set()
                  for b_data in data["ResidentialBreaker"]:
                       b_id = b_data.get("id")
                       if b_id and b_id in breakers:
                            breaker = breakers[b_id].copy()
                            power_changed = self._apply_breaker_update(b_id, breaker, b_data, source="WS-bulk")
                            if power_changed: panels_with_power_change.add(breaker.get("panel_id"))
                            breakers[b_id] = breaker
                            updated = True
                  if updated:
                      new_status_data["breakers"] = breakers
                      for pid in panels_with_power_change:
                          if pid: self._recalc_total_power(new_status_data, pid)

             if "IotCt" in data:
                  cts = new_status_data["cts"].copy()
                  for ct_data_item in data["IotCt"]:
                       ct_id = str(ct_data_item.get("id"))
                       if ct_id and ct_id in cts:
                            ct = cts[ct_id].copy()
                            self._apply_ct_update(ct, ct_data_item)
                            cts[ct_id] = ct
                            updated = True
                  if updated: new_status_data["cts"] = cts

             if panel_id and new_status_data.get("panels"):
                  panels = new_status_data["panels"].copy()
                  for i, panel in enumerate(panels):
                       if panel.get("id") == panel_id:
                            panel = panel.copy()
                            if "connected" in data: panel["connected"] = data["connected"]
                            if "rmsVoltage" in data or "rmsVoltage2" in data or "rmsVoltageA" in data or "rmsVoltageB" in data:
                                v1 = data.get("rmsVoltage") or data.get("rmsVoltageA")
                                v2 = data.get("rmsVoltage2") or data.get("rmsVoltageB")
                                if v1 is not None: panel["voltage1"] = float(v1)
                                if v2 is not None: panel["voltage2"] = float(v2)
                                if panel.get("voltage1") is not None and panel.get("voltage2") is not None:
                                    if not self._three_phase:
                                        panel["voltage"] = (panel["voltage1"] + panel["voltage2"]) / 2.0
                                    else:
                                        panel["voltage"] = (panel["voltage1"] * 0.866025403784439) + (panel["voltage2"] * 0.866025403784439)
                            if "frequencyA" in data or "frequencyB" in data:
                                if data.get("frequencyA") is not None: panel["frequency1"] = float(data["frequencyA"])
                                if data.get("frequencyB") is not None: panel["frequency2"] = float(data["frequencyB"])
                                if panel.get("frequency1") is not None and panel.get("frequency2") is not None:
                                    panel["frequency"] = (panel["frequency1"] + panel["frequency2"]) / 2
                            if "overVoltage" in data: panel["overVoltage"] = data["overVoltage"]
                            if "underVoltage" in data: panel["underVoltage"] = data["underVoltage"]
                            if "overVoltageThreshold" in data: panel["overVoltageThreshold"] = data["overVoltageThreshold"]
                            if "underVoltageThreshold" in data: panel["underVoltageThreshold"] = data["underVoltageThreshold"]
                            if "rssi" in data and data["rssi"] is not None:
                                try: panel["rssi"] = float(data["rssi"])
                                except (ValueError, TypeError): pass
                            panels[i] = panel
                            new_status_data["panels"] = panels
                            updated = True
                            break

        if updated:
            self.status_data = new_status_data
            return True
        return None

    @property
    def needs_rest_poll(self) -> bool:
        return any(self._panel_needs_rest_poll.values())

    @property
    def needs_ct_poll(self) -> bool:
        return any(self._panel_needs_ct_poll.values())

    def panel_has_hw_counters(self, panel_id: str) -> bool:
        return self._panel_has_hw_counters.get(panel_id, False)

    async def refresh_breaker_data(self) -> bool:
        if not self.status_data or not self.status_data.get("panels"): return False
        if not self.auth_token: return False
        if not any(self._panel_needs_rest_poll.values()): return False
        
        try:
            async with asyncio.timeout(30):
                await self._rest_poll_lock.acquire()
        except asyncio.TimeoutError:
            return False

        try:
            return await self._refresh_breaker_data_locked()
        finally:
            self._rest_poll_lock.release()

    async def _refresh_breaker_data_locked(self) -> bool:
        new_status_data = self.status_data.copy()
        breakers = new_status_data.get("breakers", {}).copy()
        updated = False
        panels_with_power_change = set()
        
        for panel_data in new_status_data.get("panels", []):
            panel_id = panel_data.get("id")
            
            if not panel_id or not self._panel_needs_rest_poll.get(panel_id, False):
                continue
            
            try:
                raw_breakers = await self.http.get_Whems_breakers(panel_id)
                if raw_breakers:
                    for breaker in raw_breakers:
                        if breaker.get("model") is not None and breaker["model"] not in ("NONE-2", "NONE-1"):
                            b_id = breaker["id"]
                            if b_id in breakers:
                                existing = breakers[b_id].copy()
                                power_changed = self._apply_breaker_update(b_id, existing, breaker, source="REST")
                                if power_changed:
                                    panels_with_power_change.add(existing.get("panel_id"))
                                breakers[b_id] = existing
                                updated = True
                
            except Exception as ex:
                _LOGGER.debug("[v%s] Breaker refresh error for panel %s: %s", self.version, panel_id, ex)
        
        if updated:
            new_status_data["breakers"] = breakers
            for pid in panels_with_power_change:
                if pid:
                    self._recalc_total_power(new_status_data, pid)
            self.status_data = new_status_data
        
        return updated

    async def refresh_panel_data(self) -> bool:
        """Fetch fresh panel-level data (rssi, voltage, frequency, connected)."""
        if not self.status_data or not self.status_data.get("panels"): return False
        if not self.auth_token: return False

        try:
            async with asyncio.timeout(30):
                await self._rest_poll_lock.acquire()
        except asyncio.TimeoutError:
            return False

        try:
            return await self._refresh_panel_data_locked()
        finally:
            self._rest_poll_lock.release()

    async def _refresh_panel_data_locked(self) -> bool:
        new_status_data = self.status_data.copy()
        panels = new_status_data.get("panels", []).copy()
        updated = False

        for i, panel_data in enumerate(panels):
            panel_id = panel_data.get("id")
            panel_type = panel_data.get("panel_type", "WHEMS")
            if not panel_id:
                continue

            try:
                raw = await self.http.get_panel(panel_id, panel_type)
                if not raw:
                    continue

                panel = panel_data.copy()
                
                if "rssi" in raw and raw["rssi"] is not None:
                    try: panel["rssi"] = float(raw["rssi"])
                    except (ValueError, TypeError): pass
                
                v1_key = "rmsVoltage" if "rmsVoltage" in raw else "rmsVoltageA"
                v2_key = "rmsVoltage2" if "rmsVoltage2" in raw else "rmsVoltageB"
                if v1_key in raw and raw[v1_key] is not None:
                    panel["voltage1"] = float(raw[v1_key])
                if v2_key in raw and raw[v2_key] is not None:
                    panel["voltage2"] = float(raw[v2_key])
                if panel.get("voltage1") is not None and panel.get("voltage2") is not None:
                    if not self._three_phase:
                        panel["voltage"] = (panel["voltage1"] + panel["voltage2"]) / 2.0
                    else:
                        panel["voltage"] = (panel["voltage1"] * 0.866025403784439) + (panel["voltage2"] * 0.866025403784439)
                
                if "frequencyA" in raw and raw["frequencyA"] is not None:
                    panel["frequency1"] = float(raw["frequencyA"])
                if "frequencyB" in raw and raw["frequencyB"] is not None:
                    panel["frequency2"] = float(raw["frequencyB"])
                if panel.get("frequency1") is not None and panel.get("frequency2") is not None:
                    panel["frequency"] = (panel["frequency1"] + panel["frequency2"]) / 2.0
                
                if "connected" in raw:
                    panel["connected"] = raw["connected"]
                if "overVoltage" in raw:
                    panel["overVoltage"] = raw["overVoltage"]
                if "underVoltage" in raw:
                    panel["underVoltage"] = raw["underVoltage"]

                panels[i] = panel
                updated = True

            except Exception as ex:
                _LOGGER.debug("[v%s] Panel refresh error for %s: %s", self.version, panel_id, ex)

        if updated:
            new_status_data["panels"] = panels
            self.status_data = new_status_data

        return updated

    async def refresh_ct_data(self) -> bool:
        if not self.status_data or not self.status_data.get("panels"): return False
        if not self.auth_token: return False
        
        try:
            async with asyncio.timeout(30):
                await self._rest_poll_lock.acquire()
        except asyncio.TimeoutError:
            return False

        try:
            return await self._refresh_ct_data_locked()
        finally:
            self._rest_poll_lock.release()

    async def _refresh_ct_data_locked(self) -> bool:
        new_status_data = self.status_data.copy()
        cts = new_status_data.get("cts", {}).copy()
        updated = False
        
        for panel_data in new_status_data.get("panels", []):
            panel_id = panel_data.get("id")
            if not panel_id or not self._panel_needs_ct_poll.get(panel_id, False): continue
            
            try:
                # STARTUP SYNC: Execute the bandwidth toggle exactly once upon HA boot 
                # to fetch the true hardware baseline, then never run it again to save the hardware.
                panel_type = panel_data.get("panel_type", "WHEMS")
                toggle_flag = f"_startup_toggled_{panel_id}"
                
                if not getattr(self, toggle_flag, False):
                    _LOGGER.info("[v%s] Performing one-time startup bandwidth toggle for panel %s to sync hardware CT counters.", self.version, panel_id)
                    await self._bandwidth_toggle(panel_id, panel_type)
                    setattr(self, toggle_flag, True)
                    import asyncio
                    await asyncio.sleep(5)  # Wait for cloud to ingest the fresh panel data
                
                raw_cts = await self.http.get_Whems_CT(panel_id)
                if raw_cts:
                    for ct in raw_cts:
                        if ct.get("usageType") != "NOT_USED":
                            ct_id = str(ct["id"])
                            if ct_id in cts:
                                existing_ct = cts[ct_id].copy()
                                self._apply_ct_update(existing_ct, ct)
                                cts[ct_id] = existing_ct
                                updated = True
            except Exception as ex:
                _LOGGER.debug("[v%s] CT refresh error for panel %s: %s", self.version, panel_id, ex)
        
        if updated:
            new_status_data["cts"] = cts
            self.status_data = new_status_data
        return updated