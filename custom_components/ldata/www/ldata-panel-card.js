/**
 * LDATA Panel Card
 *
 * Renders a Leviton LDATA panel as a two-column breaker schedule, similar to
 * the physical panel's own label. Breakers are auto-discovered via HA's
 * device registry (each breaker device is linked to its panel device via
 * `via_device`), so the card only needs the panel's device_id in its config.
 *
 * Usage:
 *   type: custom:ldata-panel-card
 *   device_id: <panel device id>
 *   title: "Main Panel"            # optional, defaults to the device name
 *   show_power: true               # optional, show live Watts/Amps per slot
 *   show_alarms: true              # optional, highlight over/under alarms
 *   toggle: true                   # optional, show an on/off switch on each slot when control is enabled
 *   rotate_180: true               # optional override — by default the card reads the
 *                                  # panel's own reported mounting orientation (Leviton's
 *                                  # API exposes this) and rotates automatically; only set
 *                                  # this if you need to force a specific orientation.
 */

// Matched against entity_id (not unique_id) — some HA frontend versions omit
// unique_id from the lightweight entity-registry list exposed to cards, but
// entity_id is always present. These suffixes mirror each entity's
// name_suffix in the Python integration, slugified (e.g. "Status" -> "_status",
// "Over Current" -> "_over_current"), so they hold as long as the entity_id
// wasn't manually renamed by the user.
const LDATA_SUFFIXES = {
  status: "_status",
  watts: "_watts",
  amps: "_amps",
  overCurrent: "_over_current",
  underVoltage: "_under_voltage",
  blinkLed: "_blink_led",
  cloudConnected: "_cloud_connected",
};

class LdataPanelCard extends HTMLElement {
  setConfig(config) {
    if (!config || !config.device_id) {
      throw new Error("ldata-panel-card: 'device_id' is required (the panel device).");
    }
    this._config = {
      show_power: true,
      show_alarms: true,
      toggle: true,
      // rotate_180 intentionally has no default here — leaving it unset
      // means "auto-detect from the panel's own reported orientation".
      // Set it explicitly (true/false) in YAML to override the detection.
      ...config,
    };
    this._renderSignature = null;
    this._pendingToggle = null;
    if (!this.shadowRoot) {
      this.attachShadow({ mode: "open" });
    }
  }

  static getStubConfig() {
    return { device_id: "" };
  }

  getCardSize() {
    return 6;
  }

  set hass(hass) {
    this._hass = hass;
    this._maybeRender();
  }

  // ── Data discovery ──────────────────────────────────────────────────

  _entityRegistryList(hass) {
    // Modern HA frontend exposes these as plain client-side collections.
    return hass.entities ? Object.values(hass.entities) : [];
  }

  _deviceRegistryList(hass) {
    return hass.devices ? Object.values(hass.devices) : [];
  }

  _entitiesForDevice(hass, deviceId) {
    return this._entityRegistryList(hass).filter((e) => e.device_id === deviceId);
  }

  _pickBySuffix(entities, suffix) {
    // HA appends _2, _3, ... to an entity_id when the "natural" one is
    // already taken (typically by a stale/duplicate device) — match that
    // too, so a collision-suffixed entity_id (e.g. "..._status_2") doesn't
    // silently fall out of the panel with no error.
    const pattern = new RegExp(`${suffix}(_\\d+)?$`);
    return entities.find((e) => pattern.test(e.entity_id)) || null;
  }

  _pickControlSwitch(entities) {
    return (
      entities.find(
        (e) =>
          e.entity_id.startsWith("switch.") &&
          !e.entity_id.endsWith(LDATA_SUFFIXES.blinkLed)
      ) || null
    );
  }

  _detectRotation(hass) {
    // rotate_180 explicitly set in config always wins over auto-detection.
    if (this._config.rotate_180 !== undefined && this._config.rotate_180 !== null) {
      return !!this._config.rotate_180;
    }
    // The panel's own "Cloud Connected" entity carries its reported
    // mounting orientation as an attribute (Leviton's API exposes this
    // directly — see LdataCloudConnectedSensor.extra_state_attributes).
    // It's on the panel device itself, not via_device-linked like breakers.
    const panelEntities = this._entitiesForDevice(hass, this._config.device_id);
    const cloudEnt = this._pickBySuffix(panelEntities, LDATA_SUFFIXES.cloudConnected);
    const cloudState = cloudEnt && hass.states[cloudEnt.entity_id];
    const orientation = cloudState ? Number(cloudState.attributes.orientation) : 0;
    return orientation === 180;
  }

  _collectBreakers(hass) {
    const panelDeviceId = this._config.device_id;
    const allDevices = this._deviceRegistryList(hass);
    const allEntities = this._entityRegistryList(hass);
    const breakerDevices = allDevices.filter((d) => d.via_device_id === panelDeviceId);

    // Self-diagnosis for the empty state — since this card can't easily be
    // tested against a live HA instance during development, surface exactly
    // what it saw so a real failure is debuggable from the UI alone.
    this._diagnostics = {
      hassHasDevices: typeof hass.devices === "object" && hass.devices !== null,
      hassHasEntities: typeof hass.entities === "object" && hass.entities !== null,
      totalDevices: allDevices.length,
      totalEntities: allEntities.length,
      panelDeviceFound: allDevices.some((d) => d.id === panelDeviceId),
      devicesLinkedToAnyPanel: allDevices.filter((d) => !!d.via_device_id).length,
      devicesLinkedToThisPanel: breakerDevices.length,
      entitiesWithUniqueId: allEntities.filter((e) => !!e.unique_id).length,
      statusEntitiesFoundOnThisPanel: breakerDevices.filter((dev) =>
        this._pickBySuffix(this._entitiesForDevice(hass, dev.id), LDATA_SUFFIXES.status)
      ).length,
    };

    const breakers = [];
    for (const dev of breakerDevices) {
      const entities = this._entitiesForDevice(hass, dev.id);
      const statusEnt = this._pickBySuffix(entities, LDATA_SUFFIXES.status);
      if (!statusEnt) continue; // not a breaker device (e.g. a CT) — skip

      const statusState = hass.states[statusEnt.entity_id];
      if (!statusState) continue;

      const position = Number(statusState.attributes.position);
      if (!Number.isFinite(position)) continue;
      const poles = Number(statusState.attributes.poles) || 1;
      // Gen1 breakers can't be reset remotely — only Gen2 hardware supports
      // it. Missing/undefined is treated as "can't", matching the backend's
      // own conservative default (see LDATABinarySensor.extra_state_attributes).
      const canRemoteOn = statusState.attributes.canRemoteOn === true;

      const wattsEnt = this._pickBySuffix(entities, LDATA_SUFFIXES.watts);
      const ampsEnt = this._pickBySuffix(entities, LDATA_SUFFIXES.amps);
      const overCurrentEnt = this._pickBySuffix(entities, LDATA_SUFFIXES.overCurrent);
      const underVoltageEnt = this._pickBySuffix(entities, LDATA_SUFFIXES.underVoltage);
      const switchEnt = this._pickControlSwitch(entities);

      breakers.push({
        deviceId: dev.id,
        position,
        poles,
        canRemoteOn,
        name: dev.name_by_user || dev.name || statusState.attributes.friendly_name || "Breaker",
        rating: statusState.attributes.rating,
        isOn: statusState.state === "on",
        available: statusState.state !== "unavailable",
        statusEntityId: statusEnt.entity_id,
        switchEntityId: switchEnt ? switchEnt.entity_id : null,
        wattsEntityId: wattsEnt ? wattsEnt.entity_id : null,
        ampsEntityId: ampsEnt ? ampsEnt.entity_id : null,
        overCurrentEntityId: overCurrentEnt ? overCurrentEnt.entity_id : null,
        underVoltageEntityId: underVoltageEnt ? underVoltageEnt.entity_id : null,
      });
    }

    // "Dumb" (non-smart) breakers are physically present in the panel but
    // never become HA devices — the backend deliberately excludes them
    // (model NONE-1/NONE-2, no monitoring/control data). Without accounting
    // for them here, their slot would render as a false gap instead of an
    // occupied-but-unmonitored position. The integration exposes them as an
    // attribute on the panel's own Cloud Connected entity (same pattern as
    // orientation/panel_size above).
    const cloudEnt = this._pickBySuffix(this._entitiesForDevice(hass, panelDeviceId), LDATA_SUFFIXES.cloudConnected);
    const cloudState = cloudEnt && hass.states[cloudEnt.entity_id];
    const dumbBreakers = cloudState?.attributes?.dumb_breakers || [];
    const knownPositions = new Set(breakers.map((b) => b.position));
    for (const db of dumbBreakers) {
      const position = Number(db.position);
      if (!Number.isFinite(position) || knownPositions.has(position)) continue;
      knownPositions.add(position);
      breakers.push({
        deviceId: null,
        position,
        poles: Number(db.poles) || 1,
        canRemoteOn: false,
        name: db.name || "Unmonitored Breaker",
        rating: null,
        isOn: null,
        available: false,
        isPlaceholder: true,
        statusEntityId: null,
        switchEntityId: null,
        wattsEntityId: null,
        ampsEntityId: null,
        overCurrentEntityId: null,
        underVoltageEntityId: null,
      });
    }

    // Truly open slots — no breaker record at all, not even a "dumb" one —
    // still need a grid row, or the CSS grid (which places every slot at an
    // explicit row/column, not auto-flow) simply skips that row number
    // entirely, compressing the layout out of physical alignment with the
    // real panel. Fill every position up to the panel's reported size (WHEMS
    // panels only) — or, lacking that, up to the highest known position
    // rounded up to a full row pair — with an inert spacer tile. A 2-pole
    // breaker's second (implied) slot is never reported separately by the
    // API, so it must be marked occupied here too, not just its own position.
    const occupied = new Set();
    for (const b of breakers) {
      occupied.add(b.position);
      if (b.poles === 2) occupied.add(b.position + 2);
    }
    const reportedSize = Number(cloudState?.attributes?.panel_size);
    const highestKnown = Math.max(0, ...occupied);
    const slotCount =
      Number.isFinite(reportedSize) && reportedSize > 0 ? reportedSize : highestKnown + (highestKnown % 2);
    for (let position = 1; position <= slotCount; position++) {
      if (occupied.has(position)) continue;
      breakers.push({
        deviceId: null,
        position,
        poles: 1,
        canRemoteOn: false,
        name: "",
        rating: null,
        isOn: null,
        available: false,
        isEmpty: true,
        statusEntityId: null,
        switchEntityId: null,
        wattsEntityId: null,
        ampsEntityId: null,
        overCurrentEntityId: null,
        underVoltageEntityId: null,
      });
    }

    breakers.sort((a, b) => a.position - b.position);
    return breakers;
  }

  // ── Layout ───────────────────────────────────────────────────────────

  _computeLayout(breakers, rotate) {
    // Explicit row/column placement (not CSS auto-flow) so rotate_180 can
    // deterministically flip both axes. Physical column is strictly odd
    // position = left, even position = right (confirmed against the real
    // panel) — independent of the backend's "leg" field, which groups
    // slots electrically for power/voltage math, not by physical column.
    //
    // Row is derived directly from the position number, NOT from an
    // independent per-column running counter — two counters that just pack
    // each column's breakers sequentially can drift out of sync whenever
    // the mix of 1-pole/2-pole breakers differs between columns, leaving
    // physically-adjacent slots (e.g. 9 and 10) on different visual rows
    // with the card's background showing through the mismatch. Deriving
    // row straight from position (1→row1, 3→row2, 5→row3... on the left;
    // 2→row1, 4→row2, 6→row3... on the right) keeps both columns
    // physically aligned regardless of gaps (unpopulated slots) or pole
    // mix — a 2-pole breaker's rowSpan of 2 then lines up exactly with
    // where its second slot (position+2) would fall on its own.
    const placed = [];
    for (const b of breakers) {
      const column = b.position % 2 === 1 ? 1 : 2;
      const rowSpan = b.poles === 2 ? 2 : 1;
      const row = column === 1 ? (b.position + 1) / 2 : b.position / 2;
      placed.push({ breaker: b, column, row, rowSpan });
    }

    if (rotate) {
      // Flip each column's rows within its own extent — using one shared
      // maxRow across both columns would push a shorter column's flipped
      // rows down by however much longer the other column is, leaving a
      // gap at the top instead of starting from row 1.
      const maxRowByColumn = {
        1: Math.max(1, ...placed.filter((p) => p.column === 1).map((p) => p.row + p.rowSpan - 1)),
        2: Math.max(1, ...placed.filter((p) => p.column === 2).map((p) => p.row + p.rowSpan - 1)),
      };
      for (const p of placed) {
        const maxRow = maxRowByColumn[p.column];
        p.row = maxRow - (p.row + p.rowSpan - 1) + 1;
        p.column = p.column === 1 ? 2 : 1;
      }
    }

    return placed;
  }

  // ── Change detection (avoid re-rendering the DOM every hass tick) ──

  _computeSignature(hass, breakers) {
    const parts = [this._config.device_id, this._detectRotation(hass)];
    for (const b of breakers) {
      parts.push(b.deviceId, b.position, b.poles, b.isOn, b.available);
      for (const id of [b.wattsEntityId, b.ampsEntityId, b.overCurrentEntityId, b.underVoltageEntityId]) {
        if (id && hass.states[id]) parts.push(id, hass.states[id].state);
      }
    }
    return parts.join("|");
  }

  _maybeRender() {
    if (!this._hass || !this._config) return;
    const breakers = this._collectBreakers(this._hass);
    const signature = this._computeSignature(this._hass, breakers);
    if (signature === this._renderSignature) return;
    this._renderSignature = signature;
    this._render(breakers);
  }

  // ── Rendering ────────────────────────────────────────────────────────

  _fmt(hass, entityId, decimals) {
    const state = entityId && hass.states[entityId];
    if (!state || state.state === "unavailable" || state.state === "unknown") return null;
    const num = Number(state.state);
    if (!Number.isFinite(num)) return null;
    return decimals === undefined ? num.toString() : num.toFixed(decimals);
  }

  _slotHtml(hass, placement) {
    const { breaker, column, row, rowSpan } = placement;

    const gridRow = rowSpan > 1 ? `${row} / span ${rowSpan}` : String(row);
    const tallClass = rowSpan > 1 ? " ldata-slot--tall" : "";
    // The status indicator and position badge hug the outer edge of each
    // column — left column badges sit on the left, right column on the
    // right — rather than always defaulting to one side.
    const sideClass = column === 1 ? " ldata-slot--left" : " ldata-slot--right";

    if (breaker.isEmpty) {
      // A genuinely open/unused slot — no breaker record at all, not even a
      // "dumb" one. Rendered as a bare, non-interactive filler purely to
      // hold its row's spacing; no name/state/click target makes sense here.
      return `
        <div class="ldata-slot ldata-slot--empty${tallClass}${sideClass}"
             style="grid-column: ${column}; grid-row: ${gridRow};" aria-hidden="true">
          <div class="ldata-slot-position">${breaker.position}</div>
        </div>
      `;
    }

    const showPower = this._config.show_power;
    const showAlarms = this._config.show_alarms;

    const overCurrent =
      showAlarms && breaker.overCurrentEntityId && hass.states[breaker.overCurrentEntityId]?.state === "on";
    const underVoltage =
      showAlarms && breaker.underVoltageEntityId && hass.states[breaker.underVoltageEntityId]?.state === "on";
    const alarm = overCurrent || underVoltage;

    const watts = showPower ? this._fmt(hass, breaker.wattsEntityId, 0) : null;
    const amps = showPower ? this._fmt(hass, breaker.ampsEntityId, 1) : null;

    // "Dumb" breakers get their own fill (distinct from both a normal
    // unavailable/off breaker and a truly empty spacer slot)
    const stateClass = breaker.isPlaceholder
      ? "ldata-slot--dumb"
      : !breaker.available
      ? "ldata-slot--unavailable"
      : breaker.isOn
      ? "ldata-slot--on"
      : "ldata-slot--off";
    const alarmClass = alarm ? " ldata-slot--alarm" : "";

    // A 2-pole breaker spans two rows in one column; since positions step by
    // 2 within a column (confirmed: odd column = 1,3,5,..., even column =
    // 2,4,6,...), its second slot is position+2. Assumes the API reports the
    // upper (lower-numbered) slot — flag it if a real panel shows otherwise.
    const positionLabel = rowSpan > 1 ? `${breaker.position}/${breaker.position + 2}` : String(breaker.position);

    // A live on/off switch when control is enabled and this breaker has one;
    // otherwise fall back to the passive status dot (sensor-only breakers,
    // or `toggle: false` in the card config).
    const canToggle = this._config.toggle && !!breaker.switchEntityId;
    const controlHtml = canToggle
      ? `<button type="button" class="ldata-slot-toggle${breaker.isOn ? " is-on" : ""}"
                 data-toggle-entity="${this._escapeAttr(breaker.switchEntityId)}"
                 data-toggle-name="${this._escapeAttr(breaker.name)}"
                 data-toggle-can-remote-on="${breaker.canRemoteOn}"
                 role="switch" aria-checked="${breaker.isOn}"
                 aria-label="Toggle ${this._escapeAttr(breaker.name)}"
                 ${!breaker.available ? "disabled" : ""}>
           <span class="ldata-slot-toggle-thumb"></span>
         </button>`
      : `<div class="ldata-slot-indicator" aria-hidden="true"></div>`;

    return `
      <div class="ldata-slot ${stateClass}${alarmClass}${tallClass}${sideClass}"
           style="grid-column: ${column}; grid-row: ${gridRow};"
           ${breaker.deviceId ? `data-breaker-device="${breaker.deviceId}"` : ""}
           role="button" tabindex="0"
           title="${this._escapeAttr(breaker.name)}${breaker.rating ? ` — ${breaker.rating}A` : ""}">
        <div class="ldata-slot-position">${positionLabel}</div>
        <div class="ldata-slot-body">
          <div class="ldata-slot-name">${this._escape(breaker.name)}</div>
          <div class="ldata-slot-meta">
            ${breaker.rating ? `<span class="ldata-slot-rating">${breaker.rating}A</span>` : ""}
            ${watts !== null ? `<span class="ldata-slot-reading">${watts} W</span>` : ""}
            ${amps !== null ? `<span class="ldata-slot-reading">${amps} A</span>` : ""}
            ${breaker.isPlaceholder ? `<span class="ldata-slot-reading">Not monitored</span>` : ""}
          </div>
        </div>
        ${controlHtml}
      </div>
    `;
  }

  _escape(str) {
    // Safe for HTML text-node content. NOT safe inside an attribute value —
    // the textContent/innerHTML round-trip does not escape quote characters
    // (quotes are only meaningful in attribute syntax, not text nodes), so
    // an unescaped `"` here could still break out of e.g. title="...".
    const div = document.createElement("div");
    div.textContent = str == null ? "" : String(str);
    return div.innerHTML;
  }

  _escapeAttr(str) {
    // Safe for use inside a double- or single-quoted HTML attribute value.
    return this._escape(str).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  _diagnosticsHtml() {
    const d = this._diagnostics || {};
    const line = (label, ok, detail) =>
      `<div class="ldata-diag-line ${ok ? "ldata-diag-ok" : "ldata-diag-bad"}">${ok ? "✓" : "✗"} ${this._escape(
        label
      )}${detail !== undefined ? `: ${this._escape(detail)}` : ""}</div>`;

    return `
      <div class="ldata-diag-title">Diagnostics</div>
      ${line("hass.devices available", d.hassHasDevices)}
      ${line("hass.entities available", d.hassHasEntities)}
      ${line("Configured device_id", !!this._config.device_id, this._config.device_id || "(not set)")}
      ${line("Panel device found in registry", d.panelDeviceFound)}
      ${line("Total devices seen", d.totalDevices > 0, d.totalDevices)}
      ${line("Devices linked to any panel (via_device)", d.devicesLinkedToAnyPanel > 0, d.devicesLinkedToAnyPanel)}
      ${line("Devices linked to THIS panel", d.devicesLinkedToThisPanel > 0, d.devicesLinkedToThisPanel)}
      ${line("Entities with a unique_id field", d.entitiesWithUniqueId > 0, `${d.entitiesWithUniqueId} / ${d.totalEntities}`)}
      ${line("Status entities found among linked breakers", d.statusEntitiesFoundOnThisPanel > 0, `${d.statusEntitiesFoundOnThisPanel} / ${d.devicesLinkedToThisPanel}`)}
      <div class="ldata-diag-hint">
        If "hass.devices available" is ✗, this HA frontend version doesn't expose the device
        registry the way this card expects — that's a card bug, not a config problem, please
        report it. If it's ✓ but "Devices linked to any panel" is 0, the integration hasn't
        registered the panel↔breaker link yet — make sure custom_components/ldata is fully
        updated and Home Assistant has been restarted (not just reloaded) since. If "Panel
        device found" is ✗, double-check the device_id is copied from the panel's own device
        page, not a breaker's.
      </div>
    `;
  }

  _render(breakers) {
    const hass = this._hass;
    const panelDevice = hass.devices ? hass.devices[this._config.device_id] : null;
    const title =
      this._config.title || (panelDevice && (panelDevice.name_by_user || panelDevice.name)) || "Panel";

    const rotate = this._detectRotation(hass);
    const layout = this._computeLayout(breakers, rotate);
    const slotsHtml = layout.map((placement) => this._slotHtml(hass, placement)).join("");
    const empty = breakers.length === 0;

    this.shadowRoot.innerHTML = `
      <style>${this._css()}</style>
      <ha-card>
        <div class="ldata-header">
          <div class="ldata-title">${this._escape(title)}</div>
        </div>
        ${
          empty
            ? `<div class="ldata-empty">
                 No breakers found for this panel.
                 <div class="ldata-diagnostics">${this._diagnosticsHtml()}</div>
               </div>`
            : `<div class="ldata-grid">${slotsHtml}</div>`
        }
      </ha-card>
      <div class="ldata-confirm-overlay" tabindex="-1">
        <div class="ldata-confirm-box" role="alertdialog" aria-modal="true">
          <div class="ldata-confirm-title"></div>
          <div class="ldata-confirm-actions">
            <button type="button" class="ldata-confirm-cancel">Cancel</button>
            <button type="button" class="ldata-confirm-confirm">Confirm</button>
          </div>
        </div>
      </div>
    `;

    this.shadowRoot.querySelectorAll(".ldata-slot").forEach((el) => {
      el.addEventListener("click", () => this._onSlotClick(el));
      el.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          this._onSlotClick(el);
        }
      });
    });

    // The toggle is a control nested inside the slot's own click/keydown
    // target — stop it from bubbling so pressing it doesn't also navigate.
    this.shadowRoot.querySelectorAll(".ldata-slot-toggle").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        this._requestToggle({
          entityId: btn.getAttribute("data-toggle-entity"),
          name: btn.getAttribute("data-toggle-name"),
          isOn: btn.classList.contains("is-on"),
          canRemoteOn: btn.getAttribute("data-toggle-can-remote-on") === "true",
        });
      });
      btn.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") ev.stopPropagation();
      });
    });

    const overlay = this.shadowRoot.querySelector(".ldata-confirm-overlay");
    if (overlay) {
      overlay.addEventListener("click", (ev) => {
        if (ev.target === overlay) this._closeConfirm();
      });
      overlay.addEventListener("keydown", (ev) => {
        if (ev.key === "Escape") this._closeConfirm();
      });
      overlay.querySelector(".ldata-confirm-cancel")?.addEventListener("click", () => this._closeConfirm());
      overlay.querySelector(".ldata-confirm-confirm")?.addEventListener("click", () => this._confirmToggle());
    }
    // A re-render (e.g. from an unrelated wattage tick elsewhere on the
    // panel) rebuilds this markup from scratch — reapply any dialog that
    // was already open so it doesn't silently vanish mid-decision.
    this._syncConfirmDialog();
  }

  _onSlotClick(el) {
    // Navigate to the breaker's own device page rather than toggling —
    // the on/off switch on the slot handles control now.
    const deviceId = el.getAttribute("data-breaker-device");
    if (!deviceId) return;
    history.pushState(null, "", `/config/devices/device/${deviceId}`);
    window.dispatchEvent(new CustomEvent("location-changed"));
  }

  _requestToggle(toggle) {
    if (!toggle.entityId) return;
    // Gen1 breakers can be tripped remotely but can't be reset remotely —
    // calling the service to turn one back on would silently do nothing,
    // so that case gets an informational dialog instead of an action.
    toggle.blocked = !toggle.isOn && !toggle.canRemoteOn;
    this._pendingToggle = toggle;
    this._syncConfirmDialog();
  }

  _closeConfirm() {
    this._pendingToggle = null;
    this._syncConfirmDialog();
  }

  _confirmToggle() {
    const toggle = this._pendingToggle;
    this._pendingToggle = null;
    this._syncConfirmDialog();
    if (toggle && !toggle.blocked) {
      this._hass.callService("switch", "toggle", { entity_id: toggle.entityId });
    }
  }

  _syncConfirmDialog() {
    const overlay = this.shadowRoot.querySelector(".ldata-confirm-overlay");
    if (!overlay) return;
    const toggle = this._pendingToggle;
    overlay.classList.toggle("is-open", !!toggle);
    if (!toggle) return;

    const titleEl = overlay.querySelector(".ldata-confirm-title");
    const cancelBtn = overlay.querySelector(".ldata-confirm-cancel");
    const confirmBtn = overlay.querySelector(".ldata-confirm-confirm");
    const action = toggle.isOn ? "off" : "on";
    // Surfaced on every actionable dialog for a Gen1 breaker (not just the
    // blocked "turn on" case) — tripping it off still works remotely, but
    // the user should know upfront that turning it back on will require a
    // manual reset at the panel, before they commit to flipping it off.
    const genNote = !toggle.canRemoteOn
      ? " This is a Gen1 breaker — it can only be turned back on manually at the panel."
      : "";

    if (toggle.blocked) {
      if (titleEl) {
        titleEl.textContent = `"${toggle.name}" is a Gen1 breaker and can't be turned on remotely — reset it manually at the panel.`;
      }
      if (cancelBtn) cancelBtn.style.display = "none";
      if (confirmBtn) confirmBtn.textContent = "Got it";
    } else {
      if (titleEl) titleEl.textContent = `Turn ${action} "${toggle.name}"?${genNote}`;
      if (cancelBtn) cancelBtn.style.display = "";
      if (confirmBtn) confirmBtn.textContent = action === "off" ? "Turn Off" : "Turn On";
    }
    overlay.focus();
  }

  _css() {
    return `
      ha-card {
        padding: 16px;
      }
      .ldata-header {
        display: flex;
        align-items: center;
        margin-bottom: 12px;
      }
      .ldata-title {
        font-size: 1.1em;
        font-weight: 500;
        color: var(--primary-text-color);
      }
      .ldata-empty {
        color: var(--secondary-text-color);
        font-size: 0.95em;
        padding: 8px 0;
      }
      .ldata-diagnostics {
        margin-top: 12px;
        padding: 10px 12px;
        border-radius: var(--ha-card-border-radius, 8px);
        background: var(--secondary-background-color);
        font-size: 0.82em;
      }
      .ldata-diag-title {
        font-weight: 600;
        margin-bottom: 6px;
        color: var(--primary-text-color);
      }
      .ldata-diag-line {
        font-family: var(--code-font-family, monospace);
        padding: 1px 0;
      }
      .ldata-diag-ok {
        color: var(--success-color, #4caf50);
      }
      .ldata-diag-bad {
        color: var(--error-color, #db4437);
      }
      .ldata-diag-hint {
        margin-top: 8px;
        padding-top: 8px;
        border-top: 1px solid var(--divider-color);
        color: var(--secondary-text-color);
        font-size: 0.95em;
        line-height: 1.4;
      }
      .ldata-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        /* A 44px floor (not a bare fixed size) on every row track, so a
           2-pole slot's spanned height is always at least 44 + 8 gap + 44 =
           96px = .ldata-slot--tall's min-height, regardless of what's
           adjacent (fixes 2-pole slots being too short when two of them
           sit side by side, with nothing non-spanning to pin the tracks).
           Must be minmax(44px, auto), not a bare 44px — a bare fixed size
           hard-caps every row at exactly 44px and clips single-pole slots
           whose own content (longer names, wrapped meta) needs more room. */
        grid-auto-rows: minmax(44px, auto);
        gap: 8px;
      }
      .ldata-slot {
        position: relative;
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 8px 10px;
        border-radius: var(--ha-card-border-radius, 8px);
        border: 1px solid var(--divider-color);
        background: var(--card-background-color);
        cursor: pointer;
        transition: background-color 0.15s ease, border-color 0.15s ease;
        min-height: 44px;
        /* Without this, the un-wrapped intrinsic width of a long breaker
           name (.ldata-slot-name has white-space: nowrap so it can
           ellipsis instead of wrap) bubbles up through this flex
           container to size its own grid track — even though
           .ldata-slot-body already has min-width: 0 for its own
           shrinking, that alone doesn't stop THIS element's min-content
           contribution from inflating whichever grid-template-columns
           track happens to hold the longest name, making the two 1fr
           columns visibly different widths instead of equal halves. */
        min-width: 0;
        box-sizing: border-box;
        outline: none;
      }
      .ldata-slot:hover,
      .ldata-slot:focus-visible {
        border-color: var(--primary-color);
      }
      .ldata-slot--empty {
        cursor: default;
        border-style: dashed;
        border-color: var(--divider-color);
        background: transparent;
        opacity: 0.35;
      }
      .ldata-slot--empty:hover {
        border-color: var(--divider-color);
      }
      .ldata-slot--empty .ldata-slot-position {
        background: transparent;
      }
      .ldata-slot--tall {
        flex-direction: column;
        align-items: flex-start;
        justify-content: center;
        min-height: 96px;
      }
      /* flex-direction: column swaps the axes — align-items above now
         controls the HORIZONTAL (cross) axis instead of vertical, and
         flex-start means "size to content" instead of the row-direction
         default of stretching to the container's full width. Without this,
         .ldata-slot-body's min-width: 0 has nothing to shrink FROM (it just
         grows to fit its content, including the nowrap breaker name), so
         long names on 2-pole slots visually overflow past the slot's own
         right edge instead of ellipsis-truncating like 1-pole slots do. */
      .ldata-slot--tall .ldata-slot-body {
        align-self: stretch;
      }
      .ldata-slot--right {
        padding-right: 46px;
      }
      .ldata-slot--right .ldata-slot-position,
      .ldata-slot--right .ldata-slot-indicator,
      .ldata-slot--right .ldata-slot-toggle {
        right: 8px;
      }
      .ldata-slot--left {
        padding-left: 46px;
      }
      .ldata-slot--left .ldata-slot-position,
      .ldata-slot--left .ldata-slot-indicator,
      .ldata-slot--left .ldata-slot-toggle {
        left: 8px;
      }
      .ldata-slot--on {
        background: color-mix(in srgb, var(--success-color, #4caf50) 12%, var(--card-background-color));
      }
      .ldata-slot--off {
        opacity: 0.75;
      }
      .ldata-slot--unavailable {
        opacity: 0.4;
      }
      .ldata-slot--dumb {
        /* Distinct light-grey fill for physically-installed non-smart
           breakers — visible (unlike a true empty spacer's transparent
           dashed outline) but clearly not the green "on" fill of a
           monitored breaker, since there's no state to report either way. */
        background: color-mix(in srgb, var(--disabled-text-color, #9e9e9e) 20%, var(--card-background-color));
        opacity: 0.85;
      }
      .ldata-slot--alarm {
        border-color: var(--error-color, #db4437);
        background: color-mix(in srgb, var(--error-color, #db4437) 16%, var(--card-background-color));
        animation: ldata-alarm-pulse 1.6s ease-in-out infinite;
      }
      @keyframes ldata-alarm-pulse {
        0%, 100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--error-color, #db4437) 45%, transparent); }
        50% { box-shadow: 0 0 0 4px color-mix(in srgb, var(--error-color, #db4437) 0%, transparent); }
      }
      .ldata-slot-position {
        position: absolute;
        bottom: 8px;
        min-width: 20px;
        padding: 2px 6px;
        border-radius: 10px;
        background: var(--secondary-background-color);
        color: var(--secondary-text-color);
        font-size: 0.7em;
        font-weight: 600;
        text-align: center;
        line-height: 1.3;
        box-sizing: border-box;
      }
      .ldata-slot-body {
        flex: 1 1 auto;
        min-width: 0;
      }
      .ldata-slot-name {
        font-size: 0.85em;
        font-weight: 500;
        color: var(--primary-text-color);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .ldata-slot-meta {
        display: flex;
        gap: 6px;
        font-size: 0.72em;
        color: var(--secondary-text-color);
        margin-top: 2px;
      }
      .ldata-slot-indicator {
        position: absolute;
        top: 8px;
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--disabled-text-color);
      }
      .ldata-slot--on .ldata-slot-indicator {
        background: var(--success-color, #4caf50);
      }
      .ldata-slot--alarm .ldata-slot-indicator {
        background: var(--error-color, #db4437);
      }
      .ldata-slot-toggle {
        position: absolute;
        top: 8px;
        width: 26px;
        height: 14px;
        padding: 0;
        border: none;
        border-radius: 7px;
        background: var(--disabled-text-color);
        cursor: pointer;
        outline: none;
        transition: background-color 0.15s ease;
      }
      .ldata-slot-toggle.is-on {
        background: var(--success-color, #4caf50);
      }
      .ldata-slot-toggle:focus-visible {
        box-shadow: 0 0 0 2px var(--primary-color);
      }
      .ldata-slot-toggle:disabled {
        opacity: 0.4;
        cursor: default;
      }
      .ldata-slot-toggle-thumb {
        position: absolute;
        top: 2px;
        left: 2px;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #fff;
        transition: left 0.15s ease;
      }
      .ldata-slot-toggle.is-on .ldata-slot-toggle-thumb {
        left: 14px;
      }
      .ldata-confirm-overlay {
        position: fixed;
        inset: 0;
        display: none;
        align-items: center;
        justify-content: center;
        background: rgba(0, 0, 0, 0.5);
        z-index: 10;
        outline: none;
      }
      .ldata-confirm-overlay.is-open {
        display: flex;
      }
      .ldata-confirm-box {
        background: var(--card-background-color);
        color: var(--primary-text-color);
        border-radius: var(--ha-card-border-radius, 8px);
        padding: 20px;
        max-width: 280px;
        width: 90%;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        box-sizing: border-box;
      }
      .ldata-confirm-title {
        font-size: 0.95em;
        line-height: 1.4;
        margin-bottom: 16px;
      }
      .ldata-confirm-actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
      }
      .ldata-confirm-actions button {
        padding: 8px 14px;
        border-radius: 4px;
        border: none;
        font-size: 0.85em;
        font-weight: 500;
        cursor: pointer;
        background: var(--secondary-background-color);
        color: var(--primary-text-color);
      }
      .ldata-confirm-confirm {
        background: var(--primary-color);
        color: var(--text-primary-color, #fff);
      }
    `;
  }
}

customElements.define("ldata-panel-card", LdataPanelCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: "ldata-panel-card",
  name: "LDATA Panel Card",
  description: "Visual breaker-panel layout for a Leviton LDATA panel.",
});
