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
 *   sub_panels:                    # optional — link a "dumb" breaker that physically feeds
 *                                  # a downstream sub-panel to that sub-panel's own HA device,
 *                                  # so its slot shows the sub-panel's live Watts/Amps and a
 *                                  # distinct color instead of the plain "dumb breaker" fill.
 *                                  # Clicking it opens a live nested instance of THIS card for
 *                                  # the sub-panel's own device_id in a modal — no separate
 *                                  # dashboard needed, just the config below. There is no such
 *                                  # link in Leviton's API — it must be configured by hand,
 *                                  # matched by the dumb breaker's panel position (the number
 *                                  # printed on the panel schedule).
 *     - breaker_position: 9
 *       panel_device_id: <sub-panel's own device id>
 *       rating: 50                       # optional — this breaker's own max amp rating (Leviton
 *                                         # never reports one for a dumb breaker), shown the same
 *                                         # way as a smart breaker's, before Watts/Amps.
 *       view_path: /lovelace-casita/0    # optional override — jump to this dashboard view
 *                                         # instead of the nested-card modal. Only useful if
 *                                         # you'd rather leave this card entirely; HA has no
 *                                         # registry mapping a device id to "the view showing
 *                                         # its card", so this can't be auto-derived — it only
 *                                         # takes effect once you set it explicitly.
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

// One RegExp per suffix, built once and reused — _pickBySuffix runs many
// times per breaker per hass tick, and the suffix set above is fixed, so
// there's nothing to gain from re-compiling the same pattern every call.
const LDATA_SUFFIX_PATTERNS = new Map();
function suffixPattern(suffix) {
  let pattern = LDATA_SUFFIX_PATTERNS.get(suffix);
  if (!pattern) {
    pattern = new RegExp(`${suffix}(_\\d+)?$`);
    LDATA_SUFFIX_PATTERNS.set(suffix, pattern);
  }
  return pattern;
}

// Shared shape for a slot with no real HA device behind it (a "dumb"
// breaker or a truly open slot) — neither ever has its own entities, so
// these fields are always this same handful of nulls/defaults regardless
// of which of the two categories the slot belongs to.
const NON_SMART_BREAKER_DEFAULTS = {
  deviceId: null,
  canRemoteOn: false,
  isOn: null,
  available: false,
  switchEntityId: null,
  overCurrentEntityId: null,
  underVoltageEntityId: null,
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
      sub_panels: [],
      // rotate_180 intentionally has no default here — leaving it unset
      // means "auto-detect from the panel's own reported orientation".
      // Set it explicitly (true/false) in YAML to override the detection.
      ...config,
    };
    this._renderSignature = null;
    this._pendingToggle = null;
    this._pendingSubPanelView = null;
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
    // The nested sub-panel card (if its modal is open) has its own live
    // entities that _computeSignature never tracks (it only tracks the
    // linked panel's Watts/Amps total, not every entity on it), so it
    // needs feeding directly — _render() already does this on a full
    // rebuild via _syncSubPanelOverlay(), this covers the no-rebuild case.
    if (this._pendingSubPanelView) {
      const nested = this.shadowRoot?.querySelector(".ldata-subpanel-overlay-body ldata-panel-card");
      if (nested) nested.hass = hass;
    }
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

  _indexEntitiesByDevice(hass) {
    // One pass over the whole entity registry instead of the N separate
    // O(all entities) scans _entitiesForDevice() would otherwise do — one
    // per breaker device, every hass tick.
    const index = new Map();
    for (const entity of this._entityRegistryList(hass)) {
      const list = index.get(entity.device_id);
      if (list) list.push(entity);
      else index.set(entity.device_id, [entity]);
    }
    return index;
  }

  _pickBySuffix(entities, suffix) {
    // HA appends _2, _3, ... to an entity_id when the "natural" one is
    // already taken (typically by a stale/duplicate device) — match that
    // too, so a collision-suffixed entity_id (e.g. "..._status_2") doesn't
    // silently fall out of the panel with no error.
    const pattern = suffixPattern(suffix);
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
    const breakerDevices = allDevices.filter((d) => d.via_device_id === panelDeviceId);
    // One indexed pass over the entity registry, reused for every device
    // looked up below (breakers, the panel's own Cloud Connected entity,
    // and any linked sub-panel) instead of each doing its own separate
    // full-registry scan via _entitiesForDevice().
    const entitiesByDevice = this._indexEntitiesByDevice(hass);
    const entitiesFor = (deviceId) => entitiesByDevice.get(deviceId) || [];

    const breakers = [];
    for (const dev of breakerDevices) {
      const entities = entitiesFor(dev.id);
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
    const cloudEnt = this._pickBySuffix(entitiesFor(panelDeviceId), LDATA_SUFFIXES.cloudConnected);
    const cloudState = cloudEnt && hass.states[cloudEnt.entity_id];
    const dumbBreakers = cloudState?.attributes?.dumb_breakers || [];
    const knownPositions = new Set(breakers.map((b) => b.position));
    for (const db of dumbBreakers) {
      const position = Number(db.position);
      if (!Number.isFinite(position) || knownPositions.has(position)) continue;
      knownPositions.add(position);

      // A dumb breaker that physically feeds a downstream sub-panel has no
      // such link in Leviton's API — it's a user-authored mapping in the
      // card's own config, matched by panel position. When present, borrow
      // the linked panel device's own Watts/Amps entities (same "_watts"/
      // "_amps" suffix convention used for breakers — the panel's own
      // "both legs" total sensor is the only entity on that device whose
      // entity_id ends bare in that suffix, leg-specific ones end in
      // "_leg_1"/"_leg_2" instead) so this slot shows live sub-panel load.
      const link = (this._config.sub_panels || []).find(
        (sp) => Number(sp.breaker_position) === position
      );
      // Leviton's API never reports a rating for a dumb breaker (it carries
      // no data at all) — same as panel_device_id/view_path, this only
      // exists if the user typed it into the link entry, e.g. because they
      // know it's a 50A double-pole feeding the sub-panel.
      const rating = link && link.rating ? Number(link.rating) || null : null;
      let linkedPanelDeviceId = null;
      let linkedPanelName = null;
      let linkedPanelViewPath = null;
      let wattsEntityId = null;
      let ampsEntityId = null;
      if (link && link.panel_device_id) {
        linkedPanelDeviceId = link.panel_device_id;
        // No API or registry link exists from a device id to "the dashboard
        // view showing that device's card" — a device can appear on any
        // number of dashboards, or none, and that mapping isn't exposed to
        // a Lovelace card. So it's opt-in, same as panel_device_id itself:
        // if the user tells us exactly where that panel's own card lives,
        // clicking jumps straight there instead of the generic device page.
        linkedPanelViewPath = link.view_path || null;
        const linkedDevice = hass.devices ? hass.devices[linkedPanelDeviceId] : null;
        linkedPanelName = (linkedDevice && (linkedDevice.name_by_user || linkedDevice.name)) || null;
        const linkedEntities = entitiesFor(linkedPanelDeviceId);
        const wattsEnt = this._pickBySuffix(linkedEntities, LDATA_SUFFIXES.watts);
        const ampsEnt = this._pickBySuffix(linkedEntities, LDATA_SUFFIXES.amps);
        wattsEntityId = wattsEnt ? wattsEnt.entity_id : null;
        ampsEntityId = ampsEnt ? ampsEnt.entity_id : null;
      }

      breakers.push({
        ...NON_SMART_BREAKER_DEFAULTS,
        position,
        poles: Number(db.poles) || 1,
        name: db.name || "Unmonitored Breaker",
        rating,
        isPlaceholder: true,
        linkedPanelDeviceId,
        linkedPanelName,
        linkedPanelViewPath,
        wattsEntityId,
        ampsEntityId,
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
        ...NON_SMART_BREAKER_DEFAULTS,
        position,
        poles: 1,
        name: "",
        rating: null,
        isEmpty: true,
        wattsEntityId: null,
        ampsEntityId: null,
      });
    }

    breakers.sort((a, b) => a.position - b.position);

    // Self-diagnosis for the empty state only — since this card can't
    // easily be tested against a live HA instance during development,
    // surface exactly what it saw so a real failure is debuggable from the
    // UI alone. Computed lazily here (rather than unconditionally above)
    // because _diagnosticsHtml() is the only reader and it only renders
    // when the panel ends up with zero breakers.
    if (breakers.length === 0) {
      const allEntities = this._entityRegistryList(hass);
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
          this._pickBySuffix(entitiesFor(dev.id), LDATA_SUFFIXES.status)
        ).length,
      };
    }

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

  _computeSignature(hass, breakers, rotate) {
    const parts = [this._config.device_id, rotate];
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
    // Computed once per tick and threaded through — _computeSignature and
    // _render each used to call _detectRotation() independently, redoing
    // the same panel-entity lookup twice for one render cycle.
    const rotate = this._detectRotation(this._hass);
    const signature = this._computeSignature(this._hass, breakers, rotate);
    if (signature === this._renderSignature) return;
    this._renderSignature = signature;
    this._render(breakers, rotate);
  }

  // ── Rendering ────────────────────────────────────────────────────────

  _fmt(hass, entityId, decimals) {
    const state = entityId && hass.states[entityId];
    if (!state || state.state === "unavailable" || state.state === "unknown") return null;
    const num = Number(state.state);
    if (!Number.isFinite(num)) return null;
    return decimals === undefined ? num.toString() : num.toFixed(decimals);
  }

  _slotStateClass(breaker) {
    // A dumb breaker linked to a downstream sub-panel (via card config) gets
    // its own fill, distinct from a plain unlinked dumb breaker, a normal
    // unavailable/off breaker, and a truly empty spacer slot — checked
    // before those since isPlaceholder breakers are always available: false
    // but shouldn't look identical to a real breaker that's just temporarily
    // offline, and a linked one shouldn't look like a plain dumb one either.
    if (breaker.linkedPanelDeviceId) return "ldata-slot--subpanel";
    if (breaker.isPlaceholder) return "ldata-slot--dumb";
    if (!breaker.available) return "ldata-slot--unavailable";
    return breaker.isOn ? "ldata-slot--on" : "ldata-slot--off";
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

    const stateClass = this._slotStateClass(breaker);
    const alarmClass = alarm ? " ldata-slot--alarm" : "";
    // Spelled out rather than left to the red fill alone — a breaker can be
    // red for either reason (or, rarely, both at once) and the color by
    // itself doesn't say which. Own line below the name so it never has to
    // compete with the position badge for the meta row's limited width on
    // a 1-pole slot; the grid row (minmax(44px, auto)) just grows to fit it.
    const alarmLabel = overCurrent && underVoltage
      ? "Over Current, Under Voltage"
      : overCurrent
      ? "Over Current"
      : underVoltage
      ? "Under Voltage"
      : null;

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

    // Where clicking this slot (or its sub-panel link) goes. A real breaker
    // always goes to its own device page (data-nav-path). A linked dumb
    // breaker either jumps to an explicitly configured dashboard view
    // (`view_path`, also data-nav-path) if given, or — the default, and the
    // actual point of the link — opens a live nested instance of this same
    // card for the sub-panel's own device_id right in a modal (data-subpanel-
    // device/-name), no separate dashboard required.
    const navPath = breaker.deviceId
      ? `/config/devices/device/${breaker.deviceId}`
      : breaker.linkedPanelDeviceId && breaker.linkedPanelViewPath
      ? breaker.linkedPanelViewPath
      : null;
    const subpanelModalAttrs =
      breaker.linkedPanelDeviceId && !breaker.linkedPanelViewPath
        ? ` data-subpanel-device="${this._escapeAttr(breaker.linkedPanelDeviceId)}" data-subpanel-name="${this._escapeAttr(
            breaker.linkedPanelName || "Sub Panel"
          )}"`
        : "";
    const subpanelDestLabel = breaker.linkedPanelViewPath
      ? `${breaker.linkedPanelName || "sub-panel"}'s dashboard`
      : `${breaker.linkedPanelName || "sub-panel"}'s live panel view`;
    // Hoisted once — the tile itself and the sub-panel link nested inside
    // it both need this exact same pair of attributes, since they're two
    // different click targets pointed at the same destination.
    const navPathAttr = navPath ? `data-nav-path="${this._escapeAttr(navPath)}"` : "";

    return `
      <div class="ldata-slot ${stateClass}${alarmClass}${tallClass}${sideClass}"
           style="grid-column: ${column}; grid-row: ${gridRow};"
           ${navPathAttr}${subpanelModalAttrs}
           role="button" tabindex="0"
           title="${this._escapeAttr(breaker.name)}${breaker.rating ? ` — ${breaker.rating}A` : ""}${
             breaker.linkedPanelDeviceId ? ` — feeds ${this._escapeAttr(breaker.linkedPanelName || "sub-panel")}` : ""
           }${alarmLabel ? ` — ${this._escapeAttr(alarmLabel)}` : ""}">
        <div class="ldata-slot-position">${positionLabel}</div>
        <div class="ldata-slot-body">
          <div class="ldata-slot-name">${this._escape(breaker.name)}</div>
          ${
            breaker.linkedPanelDeviceId
              ? `<a href="#" class="ldata-slot-subpanel-link"
                    ${navPathAttr}${subpanelModalAttrs}
                    title="Open ${this._escapeAttr(subpanelDestLabel)}">↳ ${this._escape(
                  breaker.linkedPanelName || "Sub Panel"
                )}</a>`
              : ""
          }
          ${alarmLabel ? `<div class="ldata-slot-alarm-text">${this._escape(alarmLabel)}</div>` : ""}
          <div class="ldata-slot-meta">
            ${breaker.rating ? `<span class="ldata-slot-rating">${breaker.rating}A</span>` : ""}
            ${amps !== null ? `<span class="ldata-slot-reading">${amps} A</span>` : ""}
            ${watts !== null ? `<span class="ldata-slot-reading">${watts} W</span>` : ""}
            ${breaker.isPlaceholder && !breaker.linkedPanelDeviceId ? `<span class="ldata-slot-reading">Not monitored</span>` : ""}
          </div>
        </div>
        ${controlHtml}
      </div>
    `;
  }

  _escape(str) {
    // Safe for HTML text-node content. NOT safe inside an attribute value —
    // this only escapes the characters meaningful in text-node syntax, not
    // quote characters (quotes are only meaningful in attribute syntax), so
    // an unescaped `"` here could still break out of e.g. title="...".
    // A plain replace chain instead of a throwaway div/textContent/innerHTML
    // round-trip — called many times per slot per render, and every call
    // was allocating and discarding a DOM element just to escape a string.
    if (str == null) return "";
    return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
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

  _render(breakers, rotate) {
    const hass = this._hass;
    const panelDevice = hass.devices ? hass.devices[this._config.device_id] : null;
    const title =
      this._config.title || (panelDevice && (panelDevice.name_by_user || panelDevice.name)) || "Panel";

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
      <div class="ldata-subpanel-overlay" tabindex="-1">
        <div class="ldata-subpanel-overlay-box" role="dialog" aria-modal="true">
          <div class="ldata-subpanel-overlay-header">
            <div class="ldata-subpanel-overlay-title"></div>
            <button type="button" class="ldata-subpanel-overlay-close" aria-label="Close">✕</button>
          </div>
          <div class="ldata-subpanel-overlay-body"></div>
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
    // No manual Enter/Space handling needed beyond that: a <button> already
    // fires its own click on either key natively.
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
      this._stopKeydownPropagationOnActivate(btn);
    });

    // Same nested-control pattern as the toggle above — the link is inside
    // the slot's own click target, so it needs its own handler with
    // propagation stopped so the parent tile's handler doesn't also fire
    // redundantly (they carry the same data-nav-path/data-subpanel-device
    // and would otherwise just perform the same action twice). An <a> also
    // fires its own click on Enter/Space natively, same as the toggle.
    this.shadowRoot.querySelectorAll(".ldata-slot-subpanel-link").forEach((a) => {
      a.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        this._handleSlotAction(a);
      });
      this._stopKeydownPropagationOnActivate(a);
    });

    const overlay = this.shadowRoot.querySelector(".ldata-confirm-overlay");
    if (overlay) {
      this._wireOverlayDismiss(overlay, () => this._closeConfirm());
      overlay.querySelector(".ldata-confirm-cancel")?.addEventListener("click", () => this._closeConfirm());
      overlay.querySelector(".ldata-confirm-confirm")?.addEventListener("click", () => this._confirmToggle());
    }

    const subOverlay = this.shadowRoot.querySelector(".ldata-subpanel-overlay");
    if (subOverlay) {
      this._wireOverlayDismiss(subOverlay, () => this._closeSubPanelView());
      subOverlay.querySelector(".ldata-subpanel-overlay-close")?.addEventListener("click", () => this._closeSubPanelView());
    }
    // A re-render (e.g. from an unrelated wattage tick elsewhere on the
    // panel) rebuilds this markup from scratch — reapply any dialog/modal
    // that was already open so it doesn't silently vanish mid-decision.
    this._syncConfirmDialog();
    this._syncSubPanelOverlay();
  }

  _onSlotClick(el) {
    // Not toggling — the on/off switch on the slot handles control now.
    this._handleSlotAction(el);
  }

  _handleSlotAction(el) {
    // A real breaker (or a sub-panel link with an explicit view_path)
    // carries data-nav-path and just navigates. A sub-panel link without
    // one carries data-subpanel-device/-name instead and opens the inline
    // nested-card modal — the default, no-extra-config experience.
    const navPath = el.getAttribute("data-nav-path");
    if (navPath) {
      this._navigateToPath(navPath);
      return;
    }
    const subDeviceId = el.getAttribute("data-subpanel-device");
    if (subDeviceId) {
      this._openSubPanelView(subDeviceId, el.getAttribute("data-subpanel-name"));
    }
  }

  _navigateToPath(path) {
    if (!path) return;
    history.pushState(null, "", path);
    window.dispatchEvent(new CustomEvent("location-changed"));
  }

  _openSubPanelView(deviceId, name) {
    if (!deviceId) return;
    this._pendingSubPanelView = { deviceId, name };
    this._syncSubPanelOverlay();
  }

  _closeSubPanelView() {
    this._pendingSubPanelView = null;
    this._syncSubPanelOverlay();
  }

  _syncSubPanelOverlay() {
    const overlay = this.shadowRoot.querySelector(".ldata-subpanel-overlay");
    if (!overlay) return;
    const pending = this._pendingSubPanelView;
    overlay.classList.toggle("is-open", !!pending);
    const body = overlay.querySelector(".ldata-subpanel-overlay-body");
    if (!pending) {
      if (body) body.innerHTML = "";
      return;
    }

    const titleEl = overlay.querySelector(".ldata-subpanel-overlay-title");
    if (titleEl) titleEl.textContent = pending.name || "Sub Panel";

    // Rebuilt fresh every time this runs (including on every outer
    // re-render while the modal is open, since _render() just replaced the
    // whole shadow DOM — the overlay markup, this body div included, is
    // regenerated along with everything else, so there's no persistent
    // node to reuse here even in principle without restructuring _render()
    // to stop wholesale-replacing the overlays on every breaker-grid
    // update) — a nested instance of this same card, pointed at the linked
    // panel's own device_id, is a complete, self-contained live view with
    // nothing more to configure than the link already provides.
    if (body) {
      body.innerHTML = "";
      const nested = document.createElement("ldata-panel-card");
      nested.setConfig({ device_id: pending.deviceId, title: pending.name || undefined });
      nested.hass = this._hass;
      body.appendChild(nested);
    }
    overlay.focus();
  }

  _stopKeydownPropagationOnActivate(el) {
    // For a native interactive element (<button>, <a>) nested inside the
    // slot's own click/keydown target — Enter/Space already fires the
    // element's own click natively, so this only needs to stop that keydown
    // from also bubbling up to the parent tile's keydown handler.
    el.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") ev.stopPropagation();
    });
  }

  _wireOverlayDismiss(overlay, closeFn) {
    overlay.addEventListener("click", (ev) => {
      if (ev.target === overlay) closeFn();
    });
    overlay.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") closeFn();
    });
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
      /* Left-column slots mirror their text toward the panel's center —
         name, sub-panel link, and meta row all hug the slot's right edge
         instead of trailing off after the position badge on the left.
         --left/--right are assigned from the already-rotated column in
         _computeLayout (not raw position parity), so this stays correct
         under rotate_180 too — whichever column renders on the left visually
         gets this, regardless of which position numbers land in it. */
      .ldata-slot--left .ldata-slot-body {
        text-align: right;
      }
      .ldata-slot--left .ldata-slot-meta {
        justify-content: flex-end;
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
      .ldata-slot--subpanel {
        /* A dumb breaker linked (via card config) to a downstream sub-panel
           device — its own blue-tinted fill, distinct from both the plain
           grey "dumb" fill and the green "on" fill, so it reads at a glance
           as "feeds another panel" rather than "just unmonitored". */
        background: color-mix(in srgb, var(--primary-color, #03a9f4) 14%, var(--card-background-color));
      }
      .ldata-slot--subpanel .ldata-slot-indicator {
        background: var(--primary-color, #03a9f4);
      }
      .ldata-slot-subpanel-link {
        /* Block, not inline — puts it on its own line between the breaker
           name and the Watts/Amps meta row instead of sharing a flex row
           with them (which used to squeeze "↳ Sub Panel  1842 W  15.4 A"
           onto one line). Underlined so it reads as an actual hyperlink,
           not just colored text. */
        display: block;
        color: var(--primary-color, #03a9f4);
        font-weight: 600;
        font-size: 0.72em;
        text-decoration: underline;
        text-underline-offset: 2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-top: 1px;
      }
      .ldata-slot-subpanel-link:hover,
      .ldata-slot-subpanel-link:focus-visible {
        color: var(--primary-color, #03a9f4);
        opacity: 0.8;
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
      .ldata-slot-alarm-text {
        /* Its own line below the name, not squeezed into the meta row —
           on a 1-pole slot the row just grows to fit it (grid-auto-rows is
           minmax(44px, auto), not a fixed 44px), so this never has to
           compete with the rating/Watts/Amps pills for width. */
        font-size: 0.72em;
        font-weight: 600;
        color: var(--error-color, #db4437);
        margin-top: 2px;
      }
      .ldata-slot-position {
        position: absolute;
        bottom: 8px;
        min-width: 20px;
        padding: 2px 6px;
        border-radius: 10px;
        /* A visible border plus a background pulled toward the text color
           (not just the flat secondary-background-color, which sits too
           close to the card's own background in some themes to read as a
           distinct pill) — a little drop shadow for depth on top of that. */
        border: 1px solid var(--divider-color);
        background: color-mix(in srgb, var(--secondary-text-color) 16%, var(--secondary-background-color));
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.18);
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
        align-items: center;
        gap: 6px;
        font-size: 0.72em;
        color: var(--secondary-text-color);
        margin-top: 2px;
      }
      .ldata-slot-rating {
        /* A fixed spec (the breaker's max amp rating), not a live reading —
           styled as the same kind of pill as .ldata-slot-position (rounded,
           bordered, shaded) instead of plain text, so it doesn't read as
           just another number next to the live Watts/Amps beside it. Same
           border/background/shadow recipe as .ldata-slot-position, kept as
           a second declaration rather than a shared class since one is
           absolutely positioned in the slot's corner and the other sits
           inline in the meta row — only their surface look is shared. */
        display: inline-flex;
        padding: 1px 6px;
        border-radius: 10px;
        border: 1px solid var(--divider-color);
        background: color-mix(in srgb, var(--secondary-text-color) 16%, var(--secondary-background-color));
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.18);
        color: var(--secondary-text-color);
        font-weight: 600;
        line-height: 1.3;
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
      .ldata-subpanel-overlay {
        position: fixed;
        inset: 0;
        display: none;
        align-items: center;
        justify-content: center;
        background: rgba(0, 0, 0, 0.5);
        z-index: 10;
        outline: none;
        padding: 24px;
        box-sizing: border-box;
      }
      .ldata-subpanel-overlay.is-open {
        display: flex;
      }
      .ldata-subpanel-overlay-box {
        background: var(--card-background-color);
        color: var(--primary-text-color);
        border-radius: var(--ha-card-border-radius, 8px);
        max-width: 480px;
        width: 100%;
        max-height: 90vh;
        overflow-y: auto;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        box-sizing: border-box;
      }
      .ldata-subpanel-overlay-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        padding: 10px 8px 10px 16px;
        border-bottom: 1px solid var(--divider-color);
        /* Sticks to the top of the scrollable box so the close button stays
           reachable even when the nested card's own content is taller than
           the modal and the body scrolls. */
        position: sticky;
        top: 0;
        background: var(--card-background-color);
      }
      .ldata-subpanel-overlay-title {
        font-size: 1em;
        font-weight: 600;
      }
      .ldata-subpanel-overlay-close {
        background: none;
        border: none;
        color: var(--secondary-text-color);
        font-size: 1.1em;
        line-height: 1;
        padding: 6px 10px;
        border-radius: 4px;
        cursor: pointer;
      }
      .ldata-subpanel-overlay-close:hover,
      .ldata-subpanel-overlay-close:focus-visible {
        color: var(--primary-text-color);
        background: var(--secondary-background-color);
      }
      .ldata-subpanel-overlay-body {
        padding: 8px;
      }
      .ldata-subpanel-overlay-body ha-card {
        /* Already inside our own modal box's shadow — the nested card's own
           shadow would just double up and look wrong stacked on top of it. */
        box-shadow: none;
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
