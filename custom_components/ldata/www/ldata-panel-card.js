/**
 * LDATA Panel Card
 *
 * Shows a Leviton load center the way it looks on the wall. The panel is not
 * drawn with CSS: it is assembled from ray-traced images of a 3D model that
 * was built from Leviton's own straight-on product photography (the source
 * for those images is in tools/panel_card_art). The cover and door surround
 * stretch to fit, and one image per breaker state is stacked in the breaker's
 * real space, so a 20-space panel and a 66-space panel both come out right.
 *
 * The breakers behave like the hardware (Leviton's handle/LED table):
 *   green window, handle ON ......... on
 *   green window, "OFF" LED lit ..... switched off remotely
 *   white window, handle OFF ........ switched off by hand
 *   red window, handle centred ...... tripped
 *
 *  - Click a breaker's rocker to switch it (asks for confirmation first).
 *  - Click anywhere else on a breaker, or its label, to open its detail sheet
 *    with every control and entity the integration exposes for that breaker.
 *
 * Breakers are auto-discovered via HA's device registry (each breaker device
 * is linked to its panel device via `via_device`), so the card only needs
 * the panel's device_id.
 *
 * Usage:
 *   type: custom:ldata-panel-card
 *   device_id: <panel device id>
 *   title: "Main Panel"        # optional, defaults to the device name
 *   show_power: true           # optional, live Watts/Amps on each circuit label
 *   show_alarms: true          # optional, flag over-current/over-/under-voltage
 *   toggle: true               # optional, the rocker switches the breaker
 *                              # (needs "Allow Breaker Control" in the integration)
 *   confirm: true              # optional, ask before switching a breaker
 *   show_panel_info: true      # optional, the panel's own readings above the door
 *   appearance: auto           # optional, auto | light | dark (dimmed lighting)
 *   main_breaker: 200          # optional, show a main breaker with this rating
 *   rotate_180: true           # optional override — by default the card reads
 *                              # the panel's reported mounting orientation.
 *   sub_panels:                # optional — link a "dumb" breaker that feeds a
 *                              # downstream sub-panel to that panel's device, so
 *                              # its label shows the sub-panel's live load and
 *                              # clicking it opens that panel's own card.
 *     - breaker_position: 9
 *       panel_device_id: <sub-panel's own device id>
 *       rating: 50             # optional — Leviton reports none for dumb breakers
 *       view_path: /lovelace/casita   # optional — navigate here instead of
 *                                     # opening the sub-panel in a dialog
 *
 * This file also defines <ldata-sidebar-panel>, the page the integration can
 * add to Home Assistant's sidebar (its "Show the load center in the sidebar"
 * option): a card for every load center, no dashboard needed.
 *
 * Texts follow the user's language. The translations are the integration's
 * own (translations/<language>.json, under "config_panel").
 */

const CARD_VERSION = "3.1.0";

// ── Artwork ──────────────────────────────────────────────────────────────
// The images sit next to this file in ./img and are produced by
// tools/panel_card_art. ART_REV is the content hash of that folder (written
// by build_assets.py); it is part of every image URL, so browsers fetch new
// artwork after an upgrade instead of serving a cached copy.
const ART_REV = "634f3d87e9";
const ART_SERVED = new URL("/ldata_static/img/", location.href).href; // always served by the integration

// Where this file was loaded from. `import.meta.url` would say, but it is a
// syntax error when the card is registered as a classic script instead of a
// module, which older setups do; the stack names the file either way.
function ownUrl() {
  if (document.currentScript && document.currentScript.src) return document.currentScript.src;
  const found = /(https?:\/\/[^\s()@]+?\.js)(?:\?[^\s()@:]*)?:\d+/.exec(String(new Error().stack || ""));
  return found ? found[1] : null;
}
let artBase = ART_SERVED;
try {
  const own = ownUrl();
  if (own) artBase = new URL("./img/", own).href;
} catch (err) {
  // keep the served path
}
const art = (name) => `${artBase}${name}.webp?v=${ART_REV}`;

// Geometry of the artwork in inches, where one breaker space is 1. These
// mirror geometry.json from tools/panel_card_art; the stylesheet repeats the
// layout numbers it needs, the code below uses the rest to place overlays.
const G = {
  tileW: 3.136, // a breaker tile: the opening plus 0.1 of dead front at each end
  tileM: 0.1,
  slotPad: 0.035,
  strip: 0.85, // dead front between the two columns of tiles
  fieldX: 0.08, // dead front outside the tiles, up to the raised rim
  fieldY: 0.25, // ... and above/below the pieces that close each column
  capH: 0.2,
  frameOut: 0.78, // door surround, from the dead front out to flat cover
  coverEdge: 0.32, // chamfered edge of the cover
  cav: [0.374, 1.441], // the rocker, measured from the logo end of the face
  led: { d: 2.684, x: -0.033 }, // status LED (centre)
  rating: { d: 1.775, x: 0.19, size: 0.106 },
  hero: { w1: 1.14, w2: 2.14, h: 3.796, top: 0.52 }, // upright product shot
  main: { w: 3.6, h: 2.7, scale: 1.25, rating: [1.372, 2.212] }, // main breaker in its opening
};
G.fieldW = 2 * G.tileW + G.strip + 2 * G.fieldX;

const pct = (v) => `${(v * 100).toFixed(2)}%`;

// ── Entity roles ─────────────────────────────────────────────────────────
// Matched against entity_id (not unique_id — some HA frontend versions omit
// unique_id from the lightweight entity registry exposed to cards). Each
// suffix is the slugified name_suffix of the matching Python entity. HA
// appends _2, _3, ... on an entity_id collision, so that tail is accepted.
// Rows are [role, domain, suffix, suffix that must NOT match].
const BREAKER_ROLES = [
  ["status", "binary_sensor", "_status"],
  ["overCurrent", "binary_sensor", "_over_current"],
  ["overVoltage", "binary_sensor", "_over_voltage"],
  ["underVoltage", "binary_sensor", "_under_voltage"],
  ["power", "switch", "_breaker"],
  ["blink", "switch", "_blink_led"],
  ["watts", "sensor", "_watts"],
  ["amps", "sensor", "_amps"],
  ["dailyConsumption", "sensor", "_daily_consumption"],
  ["dailyImport", "sensor", "_daily_import"],
  ["consumption", "sensor", "_consumption", "_daily_consumption"],
  ["import", "sensor", "_import", "_daily_import"],
  ["breakerState", "sensor", "_breaker_state"],
  ["operationalState", "sensor", "_operational_state"],
  ["ble", "sensor", "_ble_signal"],
  ["position", "sensor", "_position"],
];

const PANEL_ROLES = [
  ["cloud", "binary_sensor", "_cloud_connected"],
  ["overVoltage", "binary_sensor", "_over_voltage"],
  ["underVoltage", "binary_sensor", "_under_voltage"],
  ["watts", "sensor", "_watts"],
  ["amps", "sensor", "_amps"],
  ["wattsL1", "sensor", "_watts_leg_1"],
  ["wattsL2", "sensor", "_watts_leg_2"],
  ["ampsL1", "sensor", "_amps_leg_1"],
  ["ampsL2", "sensor", "_amps_leg_2"],
  ["voltsL1", "sensor", "_volts_leg_1"],
  ["voltsL2", "sensor", "_volts_leg_2"],
  ["freqL1", "sensor", "_frequency_leg_1"],
  ["freqL2", "sensor", "_frequency_leg_2"],
  ["dailyConsumption", "sensor", "_daily_consumption"],
  ["dailyImport", "sensor", "_daily_import"],
  ["wifi", "sensor", "_wifi_signal"],
  ["firmware", "update", ""],
];

const CT_ROLES = [
  ["watts", "sensor", "_watts"],
  ["amps", "sensor", "_amps"],
];

const SUFFIX_RE = new Map();
function suffixRe(suffix) {
  let re = SUFFIX_RE.get(suffix);
  if (!re) {
    re = new RegExp(`${suffix}(_\\d+)?$`);
    SUFFIX_RE.set(suffix, re);
  }
  return re;
}

function matchRoles(entityIds, spec) {
  const roles = {};
  const used = new Set();
  for (const [role, domain, suffix, exclude] of spec) {
    const re = suffixRe(suffix);
    const ex = exclude ? suffixRe(exclude) : null;
    const prefix = `${domain}.`;
    for (const id of entityIds) {
      if (used.has(id) || !id.startsWith(prefix) || !re.test(id) || (ex && ex.test(id))) continue;
      roles[role] = id;
      used.add(id);
      break;
    }
  }
  return { roles, used };
}

// Second pass for entities whose entity_id was renamed by the user: pick by
// what the entity *is* (domain + device_class / attributes) instead.
function fallbackRole(match, entityIds, role, test) {
  if (match.roles[role]) return;
  const id = entityIds.find((eid) => !match.used.has(eid) && test(eid));
  if (id) {
    match.roles[role] = id;
    match.used.add(id);
  }
}

// ── Small helpers ────────────────────────────────────────────────────────

const esc = (v) =>
  v == null
    ? ""
    : String(v)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");

const numOrNull = (v) => {
  const n = Number(v);
  return v === null || v === undefined || v === "" || !Number.isFinite(n) ? null : n;
};

// "ManualON" -> "Manual on", "OverCurrent" -> "Over current"
const prettyRaw = (v) => {
  if (v == null || v === "") return "—";
  const s = String(v)
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .toLowerCase();
  return s.charAt(0).toUpperCase() + s.slice(1);
};

// Material Design Icons (Apache 2.0) — inlined so the card has no runtime
// dependency on HA's icon set being loaded.
const ICON = {
  close: "M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z",
  chevron: "M8.59,16.58L13.17,12L8.59,7.41L10,6L16,12L10,18L8.59,16.58Z",
  power:
    "M16.56,5.44L15.11,6.89C16.84,7.94 18,9.83 18,12A6,6 0 0,1 12,18A6,6 0 0,1 6,12C6,9.83 7.16,7.94 8.88,6.88L7.44,5.44C5.36,6.88 4,9.28 4,12A8,8 0 0,0 12,20A8,8 0 0,0 20,12C20,9.28 18.64,6.88 16.56,5.44M13,3H11V13H13",
  open: "M14,3V5H17.59L7.76,14.83L9.17,16.24L19,6.41V10H21V3M19,19H5V5H12V3H5C3.89,3 3,3.9 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V12H19V19Z",
  alert: "M13,14H11V10H13M13,18H11V16H13M1,21H23L12,2L1,21Z",
  info: "M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z",
};
const icon = (name, cls = "ic") =>
  `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${ICON[name]}"/></svg>`;

// Where things sit on a breaker tile, as fractions of the tile's box. A tile
// is the breaker lying on its side with its logo end toward the middle of the
// panel; on a 2-pole unit the rocker is on the lower space in the left column
// and the upper space in the right column, exactly as the hardware mounts.
function tileSpots(side, poles) {
  const left = side === "left";
  const along = (d) => (left ? G.tileW - G.tileM - G.slotPad - d : G.tileM + G.slotPad + d) / G.tileW;
  const pole = poles === 2 ? (left ? 1.5 : 0.5) : 0.5;
  const across = (x) => (pole + (left ? x : -x)) / poles;
  const a0 = along(G.cav[0] - 0.05);
  const a1 = along(G.cav[1] + 0.05);
  return {
    rocker: { left: Math.min(a0, a1), width: Math.abs(a1 - a0), top: (pole - 0.5) / poles, height: 1 / poles },
    led: { left: along(G.led.d), top: across(G.led.x) },
    rating: { x: along(G.rating.d) * G.tileW, y: across(G.rating.x) * poles, turn: left ? 90 : -90 },
  };
}

// Printed amp rating. SVG, so it scales with the artwork instead of being
// clamped by the browser's minimum font size.
function ratingSvg(w, h, x, y, turn, text, size) {
  return `<svg class="ink" viewBox="0 0 ${w * 100} ${h * 100}" preserveAspectRatio="none" aria-hidden="true"><text transform="translate(${(
    x * 100
  ).toFixed(1)} ${(y * 100).toFixed(1)}) rotate(${turn})" text-anchor="middle" dominant-baseline="central" font-size="${(
    size * 100
  ).toFixed(1)}">${esc(text)}</text></svg>`;
}

// ── Language ─────────────────────────────────────────────────────────────
// Every text shown here comes from the integration's own translation files
// (translations/<language>.json, under "config_panel"), fetched for the
// user's language over the websocket. The English strings are repeated below
// so the card reads properly without them: before they arrive, on a lost
// connection, and for any string a language doesn't have.
// tests/test_translations.py keeps this block identical to en.json.
/* i18n:begin */
const EN = {
  "sidebar": {
    "title": "Load Center",
    "empty_title": "No load centers to show",
    "empty_body": "This integration has not found an LDATA or LWHEM panel yet. It may still be starting, or it may be unable to reach Leviton."
  },
  "card": {
    "name": {
      "panel": "Panel",
      "breaker": "Breaker",
      "unmonitored_breaker": "Unmonitored breaker",
      "sub_panel": "Sub-panel"
    },
    "state": {
      "on": "On",
      "off": "Off",
      "off_remote": "Off (remote)",
      "tripped": "Tripped",
      "unavailable": "Unavailable",
      "unknown": "Unknown",
      "switching": "Switching…",
      "switching_on": "Switching on…",
      "switching_off": "Switching off…",
      "not_monitored": "Not monitored",
      "switch_failed": "Couldn't switch"
    },
    "alarm": {
      "over_current": "Over current",
      "over_voltage": "Over voltage",
      "under_voltage": "Under voltage"
    },
    "raw": {
      "manualon": "Manual on",
      "manualoff": "Manual off",
      "remoteon": "Remote on",
      "remoteoff": "Remote off",
      "tripped": "Tripped",
      "softwaretrip": "Software trip",
      "upstreamoff": "Upstream off",
      "notcommunicating": "Not communicating",
      "normal": "Normal"
    },
    "meter": {
      "panel_load": "Panel load",
      "leg_1": "Leg 1",
      "leg_2": "Leg 2",
      "frequency": "Frequency",
      "today": "Today",
      "today_import": "Today import",
      "cloud": "Cloud",
      "wifi": "Wi-Fi",
      "update": "Update",
      "cloud_connected": "Connected to the Leviton cloud",
      "cloud_offline": "Panel offline",
      "cloud_unknown": "Cloud status unknown",
      "wifi_signal": "Wi-Fi signal: {dbm} dBm",
      "wifi_unknown": "Wi-Fi signal unknown",
      "update_available": "Firmware update available (install it in the My Leviton app)",
      "update_current": "Firmware up to date",
      "main": "Main",
      "main_breaker": "Main breaker",
      "main_breaker_dead": "Main breaker (no voltage on either leg)"
    },
    "label": {
      "circuit": "Circuit {position}",
      "circuits": "Circuits {first} and {second}",
      "amp_rating": "{amps} amp",
      "feeds_sub_panel": "Feeds a sub-panel",
      "feeds": "Feeds {name}",
      "show_details": "Show details",
      "open_sub_panel": "Open sub-panel",
      "open_sub_panel_dashboard": "Open sub-panel dashboard",
      "breaker_switch": "{name} breaker"
    },
    "action": {
      "turn_on": "Turn on",
      "turn_off": "Turn off",
      "turn_on_name": "Turn on {name}",
      "turn_off_name": "Turn off {name}",
      "cancel": "Cancel",
      "close": "Close",
      "got_it": "Got it",
      "device_page": "Device page"
    },
    "confirm": {
      "turn_on_title": "Turn on {name}?",
      "turn_off_title": "Turn off {name}?",
      "turn_on_body": "This circuit will be energized.",
      "turn_off_body": "Everything on this circuit will lose power.",
      "gen1_off_warning": "This is a Gen 1 breaker: once it is off, it can only be turned back on by hand at the panel.",
      "blocked_title": "{name} can't be turned on remotely",
      "blocked_body": "This is a Gen 1 smart breaker. It can be switched off from Home Assistant, but it has to be reset by hand at the panel."
    },
    "detail": {
      "both_legs": "Both legs",
      "leg": "Leg {leg}",
      "one_pole": "1-pole",
      "two_pole": "2-pole",
      "controls": "Controls",
      "breaker_power": "Breaker power",
      "power_on_hint": "On: power is flowing",
      "power_tripped_hint": "Tripped: check the circuit before resetting it",
      "power_remote_off_hint": "Switched off remotely",
      "gen1_note": "Gen 1 breaker: it can be switched off remotely but must be reset by hand at the panel.",
      "control_disabled": "Remote control is off. Turn on {option} in the LDATA integration options to switch breakers from Home Assistant.",
      "option_breaker_control": "Allow Breaker Control",
      "identify": "Identify",
      "identify_hint": "Blink this breaker's LED to find it in the panel",
      "blink_led": "Blink LED",
      "identify_disabled": "Turn on {option} in the LDATA integration options to blink a breaker's LED from here.",
      "option_identify": "Allow Identify",
      "live": "Live",
      "power": "Power",
      "current": "Current",
      "load": "Load",
      "energy": "Energy",
      "today": "Today",
      "today_import": "Today, import",
      "lifetime": "Lifetime",
      "lifetime_import": "Lifetime, import",
      "protection": "Protection",
      "operational_state": "Operational state",
      "diagnostics": "Diagnostics",
      "breaker_state": "Breaker state",
      "second_pole": "Second pole",
      "remote_state": "Remote state",
      "previous_state": "Previous state",
      "change_reason": "Last change reason",
      "circuit_type": "Circuit type",
      "critical": "Critical circuit",
      "locked": "Locked",
      "meter_chip": "Metering chip",
      "bluetooth": "Bluetooth signal",
      "device": "Device",
      "model": "Model",
      "rating": "Rating",
      "remote_reset": "Remote reset",
      "firmware": "Firmware",
      "hardware": "Hardware",
      "serial": "Serial number",
      "status": "Status",
      "other_entities": "Other entities",
      "yes": "Yes",
      "no": "No",
      "ok": "OK",
      "fault": "Fault",
      "alarm": "Alarm",
      "not_set": "Not set",
      "remote_reset_yes": "Supported (Gen 2)",
      "remote_reset_no": "Not supported (Gen 1)",
      "standard_breaker": "This is a standard (non-smart) breaker. Leviton reports no state or readings for it, so there is nothing to control or monitor here.",
      "standard_breaker_hint": "If it feeds a sub-panel that has its own LWHEM or LDATA hub, link them with {option} in this card's YAML to show that panel's live load on this breaker."
    },
    "setup": {
      "choose_title": "Choose your panel",
      "choose_body": "Set {option} to your LDATA or LWHEM panel device (Settings → Devices & services → Devices → your panel).",
      "empty_title": "No breakers found for this panel",
      "check_devices": "Device list available to the card",
      "check_entities": "Entity list available to the card",
      "check_device_id": "Configured device ID",
      "check_panel_found": "Panel device found",
      "check_total_devices": "Devices seen",
      "check_linked_any": "Devices linked to any panel",
      "check_linked_this": "Devices linked to this panel",
      "check_breakers": "Breakers with a Status entity",
      "empty_help": "If the panel device is not found, copy the device ID from the panel's own device page, not from a breaker's. If it is found but nothing is linked to it, update the LDATA integration and restart Home Assistant; a reload is not enough."
    }
  },
  "editor": {
    "card_name": "LDATA Panel Card",
    "card_description": "A realistic, interactive view of your Leviton load center.",
    "panel": "Panel",
    "panel_help": "Pick the panel (the LDATA or LWHEM hub), not a breaker. Sub-panel links are set in YAML.",
    "title": "Title (optional)",
    "show_power": "Show live watts and amps",
    "show_alarms": "Flag alarms",
    "toggle": "Switch breakers from the panel",
    "confirm": "Ask before switching",
    "show_panel_info": "Show the panel's readings",
    "appearance": "Lighting",
    "appearance_auto": "Follow theme",
    "appearance_light": "Bright",
    "appearance_dark": "Dimmed",
    "main_breaker": "Main breaker rating (optional)",
    "main_breaker_help": "Leviton doesn't report the main breaker. Leave empty for a main-lug panel."
  }
};
/* i18n:end */

const I18N_PREFIX = "component.ldata.config_panel.";
const I18N_WAIT_MS = 1500; // how long a first paint waits for the user's language
const I18N_RETRY_MS = 30000;

function flattenStrings(node, prefix, out) {
  for (const [key, value] of Object.entries(node)) {
    if (value && typeof value === "object") flattenStrings(value, `${prefix}${key}.`, out);
    else out[`${prefix}${key}`] = value;
  }
  return out;
}
const EN_FLAT = flattenStrings(EN, "", {});

const i18nCache = new Map(); // language -> { lang, strings, done, failed, at, wait }
const i18nWaiters = new Set(); // called whenever a language finishes loading

function hassLanguage(hass) {
  return (hass && (hass.language || (hass.locale && hass.locale.language))) || "en";
}

// The strings for hass's language, requested on first use. One request per
// language however many cards are on the page.
function i18nEntry(hass) {
  const lang = hassLanguage(hass);
  let entry = i18nCache.get(lang);
  if (entry && entry.failed && Date.now() - entry.at > I18N_RETRY_MS) entry = null;
  if (entry) {
    localizePicker(entry);
    return entry;
  }

  // English is built in, so an English user never waits for it.
  entry = { lang, strings: null, done: false, failed: false, at: Date.now(), wait: !/^en(-|$)/i.test(lang) };
  i18nCache.set(lang, entry);
  const finish = (strings) => {
    entry.strings = strings && typeof strings === "object" ? strings : null;
    entry.failed = !entry.strings;
    entry.done = true;
    entry.at = Date.now();
    for (const waiter of [...i18nWaiters]) waiter(entry);
  };
  let request;
  try {
    request = hass.callWS({ type: "frontend/get_translations", language: lang, category: "config_panel", integration: ["ldata"] });
  } catch (err) {
    request = Promise.reject(err);
  }
  Promise.resolve(request).then(
    (result) => finish(result && result.resources),
    () => finish(null)
  );
  return entry;
}

// A lookup for one language: translated string, else English, else the key.
// {placeholders} are filled from vars.
function translator(entry) {
  const strings = entry && entry.strings;
  return (key, vars) => {
    let text = strings ? strings[I18N_PREFIX + key] : undefined;
    if (typeof text !== "string" || !text) text = EN_FLAT[key];
    if (typeof text !== "string") return key;
    return vars ? text.replace(/\{(\w+)\}/g, (whole, name) => (name in vars ? String(vars[name]) : whole)) : text;
  };
}
const englishOnly = translator(null);

// Shared by the card, its editor and the sidebar page: follow hass's language,
// and call `changed` again when its strings arrive.
const LanguageMixin = (Base) =>
  class extends Base {
    // Returns true when the strings in use changed, false when they didn't,
    // and null when nothing has been shown yet and the user's language is
    // still on its way (a short wait beats a flash of English).
    _syncLanguage(hass) {
      const entry = i18nEntry(hass);
      const settled = entry.done || !entry.wait || Date.now() - entry.at >= I18N_WAIT_MS;
      if (!entry.done) this._awaitLanguage(entry);
      if (!settled) return this._langKey ? false : null;
      const key = `${entry.lang}|${entry.strings ? 1 : 0}`;
      if (key === this._langKey) return false;
      this._langKey = key;
      this._t = translator(entry);
      return true;
    }

    _awaitLanguage(entry) {
      if (!this._onLanguage) this._onLanguage = () => this._languageChanged();
      i18nWaiters.add(this._onLanguage);
      const left = I18N_WAIT_MS - (Date.now() - entry.at);
      if (entry.wait && left > 0 && !this._langTimer) {
        this._langTimer = setTimeout(() => {
          this._langTimer = null;
          this._languageChanged();
        }, left + 20);
      }
    }

    _forgetLanguage() {
      if (this._onLanguage) i18nWaiters.delete(this._onLanguage);
      if (this._langTimer) clearTimeout(this._langTimer);
      this._langTimer = null;
    }
  };

// ── The card ─────────────────────────────────────────────────────────────

class LdataPanelCard extends LanguageMixin(HTMLElement) {
  constructor() {
    super();
    this._t = englishOnly;
    this._pending = new Map(); // switch entity_id -> { target, since }
    this._errors = new Map(); // slot position -> { text, until }
    this._fmtCache = new Map();
    this._trackedIds = [];
    this._trackedRefs = [];
    this._timers = new Set();
  }

  static getStubConfig(hass) {
    // Pre-fill the panel when the card is added from the card picker, so the
    // preview shows a real panel instead of an error.
    const ents = hass && hass.entities ? Object.values(hass.entities) : [];
    const cloud = ents.find(
      (e) => e.device_id && e.platform === "ldata" && /^binary_sensor\..+_cloud_connected(_\d+)?$/.test(e.entity_id)
    );
    return { device_id: cloud ? cloud.device_id : "" };
  }

  static getConfigElement() {
    return document.createElement("ldata-panel-card-editor");
  }

  setConfig(config) {
    if (!config || typeof config !== "object") {
      throw new Error("ldata-panel-card: invalid configuration.");
    }
    this._config = {
      show_power: true,
      show_alarms: true,
      toggle: true,
      confirm: true,
      show_panel_info: true,
      appearance: "auto",
      // rotate_180 intentionally has no default — unset means "use the
      // panel's own reported orientation".
      ...config,
      sub_panels: Array.isArray(config.sub_panels) ? config.sub_panels : [],
    };
    this._disc = null;
    this._structKey = null;
    this._trackedIds = [];
    this._trackedRefs = [];
    if (!this.shadowRoot) this._initShadow();
    if (this._hass) this._update(true);
  }

  set hass(hass) {
    this._hass = hass;
    this._update(false);
    // A nested sub-panel card (inside the sub-panel dialog) needs feeding too.
    if (this._subCard) this._subCard.hass = hass;
  }

  get hass() {
    return this._hass;
  }

  connectedCallback() {
    if (!this._ro && window.ResizeObserver) {
      this._ro = new ResizeObserver((entries) => this._onResize(entries[0].contentRect.width));
    }
    if (this._ro) this._ro.observe(this);
  }

  disconnectedCallback() {
    if (this._ro) this._ro.disconnect();
    this._forgetLanguage();
    for (const t of this._timers) clearTimeout(t);
    this._timers.clear();
    for (const dlg of [this._dlgDetail, this._dlgConfirm, this._dlgSub]) {
      if (dlg && dlg.open) dlg.close();
    }
  }

  getCardSize() {
    const rows = this._model ? this._model.rows : 12;
    return Math.max(4, Math.ceil((rows * 34 + 230) / 50));
  }

  // Sections view (HA 2024.11+): take the full section width by default.
  getGridOptions() {
    return { columns: 12, min_columns: 6, rows: "auto" };
  }

  // Sections view, HA 2024.8 – 2024.10 (4-column grid).
  getLayoutOptions() {
    return { grid_columns: 4, grid_min_columns: 2, grid_rows: "auto" };
  }

  // ── Setup ──────────────────────────────────────────────────────────

  _initShadow() {
    const root = this.attachShadow({ mode: "open" });
    root.innerHTML = `
      <style>${CARD_CSS}</style>
      <ha-card><div class="content"></div></ha-card>
      <dialog class="dlg dlg--detail" aria-labelledby="ldp-detail-name"><div class="dlg-in"></div></dialog>
      <dialog class="dlg dlg--confirm" role="alertdialog" aria-labelledby="ldp-cf-title"><div class="dlg-in"></div></dialog>
      <dialog class="dlg dlg--sub" aria-labelledby="ldp-sub-title"><div class="dlg-in"></div></dialog>
    `;
    this._content = root.querySelector(".content");
    this._dlgDetail = root.querySelector(".dlg--detail");
    this._dlgConfirm = root.querySelector(".dlg--confirm");
    this._dlgSub = root.querySelector(".dlg--sub");

    // One delegated listener for everything — the panel DOM is rebuilt when
    // its structure changes, the listener survives that.
    root.addEventListener("click", (ev) => this._onClick(ev));
    root.addEventListener("pointerover", (ev) => this._hot(ev, true));
    root.addEventListener("pointerout", (ev) => this._hot(ev, false));
    // Image errors don't bubble; capture them to fall back to the served path.
    root.addEventListener("error", (ev) => this._onArtError(ev), true);
    this._applyArt();
    this._dlgDetail.addEventListener("close", () => {
      this._detailPos = null;
      this._detailConfirm = false;
      this._detailRows = [];
    });
    this._dlgConfirm.addEventListener("close", () => {
      this._confirm = null;
    });
    this._dlgSub.addEventListener("close", () => {
      const body = this._dlgSub.querySelector(".sub-b");
      if (body) body.innerHTML = "";
      this._subCard = null;
    });
    // The nested sub-panel card asks HA for more-info itself; get our modal
    // out of the way first so HA's dialog isn't stuck underneath it. The
    // event keeps bubbling to HA after this.
    this._dlgSub.addEventListener("hass-more-info", () => {
      if (this._dlgSub.open) this._dlgSub.close();
    });
  }

  _onResize(width) {
    if (!width) return;
    // The artwork is laid out in "breaker spaces": --u is the height of one
    // space in px. The hardware keeps its true proportions; whatever width is
    // left over goes to the circuit labels either side of the door. Narrow
    // cards get a slimmer door surround so the labels keep enough room.
    const dpr = window.devicePixelRatio || 1;
    const t = Math.min(1, Math.max(0, (width - 380) / 260));
    const k = Math.round((0.3 + 0.7 * t) * 100) / 100;
    const edge = G.coverEdge * k + 0.03 + 0.03 * t;
    const share = 0.19 + 0.035 * Math.min(1, Math.max(0, (width - 380) / 100));
    const label = Math.min(176, Math.max(62, width * share));
    const units = G.fieldW + 2 * G.frameOut * k + 2 * edge;
    let u = (width - 6 - 2 * label) / units;
    u = Math.max(18, Math.min(46, u));
    u = Math.floor(u * dpr) / dpr; // whole device pixels, so stacked tiles meet cleanly
    const fs = Math.round(Math.min(14.5, Math.max(10.5, width / 44)) * 4) / 4;
    const key = `${u}|${k}|${fs}|${edge}`;
    if (key !== this._sizeKey) {
      this._sizeKey = key;
      this.style.setProperty("--u", `${u}px`);
      this.style.setProperty("--k", String(k));
      this.style.setProperty("--edge", edge.toFixed(3));
      this.style.setProperty("--fs", `${fs}px`);
      this._fitMainCaption();
    }
    this.toggleAttribute("narrow", width < 430);
    this.toggleAttribute("compact", width < 600);
  }

  // Point the stylesheet at the artwork. Called again if the images turn out
  // not to be where this file was loaded from.
  _applyArt() {
    for (const name of ["cover", "frame", "screw-a", "screw-b"]) {
      this.style.setProperty(`--art-${name}`, `url("${art(name)}")`);
    }
  }

  _onArtError(ev) {
    const img = ev.target;
    if (!(img instanceof HTMLImageElement) || !img.src.startsWith(artBase)) return;
    // A blip on the network shouldn't leave a hole in the panel: try once more.
    if (!img.dataset.retry) {
      img.dataset.retry = "1";
      const src = img.src;
      const t = setTimeout(() => {
        this._timers.delete(t);
        if (img.isConnected && img.src === src) img.src = src;
      }, 1500);
      this._timers.add(t);
    }
    // If this file was loaded from somewhere that has no ./img beside it (a
    // hand-copied card, say), use the copy the integration always serves —
    // but only once that copy is known to be there.
    if (artBase === ART_SERVED || this._artProbe) return;
    const probe = new Image();
    this._artProbe = probe;
    probe.onload = () => {
      artBase = ART_SERVED;
      this._applyArt();
      this._structKey = null;
      this._update(true);
    };
    probe.src = `${ART_SERVED}cover.webp?v=${ART_REV}`;
  }

  // Hovering a breaker or its label marks both, so it's clear which belong together.
  _hot(ev, on) {
    const el = ev.target && ev.target.closest ? ev.target.closest(".bkr[data-pos], .lbl[data-pos]") : null;
    const pair = el && this._slotEls ? this._slotEls.get(Number(el.dataset.pos)) : null;
    if (!pair) return;
    pair.tile.toggleAttribute("hot", on);
    pair.lbl.toggleAttribute("hot", on);
  }

  // Fetch the other states of every breaker on screen, so flipping one never
  // waits on the network.
  _preload(m) {
    const want = new Set();
    for (const p of m.placed) {
      const s = p.slot;
      if (s.kind === "empty") continue;
      const base = `bk-${p.column === 1 ? "L" : "R"}${s.poles}${s.kind === "smart" ? "s" : "t"}`;
      for (const state of s.kind === "smart" ? ["on", "off", "trip"] : ["on"]) want.add(`${base}-${state}`);
    }
    const run = () => {
      this._preloaded = this._preloaded || new Map();
      for (const name of want) {
        if (this._preloaded.has(name)) continue;
        const img = new Image();
        img.decoding = "async";
        img.src = art(name);
        this._preloaded.set(name, img);
      }
    };
    if (window.requestIdleCallback) window.requestIdleCallback(run, { timeout: 2500 });
    else setTimeout(run, 400);
  }

  // ── Update cycle ───────────────────────────────────────────────────

  _update(force) {
    const hass = this._hass;
    if (!hass || !this._config || !this._content) return;

    this._applyAppearance(hass);

    const language = this._syncLanguage(hass);
    if (language === null) return;
    if (language) {
      // Every string is baked into the DOM, so start over in the new language.
      this._structKey = null;
      this._msgKey = null;
      force = true;
    }

    if (!this._config.device_id) {
      this._renderMessage(
        this._t("card.setup.choose_title"),
        this._html("card.setup.choose_body", { option: "<code>device_id</code>" })
      );
      return;
    }

    // Discovery walks the whole registry, so it only reruns when the registry
    // changes — or, while some entity's state hasn't loaded yet, at most every
    // few seconds (a user-disabled entity would otherwise keep it "incomplete"
    // and rescan on every state change in the house).
    const now = Date.now();
    if (
      !this._disc ||
      hass.entities !== this._discEntities ||
      hass.devices !== this._discDevices ||
      (this._disc.incomplete && hass.states !== this._discStates && now - this._discAt > 5000)
    ) {
      this._disc = this._discover(hass);
      this._discAt = now;
      this._discEntities = hass.entities;
      this._discDevices = hass.devices;
      this._discStates = hass.states;
      this._setTracked(this._disc.tracked);
      force = true;
    }

    const locale = hass.locale;
    if (locale !== this._lastLocale) {
      this._lastLocale = locale;
      this._fmtCache.clear();
      [this._numLocale, this._numGrouping] = this._resolveLocale(hass);
      force = true;
    }

    // Nothing this card shows changed — HA calls `hass` for every state change
    // in the house, so bail out cheaply.
    if (!this._trackedChanged(hass) && !force) return;

    const model = this._buildModel(hass, this._disc);
    this._model = model;

    if (model.empty) {
      this._renderEmpty();
      return;
    }
    if (model.structKey !== this._structKey) {
      this._build(model);
      this._structKey = model.structKey;
      if (this._detailPos != null) this._buildDetail();
    }
    this._patch(model);
    if (this._detailPos != null) this._patchDetail();
  }

  _languageChanged() {
    this._update(false);
  }

  // A translated sentence with markup in its placeholders. The sentence is
  // escaped; only the parts passed in here are HTML.
  _html(key, parts) {
    return esc(this._t(key)).replace(/\{(\w+)\}/g, (whole, name) => (name in parts ? parts[name] : whole));
  }

  // Leviton's own state names ("ManualON", "SoftwareTrip"): translated where
  // known, tidied up otherwise.
  _raw(value) {
    if (value == null || value === "") return "—";
    const key = `card.raw.${String(value).toLowerCase().replace(/[^a-z0-9]/g, "")}`;
    return key in EN_FLAT ? this._t(key) : prettyRaw(value);
  }

  // "Circuit 7", or "Circuits 7 and 9" for a 2-pole breaker.
  _where(s) {
    return s.poles === 2
      ? this._t("card.label.circuits", { first: s.position, second: s.position + 2 })
      : this._t("card.label.circuit", { position: s.position });
  }

  _setTracked(ids) {
    this._trackedIds = ids;
    this._trackedRefs = new Array(ids.length);
  }

  _trackedChanged(hass) {
    const states = hass.states;
    let changed = false;
    for (let i = 0; i < this._trackedIds.length; i++) {
      const ref = states[this._trackedIds[i]];
      if (ref !== this._trackedRefs[i]) {
        this._trackedRefs[i] = ref;
        changed = true;
      }
    }
    return changed;
  }

  _applyAppearance(hass) {
    const pref = this._config.appearance;
    const dark = pref === "dark" || (pref !== "light" && !!(hass.themes && hass.themes.darkMode));
    const value = dark ? "dark" : "light";
    if (this.getAttribute("appearance") !== value) this.setAttribute("appearance", value);
  }

  _resolveLocale(hass) {
    const loc = hass.locale || {};
    const lang = loc.language || hass.language || navigator.language;
    switch (loc.number_format) {
      case "comma_decimal":
        return ["en-US", true];
      case "decimal_comma":
        return ["de", true];
      case "space_comma":
        return ["fr", true];
      case "system":
        return [undefined, true];
      case "none":
        return [lang, false];
      default:
        return [lang, true];
    }
  }

  _nf(digits) {
    let f = this._fmtCache.get(digits);
    if (!f) {
      const opts = { minimumFractionDigits: digits, maximumFractionDigits: digits, useGrouping: this._numGrouping };
      try {
        f = new Intl.NumberFormat(this._numLocale, opts);
      } catch (_e) {
        f = new Intl.NumberFormat(undefined, opts);
      }
      this._fmtCache.set(digits, f);
    }
    return f;
  }

  _watts(n) {
    if (n === null) return null;
    return Math.abs(n) >= 10000 ? `${this._nf(1).format(n / 1000)} kW` : `${this._nf(0).format(n)} W`;
  }

  _amps(n) {
    return n === null ? null : `${this._nf(1).format(n)} A`;
  }

  _num(eid) {
    const s = eid && this._hass.states[eid];
    return s ? numOrNull(s.state) : null;
  }

  // ── Discovery (registry-driven, cached until the registry changes) ──

  _discover(hass) {
    const cfg = this._config;
    const panelId = cfg.device_id;
    const states = hass.states || {};
    const devices = hass.devices || {};
    const entityList = hass.entities ? Object.values(hass.entities) : [];

    const byDevice = new Map();
    for (const e of entityList) {
      if (!e.device_id) continue;
      const list = byDevice.get(e.device_id);
      if (list) list.push(e.entity_id);
      else byDevice.set(e.device_id, [e.entity_id]);
    }
    const idsFor = (id) => byDevice.get(id) || [];
    const category = (eid) => (hass.entities[eid] && hass.entities[eid].entity_category) || null;
    const attr = (eid) => (states[eid] && states[eid].attributes) || {};
    let incomplete = false;

    // Panel
    const panelIds = idsFor(panelId);
    const panel = matchRoles(panelIds, PANEL_ROLES);
    fallbackRole(panel, panelIds, "cloud", (eid) => {
      const a = attr(eid);
      return eid.startsWith("binary_sensor.") && ("orientation" in a || "dumb_breakers" in a || "panel_size" in a);
    });

    // Breakers and CT clamps are both linked to the panel via via_device.
    const breakers = [];
    const cts = [];
    for (const dev of Object.values(devices)) {
      if (dev.via_device_id !== panelId) continue;
      const ids = idsFor(dev.id);
      const m = matchRoles(ids, BREAKER_ROLES);
      fallbackRole(m, ids, "status", (eid) => {
        const a = attr(eid);
        return eid.startsWith("binary_sensor.") && a.position !== undefined && a.poles !== undefined;
      });
      if (!m.roles.status) {
        const ct = matchRoles(ids, CT_ROLES);
        fallbackRole(ct, ids, "watts", (eid) => eid.startsWith("sensor.") && attr(eid).device_class === "power");
        fallbackRole(ct, ids, "amps", (eid) => eid.startsWith("sensor.") && attr(eid).device_class === "current");
        if (ct.roles.watts || ct.roles.amps) {
          cts.push({ deviceId: dev.id, name: dev.name_by_user || dev.name || "CT", roles: ct.roles });
        } else if (ids.length && !ids.some((eid) => states[eid])) {
          incomplete = true; // states not loaded yet — retry once they are
        }
        continue;
      }
      fallbackRole(m, ids, "watts", (eid) => eid.startsWith("sensor.") && attr(eid).device_class === "power");
      fallbackRole(m, ids, "amps", (eid) => eid.startsWith("sensor.") && attr(eid).device_class === "current");
      fallbackRole(m, ids, "blink", (eid) => eid.startsWith("switch.") && category(eid) === "diagnostic");
      fallbackRole(m, ids, "power", (eid) => eid.startsWith("switch.") && !category(eid));
      breakers.push({
        deviceId: dev.id,
        name: dev.name_by_user || dev.name || null,
        roles: m.roles,
        others: ids.filter((eid) => !m.used.has(eid)),
      });
    }
    cts.sort((a, b) => a.name.localeCompare(b.name));

    // Hand-configured links from a dumb breaker to the sub-panel it feeds.
    const links = [];
    for (const sp of cfg.sub_panels) {
      if (!sp) continue;
      const position = Number(sp.breaker_position);
      if (!Number.isFinite(position)) continue;
      const deviceId = sp.panel_device_id || null;
      const dev = deviceId ? devices[deviceId] : null;
      const ids = deviceId ? idsFor(deviceId) : [];
      links.push({
        position,
        deviceId,
        viewPath: sp.view_path || null,
        rating: numOrNull(sp.rating),
        name: (dev && (dev.name_by_user || dev.name)) || null,
        roles: matchRoles(ids, PANEL_ROLES).roles,
      });
    }

    const tracked = new Set();
    const add = (roles) => Object.values(roles).forEach((eid) => eid && tracked.add(eid));
    add(panel.roles);
    breakers.forEach((b) => {
      add(b.roles);
      b.others.forEach((eid) => tracked.add(eid));
    });
    cts.forEach((c) => add(c.roles));
    links.forEach((l) => add(l.roles));

    if (panelIds.length && !panel.roles.cloud) incomplete = true;
    if (breakers.some((b) => !states[b.roles.status])) incomplete = true;

    return {
      panelDevice: devices[panelId] || null,
      panel: { roles: panel.roles },
      breakers,
      cts,
      links,
      tracked: [...tracked],
      incomplete,
      diagnostics: {
        hassHasDevices: typeof hass.devices === "object" && hass.devices !== null,
        hassHasEntities: typeof hass.entities === "object" && hass.entities !== null,
        totalDevices: Object.keys(devices).length,
        totalEntities: entityList.length,
        panelDeviceFound: !!devices[panelId],
        devicesLinkedToAnyPanel: Object.values(devices).filter((d) => !!d.via_device_id).length,
        devicesLinkedToThisPanel: Object.values(devices).filter((d) => d.via_device_id === panelId).length,
        statusEntitiesFoundOnThisPanel: breakers.length,
      },
    };
  }

  // ── Model (cheap, recomputed when a tracked state changes) ─────────

  _buildModel(hass, d) {
    const st = hass.states;
    const cfg = this._config;
    const cloud = d.panel.roles.cloud ? st[d.panel.roles.cloud] : null;
    const ca = (cloud && cloud.attributes) || {};

    const rotate =
      cfg.rotate_180 !== undefined && cfg.rotate_180 !== null
        ? !!cfg.rotate_180
        : Number(ca.orientation) === 180;

    const slots = [];
    const taken = new Set();
    for (const b of d.breakers) {
      const s = st[b.roles.status];
      if (!s) continue;
      const a = s.attributes || {};
      const position = Number(a.position);
      if (!Number.isFinite(position) || taken.has(position)) continue;
      taken.add(position);
      slots.push({
        kind: "smart",
        position,
        poles: Number(a.poles) === 2 ? 2 : 1,
        deviceId: b.deviceId,
        name: b.name || a.friendly_name || this._t("card.name.breaker"),
        rating: numOrNull(a.rating),
        model: a.model || null,
        canRemoteOn: a.canRemoteOn === true,
        roles: b.roles,
        others: b.others,
      });
    }

    // Physically present but non-smart ("dumb") breakers never become HA
    // devices — the integration lists them on the panel's Cloud Connected
    // entity so they don't show up as false gaps.
    const linkByPos = new Map(d.links.map((l) => [l.position, l]));
    for (const db of Array.isArray(ca.dumb_breakers) ? ca.dumb_breakers : []) {
      const position = Number(db && db.position);
      if (!Number.isFinite(position) || taken.has(position)) continue;
      taken.add(position);
      const link = linkByPos.get(position) || null;
      slots.push({
        kind: link && link.deviceId ? "link" : "dumb",
        position,
        poles: Number(db.poles) === 2 ? 2 : 1,
        name: db.name || this._t("card.name.unmonitored_breaker"),
        rating: link ? link.rating : null,
        link,
      });
    }

    // Open positions become blank twist-outs, so the drawing keeps the
    // panel's real proportions. A 2-pole breaker's second position is never
    // reported separately, so it is marked taken here too.
    const occupied = new Set();
    for (const s of slots) {
      occupied.add(s.position);
      if (s.poles === 2) occupied.add(s.position + 2);
    }
    const highest = Math.max(0, ...occupied);
    const reported = Number(ca.panel_size);
    const evenHighest = highest + (highest % 2);
    const count = Number.isFinite(reported) && reported > 0 ? Math.max(reported, evenHighest) : evenHighest;
    for (let p = 1; p <= count; p++) {
      if (!occupied.has(p)) slots.push({ kind: "empty", position: p, poles: 1 });
    }
    slots.sort((a, b) => a.position - b.position);

    if (!slots.length) return { empty: true, rows: 0 };

    const placed = this._computeLayout(slots, rotate);
    const rows = Math.max(1, ...placed.map((p) => p.row + p.rowSpan - 1));

    // Position numbers printed on the dead front between the two columns.
    const numbers = new Map();
    for (const p of placed) {
      for (let i = 0; i < p.rowSpan; i++) {
        const pos = p.slot.position + 2 * (rotate ? p.rowSpan - 1 - i : i);
        const row = p.row + i;
        const entry = numbers.get(row) || { row };
        entry[p.column === 1 ? "left" : "right"] = pos;
        numbers.set(row, entry);
      }
    }

    const now = Date.now();
    for (const s of slots) this._slotDynamics(st, s, now);

    const panelDevice = d.panelDevice;
    const title = cfg.title || (panelDevice && (panelDevice.name_by_user || panelDevice.name)) || this._t("card.name.panel");

    const structKey = JSON.stringify([
      rotate,
      rows,
      title,
      cfg.toggle,
      cfg.show_power,
      cfg.show_panel_info,
      cfg.main_breaker || null,
      Object.keys(d.panel.roles).sort(),
      d.cts.map((c) => [c.deviceId, c.name]),
      placed.map((p) => [
        p.column,
        p.row,
        p.rowSpan,
        p.slot.kind,
        p.slot.position,
        p.slot.poles,
        p.slot.name || "",
        p.slot.rating,
        p.slot.deviceId || "",
        p.slot.roles ? !!p.slot.roles.power : 0,
        p.slot.link ? [p.slot.link.deviceId, p.slot.link.name, p.slot.link.viewPath] : 0,
      ]),
    ]);

    return {
      empty: false,
      rotate,
      rows,
      title,
      slots,
      placed,
      numbers: [...numbers.values()].sort((a, b) => a.row - b.row),
      byPos: new Map(slots.map((s) => [s.position, s])),
      head: this._headDynamics(st, d),
      structKey,
      panelDevice,
    };
  }

  _slotDynamics(st, s, now) {
    const cfg = this._config;
    if (s.kind === "empty") return;

    if (s.kind !== "smart") {
      const roles = (s.link && s.link.roles) || {};
      s.watts = cfg.show_power ? this._num(roles.watts) : null;
      s.amps = cfg.show_power ? this._num(roles.amps) : null;
      s.vis = "unknown";
      s.handle = "on";
      s.led = "off";
      s.alarms = [];
      return;
    }

    const r = s.roles;
    const status = st[r.status];
    const available = !!status && status.state !== "unavailable";
    const isOn = !!status && status.state === "on";
    const bs = r.breakerState ? st[r.breakerState] : null;
    const bsa = (bs && bs.attributes) || {};
    const raw = bs && bs.state !== "unavailable" && bs.state !== "unknown" ? bs.state : null;
    const tripped = /trip/i.test(raw || "") || /trip/i.test(bsa.second_pole_state || "");
    const remoteOff = bsa.remote_state === "RemoteOFF";

    let vis;
    if (!available) vis = "unavailable";
    else if (tripped) vis = "tripped";
    else if (isOn) vis = "on";
    else if (remoteOff && raw !== "ManualOFF") vis = "remote-off";
    else vis = "off";

    const sw = r.power ? st[r.power] : null;
    s.switchOn = sw ? sw.state === "on" : isOn;
    s.switchAvailable = !!sw && sw.state !== "unavailable";
    s.blinkOn = r.blink ? !!st[r.blink] && st[r.blink].state === "on" : false;

    // A remote command takes a cloud round-trip; show it in flight until the
    // switch reports the new state (or give up after 30 s).
    const pend = r.power ? this._pending.get(r.power) : null;
    if (pend) {
      if (s.switchOn === (pend.target === "on") || now - pend.since > 30000) {
        this._pending.delete(r.power);
      } else {
        vis = "pending";
        s.pendingTarget = pend.target;
      }
    }

    s.available = available;
    s.isOn = isOn;
    s.raw = raw;
    s.vis = vis;
    // What the breaker itself shows (Leviton's handle and LED table): a
    // remote switch-off leaves the handle on and green and lights the LED.
    const handleOn = isOn || (remoteOff && raw !== "ManualOFF");
    s.handle = !available ? "off" : tripped ? "trip" : handleOn ? "on" : "off";
    s.led = vis === "pending" || s.blinkOn ? "blink" : vis === "remote-off" ? "on" : "off";
    s.watts = cfg.show_power ? this._num(r.watts) : null;
    s.amps = cfg.show_power ? this._num(r.amps) : null;

    const alarms = [];
    if (cfg.show_alarms) {
      if (r.overCurrent && st[r.overCurrent] && st[r.overCurrent].state === "on") alarms.push(this._t("card.alarm.over_current"));
      if (r.overVoltage && st[r.overVoltage] && st[r.overVoltage].state === "on") alarms.push(this._t("card.alarm.over_voltage"));
      if (r.underVoltage && st[r.underVoltage] && st[r.underVoltage].state === "on") alarms.push(this._t("card.alarm.under_voltage"));
      const op = r.operationalState && st[r.operationalState] ? st[r.operationalState].state : null;
      if (op && !["Normal", "unknown", "unavailable", ""].includes(op)) alarms.push(this._raw(op));
    }
    s.alarms = alarms;

    const err = this._errors.get(s.position);
    s.error = err && err.until > now ? err.text : null;
    if (err && !s.error) this._errors.delete(s.position);
  }

  _headDynamics(st, d) {
    const r = d.panel.roles;
    const val = (eid) => (eid && st[eid] ? numOrNull(st[eid].state) : null);
    const cloud = r.cloud ? st[r.cloud] : null;
    const fw = r.firmware ? st[r.firmware] : null;
    return {
      watts: val(r.watts),
      amps: val(r.amps),
      voltsL1: val(r.voltsL1),
      voltsL2: val(r.voltsL2),
      ampsL1: val(r.ampsL1),
      ampsL2: val(r.ampsL2),
      freq: val(r.freqL1) !== null ? val(r.freqL1) : val(r.freqL2),
      today: val(r.dailyConsumption),
      todayImport: val(r.dailyImport),
      rssi: val(r.wifi),
      cloud: cloud ? cloud.state : null,
      fwAvailable: !!fw && fw.state === "on",
      overVoltage: !!(r.overVoltage && st[r.overVoltage] && st[r.overVoltage].state === "on"),
      underVoltage: !!(r.underVoltage && st[r.underVoltage] && st[r.underVoltage].state === "on"),
      cts: d.cts.map((c) => ({ name: c.name, watts: val(c.roles.watts), eid: c.roles.watts || c.roles.amps })),
    };
  }

  // Explicit row/column placement (not CSS auto-flow) so rotate_180 can flip
  // both axes deterministically. Odd positions are the left column, even
  // positions the right — independent of the electrical leg. The row comes
  // straight from the position number so the two columns stay physically
  // aligned whatever the mix of 1- and 2-pole breakers.
  _computeLayout(slots, rotate) {
    const placed = slots.map((slot) => {
      const column = slot.position % 2 === 1 ? 1 : 2;
      return {
        slot,
        column,
        row: column === 1 ? (slot.position + 1) / 2 : slot.position / 2,
        rowSpan: slot.poles === 2 ? 2 : 1,
      };
    });
    if (rotate) {
      // Flip each column within its own extent, then swap the columns.
      const maxRow = {};
      for (const c of [1, 2]) {
        maxRow[c] = Math.max(1, ...placed.filter((p) => p.column === c).map((p) => p.row + p.rowSpan - 1));
      }
      for (const p of placed) {
        p.row = maxRow[p.column] - (p.row + p.rowSpan - 1) + 1;
        p.column = p.column === 1 ? 2 : 1;
      }
    }
    return placed;
  }

  // ── Build (only when the panel's structure changes) ────────────────

  _build(m) {
    const cfg = this._config;
    const rows = m.rows;
    const main = numOrNull(cfg.main_breaker);

    // One grid holds everything from the labels inward, so a label and its
    // breaker share a row and follow each other in the page order. Grid row
    // 1 is the top of the door surround and row 2 the piece that closes the
    // top of each column, so panel row N is grid row N + 2.
    let cells = "";
    for (const p of m.placed) {
      const side = p.column === 1 ? "left" : "right";
      const where = `grid-row:${p.row + 2} / span ${p.rowSpan}`;
      // Higher spaces paint over lower ones: a breaker's shadow falls on the
      // space beneath it.
      const tile = this._tileHtml(p, side, `${where};z-index:${rows - p.row + 2}`);
      const label = this._labelHtml(p, side, where);
      cells += side === "left" ? label + tile : tile + label;
    }
    let numbers = "";
    for (const n of m.numbers) {
      numbers += `<div class="num" style="grid-row:${n.row + 2}" aria-hidden="true"><span>${n.left ?? ""}</span><span>${n.right ?? ""}</span></div>`;
    }
    const mainHtml = main
      ? `<div class="main" data-h="main">
           <img class="main-sp" data-h="mainImg" alt="" draggable="false">
           ${ratingSvg(G.main.w, G.main.h, G.main.rating[0], G.main.rating[1], 90, String(main), G.rating.size * G.main.scale)}
           <span class="main-cap" aria-hidden="true">${esc(this._t("card.meter.main"))}</span>
         </div>`
      : "";
    const cap = (cls, name) => `<img class="cap ${cls}" src="${art(name)}" alt="" draggable="false">`;

    this._content.innerHTML = `
      <div class="stage">
        <div class="cover${main ? " has-main" : ""}" style="--rows:${rows}">
          <i class="screw screw--tl"></i><i class="screw screw--tr"></i><i class="screw screw--bl"></i><i class="screw screw--br"></i>
          ${this._headHtml(m)}
          <div class="body">
            <i class="well"></i>
            ${mainHtml}
            <i class="gap gap--l"></i><i class="gap gap--r"></i>
            ${cap("cap--tl", "cap-L-top")}${cap("cap--tr", "cap-R-top")}${cap("cap--bl", "cap-L-bot")}${cap("cap--br", "cap-R-bot")}
            ${numbers}
            ${cells}
          </div>
          <div class="foot"></div>
        </div>
      </div>`;

    // Index the dynamic parts so each update only touches what changed.
    this._slotEls = new Map();
    for (const tile of this._content.querySelectorAll(".bkr[data-pos]")) {
      const pos = Number(tile.dataset.pos);
      const lbl = this._content.querySelector(`.lbl[data-pos="${pos}"]`);
      this._slotEls.set(pos, {
        tile,
        lbl,
        code: tile.dataset.code,
        img: tile.querySelector(".sp"),
        rocker: tile.querySelector("button.rk"),
        sub: lbl.querySelector(".lbl-sub"),
        tag: lbl.querySelector(".lbl-tag"),
        barFill: lbl.querySelector(".lbl-bar i"),
        cache: {},
      });
    }
    this._headEls = {};
    for (const el of this._content.querySelectorAll("[data-h]")) this._headEls[el.dataset.h] = el;
    this._headCache = {};
    this._fitMainCaption();
    this._preload(m);
  }

  // "Main" is printed in the little dead front beside the main breaker. Some
  // languages need a longer word than fits there; that one is turned to read
  // down the side of the breaker instead of being cut short.
  _fitMainCaption() {
    const cap = this._content && this._content.querySelector(".main-cap");
    if (!cap) return;
    cap.classList.remove("main-cap--tall");
    if (cap.scrollWidth > cap.clientWidth + 1) cap.classList.add("main-cap--tall");
  }

  _headHtml(m) {
    const cfg = this._config;
    const t = this._t;
    const r = this._disc.panel.roles;

    const led = (key, label, eid) =>
      eid
        ? `<button type="button" class="ind" data-act="more" data-eid="${esc(eid)}" data-h="${key}" title="${esc(
            label
          )}"><i class="${key === "wifi" ? "bars" : "pilot"}">${key === "wifi" ? "<i></i><i></i><i></i><i></i>" : ""}</i><b>${esc(
            label
          )}</b></button>`
        : "";

    const cell = (key, cap, eid) =>
      eid
        ? `<button type="button" class="m-cell" data-act="more" data-eid="${esc(eid)}"><span class="m-cap">${esc(
            cap
          )}</span><span class="m-val" data-h="${key}"></span></button>`
        : "";

    let meter = "";
    if (cfg.show_panel_info) {
      const cells = [
        cell("l1", t("card.meter.leg_1"), r.voltsL1 || r.ampsL1),
        cell("l2", t("card.meter.leg_2"), r.voltsL2 || r.ampsL2),
        cell("freq", t("card.meter.frequency"), r.freqL1 || r.freqL2),
        cell("today", t("card.meter.today"), r.dailyConsumption),
        r.dailyImport ? cell("todayImport", t("card.meter.today_import"), r.dailyImport) : "",
        ...this._disc.cts.map((c, i) => cell(`ct${i}`, c.name, c.roles.watts || c.roles.amps)),
      ].join("");
      meter = `
        <div class="meter">
          <button type="button" class="m-main" data-act="more" data-eid="${esc(r.watts || "")}" ${r.watts ? "" : "disabled"}>
            <span class="m-cap">${esc(t("card.meter.panel_load"))}</span>
            <span class="m-big" data-h="total"></span>
            <span class="m-amps" data-h="amps"></span>
          </button>
          <div class="m-grid">${cells}</div>
          <div class="m-alarm" data-h="alarm" hidden></div>
        </div>`;
    }

    return `
      <div class="head">
        <div class="head-top">
          <div class="plate" title="${esc(m.title)}">${esc(m.title)}</div>
          <div class="inds">
            ${led("cloud", t("card.meter.cloud"), r.cloud)}
            ${led("wifi", t("card.meter.wifi"), r.wifi)}
            ${led("fw", t("card.meter.update"), r.firmware)}
          </div>
        </div>
        ${meter}
      </div>`;
  }

  _tileHtml(p, side, style) {
    const s = p.slot;
    const col = side === "left" ? "L" : "R";
    if (s.kind === "empty") {
      return `<div class="bkr bkr--${side} bkr--empty" style="${style}" aria-hidden="true"><img class="sp" src="${art(
        `fill-${col}`
      )}" alt="" draggable="false"></div>`;
    }
    const spots = tileSpots(side, s.poles);
    const smart = s.kind === "smart";
    const rk = spots.rocker;
    const rocker =
      smart && s.roles.power && this._config.toggle
        ? `<button type="button" class="rk" data-act="toggle" data-pos="${s.position}" role="switch" aria-checked="false" style="left:${pct(
            rk.left
          )};top:${pct(rk.top)};width:${pct(rk.width)};height:${pct(rk.height)}"></button>`
        : "";
    const rating = s.rating
      ? ratingSvg(G.tileW, s.poles, spots.rating.x, spots.rating.y, spots.rating.turn, String(s.rating), G.rating.size)
      : "";
    return `
      <div class="bkr bkr--${side} bkr--${s.kind}" style="${style}" data-pos="${s.position}" data-code="${col}${s.poles}${
      smart ? "s" : "t"
    }" data-vis="unknown">
        <img class="sp" alt="" draggable="false">
        <button type="button" class="hit" data-act="open" data-pos="${s.position}" tabindex="-1" aria-hidden="true"></button>
        ${rating}
        ${smart ? `<i class="led" style="left:${pct(spots.led.left)};top:${pct(spots.led.top)}"></i>` : ""}
        ${rocker}
      </div>`;
  }

  _labelHtml(p, side, style) {
    const s = p.slot;
    if (s.kind === "empty") return "";
    return `
      <button type="button" class="lbl lbl--${side} lbl--${s.kind}${p.rowSpan > 1 ? " lbl--tall" : ""}" style="${style}" data-act="open" data-pos="${s.position}" data-vis="unknown">
        <span class="lbl-top"><span class="lbl-name">${esc(s.name)}</span><span class="lbl-tag"></span></span>
        <span class="lbl-sub"></span>
        <span class="lbl-bar"><i></i></span>
      </button>`;
  }

  // ── Patch (every relevant state change) ────────────────────────────

  _set(cache, key, value, apply) {
    if (cache[key] === value) return;
    cache[key] = value;
    apply(value);
  }

  _patch(m) {
    for (const s of m.slots) {
      if (s.kind === "empty") continue;
      const el = this._slotEls.get(s.position);
      if (el) this._patchSlot(s, el);
    }
    this._patchHead(m.head);
  }

  // Watts and amps as separate spans, so narrow cards can drop the amps.
  _readings(s) {
    const w = this._watts(s.watts);
    const a = this._amps(s.amps);
    if (!w && !a) return null;
    const text = [w, a].filter(Boolean).join(" · ");
    const html = w && a ? `<span>${esc(w)}</span><span class="r-amps"> · ${esc(a)}</span>` : esc(w || a);
    return { text, html };
  }

  _slotSubText(s) {
    const t = this._t;
    const r = this._readings(s);
    if (s.kind === "dumb") return { text: t("card.state.not_monitored"), tone: "muted" };
    if (s.kind === "link") {
      const name = s.link.name || t("card.name.sub_panel");
      return { text: r ? `${name}, ${r.text}` : name, html: `↳ ${esc(name)}${r ? ` · ${r.html}` : ""}`, tone: "link" };
    }
    if (s.error) return { text: s.error, tone: "bad" };
    const alarm = s.alarms && s.alarms.length ? s.alarms.join(", ") : null;
    switch (s.vis) {
      case "pending":
        return { text: t(s.pendingTarget === "on" ? "card.state.switching_on" : "card.state.switching_off"), tone: "warn" };
      case "unavailable":
        return { text: t("card.state.unavailable"), tone: "muted" };
      case "tripped":
        return { text: alarm ? `${t("card.state.tripped")} · ${alarm}` : t("card.state.tripped"), tone: "bad" };
      default:
        break;
    }
    // An alarm outranks the readings: say what's wrong, readings follow.
    if (alarm) {
      return { text: [alarm, r && r.text].filter(Boolean).join(" · "), html: r ? `${esc(alarm)} · ${r.html}` : null, tone: "bad" };
    }
    if (s.vis === "remote-off") return { text: t("card.state.off_remote"), tone: "muted" };
    if (s.vis === "off") return { text: t("card.state.off"), tone: "muted" };
    return { text: r ? r.text : t("card.state.on"), html: r && r.html, tone: "" };
  }

  _patchSlot(s, el) {
    const c = el.cache;
    const t = this._t;
    const sub = this._slotSubText(s);
    const alarm = s.alarms && s.alarms.length ? s.alarms : null;

    this._set(c, "vis", s.vis, (v) => {
      el.tile.dataset.vis = v;
      el.lbl.dataset.vis = v;
    });
    // The picture follows the hardware: handle position and window colour.
    this._set(c, "art", `bk-${el.code}-${s.handle}`, (v) => (el.img.src = art(v)));
    this._set(c, "led", s.led, (v) => (el.tile.dataset.led = v));
    this._set(c, "alarm", alarm ? alarm.join(", ") : "", (v) => el.lbl.toggleAttribute("data-alarm", !!v));
    this._set(c, "sub", `${sub.tone}|${sub.text}`, () => {
      if (sub.html) el.sub.innerHTML = sub.html;
      else el.sub.textContent = sub.text;
      el.sub.dataset.tone = sub.tone;
    });

    const tag = alarm ? "!" : s.rating ? `${s.rating}A` : "";
    this._set(c, "tag", tag, () => {
      if (alarm) el.tag.innerHTML = icon("alert");
      else el.tag.textContent = tag;
      el.tag.classList.toggle("lbl-tag--alarm", !!alarm);
    });

    // Load bar: how close the circuit runs to its rating.
    let load = null;
    if (s.vis === "on" && s.rating && s.amps !== null && s.amps >= 0) load = Math.min(100, (s.amps / s.rating) * 100);
    const loadKey = load === null ? "" : Math.round(load);
    this._set(c, "load", loadKey, () => {
      el.barFill.style.width = load === null ? "0" : `${Math.max(2, load)}%`;
      if (load !== null) el.lbl.dataset.load = load >= 80 ? "high" : load >= 50 ? "warn" : "ok";
    });

    const stateWord = {
      on: t("card.state.on"),
      off: t("card.state.off"),
      "remote-off": t("card.state.off_remote"),
      tripped: t("card.state.tripped"),
      unavailable: t("card.state.unavailable"),
      pending: t("card.state.switching"),
      unknown: s.kind === "link" ? t("card.label.feeds_sub_panel") : t("card.state.not_monitored"),
    }[s.vis];
    // What a screen reader says for this circuit: name, where, rating, state,
    // then the readings or sub-panel (unless that only repeats the state).
    const extra = sub.tone === "" || sub.tone === "link" ? sub.text : null;
    const parts = [
      s.name,
      this._where(s),
      s.rating ? t("card.label.amp_rating", { amps: s.rating }) : null,
      stateWord,
      extra !== stateWord ? extra : null,
      alarm ? alarm.join(", ") : null,
    ].filter(Boolean);
    const label = parts.join(", ");
    this._set(c, "label", label, (v) => {
      const action = s.kind !== "link" ? "show_details" : s.link.viewPath ? "open_sub_panel_dashboard" : "open_sub_panel";
      el.lbl.setAttribute("aria-label", `${v}. ${t(`card.label.${action}`)}`);
      el.lbl.title = [
        s.name,
        s.rating ? `${s.rating} A` : null,
        alarm ? alarm.join(", ") : null,
        s.kind !== "link" ? null : s.link.name ? t("card.label.feeds", { name: s.link.name }) : t("card.label.feeds_sub_panel"),
      ]
        .filter(Boolean)
        .join(" — ");
    });

    if (el.rocker) {
      this._set(c, "rk", `${s.switchOn}|${s.vis}|${s.switchAvailable}`, () => {
        el.rocker.setAttribute("aria-checked", String(!!s.switchOn));
        el.rocker.setAttribute("aria-label", t("card.label.breaker_switch", { name: s.name }));
        el.rocker.title =
          s.vis === "pending" ? t("card.state.switching") : t(s.switchOn ? "card.action.turn_off_name" : "card.action.turn_on_name", { name: s.name });
        el.rocker.disabled = !s.switchAvailable || s.vis === "pending";
      });
    }
  }

  _patchHead(h) {
    const els = this._headEls || {};
    const c = this._headCache || (this._headCache = {});
    const t = this._t;
    const text = (key, value) => {
      const el = els[key];
      if (el) this._set(c, key, value, (v) => (el.textContent = v));
    };
    const nf1 = this._nf(1);
    const dash = "—";

    if (els.total) {
      const w = h.watts;
      let big = dash;
      if (w !== null) big = Math.abs(w) >= 1000 ? `${this._nf(2).format(w / 1000)} kW` : `${this._nf(0).format(w)} W`;
      text("total", big);
      text("amps", h.amps !== null ? `${nf1.format(h.amps)} A` : "");
    }
    const leg = (v, a) => [v !== null ? `${nf1.format(v)} V` : null, a !== null ? `${nf1.format(a)} A` : null].filter(Boolean).join(" · ") || dash;
    text("l1", leg(h.voltsL1, h.ampsL1));
    text("l2", leg(h.voltsL2, h.ampsL2));
    text("freq", h.freq !== null ? `${nf1.format(h.freq)} Hz` : dash);
    text("today", h.today !== null ? `${nf1.format(h.today)} kWh` : dash);
    text("todayImport", h.todayImport !== null ? `${nf1.format(h.todayImport)} kWh` : dash);
    h.cts.forEach((ct, i) => text(`ct${i}`, ct.watts !== null ? this._watts(ct.watts) : dash));

    if (els.cloud) {
      const state = h.cloud === "on" ? "on" : h.cloud === "off" ? "off" : "unknown";
      this._set(c, "cloudState", state, (v) => {
        els.cloud.dataset.state = v;
        els.cloud.title = t(v === "on" ? "card.meter.cloud_connected" : v === "off" ? "card.meter.cloud_offline" : "card.meter.cloud_unknown");
      });
    }
    if (els.wifi) {
      const r = h.rssi;
      const bars = r === null ? 0 : r >= -55 ? 4 : r >= -65 ? 3 : r >= -75 ? 2 : r >= -85 ? 1 : 0;
      this._set(c, "wifiBars", `${bars}|${r}`, () => {
        els.wifi.dataset.bars = String(bars);
        els.wifi.title = r === null ? t("card.meter.wifi_unknown") : t("card.meter.wifi_signal", { dbm: r });
      });
    }
    if (els.fw) {
      this._set(c, "fw", h.fwAvailable, (v) => {
        els.fw.dataset.state = v ? "on" : "off";
        els.fw.title = t(v ? "card.meter.update_available" : "card.meter.update_current");
      });
    }
    if (els.mainImg) {
      // Leviton doesn't report the main breaker, but the hub is fed through
      // it: with both legs dead, the main is open.
      const dead = h.voltsL1 !== null && h.voltsL2 !== null && h.voltsL1 <= 90 && h.voltsL2 <= 90;
      this._set(c, "main", dead ? "off" : "on", (v) => {
        els.mainImg.src = art(`main-${v}`);
        els.main.title = t(v === "on" ? "card.meter.main_breaker" : "card.meter.main_breaker_dead");
      });
    }
    if (els.alarm) {
      const alarm = [h.overVoltage ? t("card.alarm.over_voltage") : null, h.underVoltage ? t("card.alarm.under_voltage") : null].filter(Boolean).join(" · ");
      this._set(c, "alarm", alarm, (v) => {
        els.alarm.hidden = !v;
        els.alarm.innerHTML = v ? `${icon("alert")}<span>${esc(v)}</span>` : "";
      });
    }
  }

  // ── Messages / empty state ─────────────────────────────────────────

  _renderMessage(title, html) {
    // Called on every hass update while the card has nothing else to show.
    const key = `${title}|${html}`;
    if (this._structKey === null && this._msgKey === key) return;
    this._msgKey = key;
    this._structKey = null;
    this._content.innerHTML = `<div class="msg"><div class="msg-t">${esc(title)}</div><div class="msg-b">${html}</div></div>`;
  }

  _renderEmpty() {
    const d = (this._disc && this._disc.diagnostics) || {};
    const line = (label, ok, detail) =>
      `<div class="diag ${ok ? "diag--ok" : "diag--bad"}">${ok ? "✓" : "✗"} ${esc(label)}${
        detail !== undefined ? `: ${esc(detail)}` : ""
      }</div>`;
    const t = this._t;
    this._renderMessage(
      t("card.setup.empty_title"),
      `<div class="diags">
        ${line(t("card.setup.check_devices"), d.hassHasDevices)}
        ${line(t("card.setup.check_entities"), d.hassHasEntities)}
        ${line(t("card.setup.check_device_id"), !!this._config.device_id, this._config.device_id || t("card.detail.not_set"))}
        ${line(t("card.setup.check_panel_found"), d.panelDeviceFound)}
        ${line(t("card.setup.check_total_devices"), d.totalDevices > 0, d.totalDevices)}
        ${line(t("card.setup.check_linked_any"), d.devicesLinkedToAnyPanel > 0, d.devicesLinkedToAnyPanel)}
        ${line(t("card.setup.check_linked_this"), d.devicesLinkedToThisPanel > 0, d.devicesLinkedToThisPanel)}
        ${line(t("card.setup.check_breakers"), d.statusEntitiesFoundOnThisPanel > 0, `${d.statusEntitiesFoundOnThisPanel} / ${d.devicesLinkedToThisPanel}`)}
      </div>
      <p>${esc(t("card.setup.empty_help"))}</p>`
    );
  }

  // ── Interaction ────────────────────────────────────────────────────

  _onClick(ev) {
    const target = ev.target;
    // A click on a modal dialog's backdrop targets the <dialog> itself (its
    // content fills the whole box), so that closes it.
    if (target instanceof HTMLDialogElement) {
      target.close();
      return;
    }
    const el = target.closest ? target.closest("[data-act]") : null;
    if (!el || el.disabled) return;
    const pos = Number(el.dataset.pos);
    switch (el.dataset.act) {
      case "open":
        this._openSlot(pos);
        break;
      case "toggle":
        ev.stopPropagation();
        this._requestToggle(pos);
        break;
      case "more":
        this._moreInfo(el.dataset.eid);
        break;
      case "d-close":
        this._dlgDetail.close();
        break;
      case "d-power":
        this._detailPower();
        break;
      case "d-cancel":
        this._detailConfirm = false;
        this._patchDetail();
        if (this._detailEls && this._detailEls.pbtn) this._detailEls.pbtn.focus();
        break;
      case "d-confirm":
        this._detailConfirmed();
        break;
      case "d-blink":
        this._toggleBlink();
        break;
      case "d-device":
        this._navigate(`/config/devices/device/${el.dataset.device}`);
        break;
      case "c-cancel":
        this._dlgConfirm.close();
        break;
      case "c-ok":
        this._confirmOk();
        break;
      case "s-close":
        this._dlgSub.close();
        break;
      default:
        break;
    }
  }

  _openSlot(pos) {
    const s = this._model && this._model.byPos.get(pos);
    if (!s) return;
    if (s.kind === "link") {
      if (s.link.viewPath) this._navigate(s.link.viewPath);
      else this._openSubPanel(s.link.deviceId, s.link.name || s.name);
      return;
    }
    this._detailPos = pos;
    this._detailConfirm = false;
    this._buildDetail();
    this._patchDetail();
    if (!this._dlgDetail.open) this._dlgDetail.showModal();
  }

  _navigate(path) {
    if (!path) return;
    for (const dlg of [this._dlgDetail, this._dlgConfirm, this._dlgSub]) if (dlg.open) dlg.close();
    history.pushState(null, "", path);
    window.dispatchEvent(new CustomEvent("location-changed", { detail: { replace: false } }));
  }

  _moreInfo(entityId) {
    if (!entityId) return;
    // Close our own modal first: HA's more-info dialog isn't guaranteed to
    // stack above a native modal <dialog> on every frontend version.
    for (const dlg of [this._dlgDetail, this._dlgConfirm]) if (dlg.open) dlg.close();
    const ev = new Event("hass-more-info", { bubbles: true, composed: true });
    ev.detail = { entityId };
    this.dispatchEvent(ev);
  }

  _requestToggle(pos) {
    const s = this._model && this._model.byPos.get(pos);
    if (!s || s.kind !== "smart" || !s.roles.power || s.vis === "pending") return;
    const target = s.switchOn ? "off" : "on";
    // Gen1 breakers can be tripped remotely but not reset — asking the cloud
    // to turn one on silently does nothing, so explain instead.
    if (target === "on" && !s.canRemoteOn) {
      this._openConfirm({ pos, target, blocked: true });
      return;
    }
    if (!this._config.confirm) {
      this._switch(s, target);
      return;
    }
    this._openConfirm({ pos, target, blocked: false });
  }

  _openConfirm(c) {
    const s = this._model.byPos.get(c.pos);
    if (!s) return;
    this._confirm = c;
    const t = this._t;
    const off = c.target === "off";
    const where = `${this._where(s)}${s.rating ? ` · ${s.rating} A` : ""}`;
    let title;
    let body;
    let ok;
    if (c.blocked) {
      title = t("card.confirm.blocked_title", { name: s.name });
      body = t("card.confirm.blocked_body");
      ok = t("card.action.got_it");
    } else {
      title = t(off ? "card.confirm.turn_off_title" : "card.confirm.turn_on_title", { name: s.name });
      body = t(off ? "card.confirm.turn_off_body" : "card.confirm.turn_on_body");
      if (off && !s.canRemoteOn) body += ` ${t("card.confirm.gen1_off_warning")}`;
      ok = t(off ? "card.action.turn_off" : "card.action.turn_on");
    }
    this._dlgConfirm.querySelector(".dlg-in").innerHTML = `
      <div class="cf">
        <div class="cf-art" data-vis="${esc(s.vis)}">${this._heroHtml(s, false)}</div>
        <div class="cf-txt">
          <div class="cf-where">${esc(where)}</div>
          <h2 class="cf-title" id="ldp-cf-title">${esc(title)}</h2>
          <p class="cf-body">${esc(body)}</p>
        </div>
      </div>
      <div class="cf-acts">
        ${c.blocked ? "" : `<button type="button" class="btn" data-act="c-cancel">${esc(t("card.action.cancel"))}</button>`}
        <button type="button" class="btn ${c.blocked ? "btn--tonal" : off ? "btn--danger" : "btn--primary"}" data-act="c-ok" autofocus>${esc(ok)}</button>
      </div>`;
    if (!this._dlgConfirm.open) this._dlgConfirm.showModal();
  }

  _confirmOk() {
    const c = this._confirm;
    this._dlgConfirm.close();
    if (!c || c.blocked) return;
    const s = this._model && this._model.byPos.get(c.pos);
    if (s) this._switch(s, c.target);
  }

  _switch(s, target) {
    const entityId = s.roles.power;
    this._pending.set(entityId, { target, since: Date.now() });
    this._errors.delete(s.position);
    const t = setTimeout(() => {
      this._timers.delete(t);
      this._update(true);
    }, 31000);
    this._timers.add(t);
    Promise.resolve(this._hass.callService("switch", target === "on" ? "turn_on" : "turn_off", { entity_id: entityId })).catch((err) => {
      this._pending.delete(entityId);
      this._errors.set(s.position, { text: this._t("card.state.switch_failed"), until: Date.now() + 8000 });
      console.error("ldata-panel-card: switching failed", err);
      const t2 = setTimeout(() => {
        this._timers.delete(t2);
        this._update(true);
      }, 8100);
      this._timers.add(t2);
      this._update(true);
    });
    this._update(true);
  }

  _openSubPanel(deviceId, name) {
    if (!deviceId) return;
    const inner = this._dlgSub.querySelector(".dlg-in");
    inner.innerHTML = `
      <div class="sub-h">
        <h2 class="sub-t" id="ldp-sub-title">${esc(name || this._t("card.name.sub_panel"))}</h2>
        <button type="button" class="icon-btn" data-act="s-close" aria-label="${esc(this._t("card.action.close"))}" autofocus>${icon("close")}</button>
      </div>
      <div class="sub-b"></div>`;
    const card = document.createElement("ldata-panel-card");
    card.setConfig({
      device_id: deviceId,
      title: name || undefined,
      appearance: this._config.appearance,
      confirm: this._config.confirm,
    });
    card.hass = this._hass;
    inner.querySelector(".sub-b").appendChild(card);
    this._subCard = card;
    if (!this._dlgSub.open) this._dlgSub.showModal();
  }

  // ── Detail sheet ───────────────────────────────────────────────────

  // Upright product shot of one breaker, used in the dialogs.
  _heroHtml(s, interactive) {
    const smart = s.kind === "smart";
    const two = s.poles === 2;
    const w = two ? G.hero.w2 : G.hero.w1;
    const cx = two ? 1.57 : 0.57; // centre of the pole that carries the rocker
    const y = (d) => (G.hero.top + d) / G.hero.h;
    const rocker =
      interactive && smart && s.roles.power && this._config.toggle
        ? `<button type="button" class="rk" data-act="toggle" data-pos="${s.position}" role="switch" aria-checked="false" aria-label="${esc(
            this._t("card.label.breaker_switch", { name: s.name })
          )}" style="left:${pct((cx - 0.49) / w)};width:${pct(0.98 / w)};top:${pct(y(G.cav[0] - 0.05))};height:${pct(
            (G.cav[1] - G.cav[0] + 0.1) / G.hero.h
          )}"></button>`
        : "";
    return `<div class="hero hero--${s.poles}p${smart ? "" : " hero--std"}" data-led="${esc(s.led || "off")}">
        <img class="hero-img" alt="" draggable="false" src="${art(`hero-${s.poles}${smart ? "s" : "t"}-${s.handle || "on"}`)}">
        ${s.rating ? ratingSvg(w, G.hero.h, cx + G.rating.x, G.hero.top + G.rating.d, 0, String(s.rating), G.rating.size) : ""}
        ${smart ? `<i class="led" style="left:${pct((cx + G.led.x) / w)};top:${pct(y(G.led.d))}"></i>` : ""}
        ${rocker}
      </div>`;
  }

  _buildDetail() {
    const s = this._model && this._model.byPos.get(this._detailPos);
    const inner = this._dlgDetail.querySelector(".dlg-in");
    this._detailRows = [];
    if (!s) {
      if (this._dlgDetail.open) this._dlgDetail.close();
      return;
    }
    const scroll = inner.scrollTop;
    const t = this._t;
    const where = this._where(s);
    const r = s.roles || {};
    const statusAttr = (r.status && this._hass.states[r.status] && this._hass.states[r.status].attributes) || {};
    const leg = s.poles === 2 ? t("card.detail.both_legs") : statusAttr.leg ? t("card.detail.leg", { leg: statusAttr.leg }) : null;

    const chips = [
      s.kind === "smart" ? `<span class="chip chip--state" data-d="state"></span>` : "",
      s.rating ? `<span class="chip">${esc(s.rating)} A</span>` : "",
      `<span class="chip">${esc(t(s.poles === 2 ? "card.detail.two_pole" : "card.detail.one_pole"))}</span>`,
      leg ? `<span class="chip">${esc(leg)}</span>` : "",
      s.model ? `<span class="chip">${esc(s.model)}</span>` : "",
    ].join("");

    let body = "";
    if (s.kind === "dumb") {
      body = `
        <section class="sec">
          <p class="note">${icon("info")}<span>${esc(t("card.detail.standard_breaker"))}</span></p>
          <p class="note note--muted"><span>${this._html("card.detail.standard_breaker_hint", { option: "<code>sub_panels</code>" })}</span></p>
        </section>`;
    } else {
      body = this._detailControlsHtml(s) + this._detailLiveHtml(s) + this._detailSectionsHtml(s);
    }

    inner.innerHTML = `
      <header class="dh">
        <div class="dh-art" data-vis="unknown">${this._heroHtml(s, true)}</div>
        <div class="dh-txt">
          <div class="dh-where">${esc(where)}</div>
          <h2 class="dh-name" id="ldp-detail-name">${esc(s.name)}</h2>
          <div class="chips">${chips}</div>
        </div>
        <button type="button" class="icon-btn dh-x" data-act="d-close" aria-label="${esc(t("card.action.close"))}" autofocus>${icon("close")}</button>
      </header>
      <div class="dlg-body">${body}</div>
      <footer class="dlg-foot">
        ${s.deviceId ? `<button type="button" class="btn btn--text" data-act="d-device" data-device="${esc(s.deviceId)}">${icon("open")}<span>${esc(t("card.action.device_page"))}</span></button>` : "<span></span>"}
        <button type="button" class="btn btn--tonal" data-act="d-close">${esc(t("card.action.close"))}</button>
      </footer>`;
    inner.scrollTop = scroll;

    // Index value cells for patching.
    for (const el of inner.querySelectorAll("[data-row]")) {
      const def = this._detailRowDefs[Number(el.dataset.row)];
      if (def) this._detailRows.push({ el, def, cache: {} });
    }
    this._detailEls = {};
    for (const el of inner.querySelectorAll("[data-d]")) this._detailEls[el.dataset.d] = el;
    this._detailCache = {};
  }

  _detailControlsHtml(s) {
    const r = s.roles;
    const t = this._t;
    const option = (key) => `<b>${esc(t(key))}</b>`;
    const power = r.power
      ? `<div class="ctl">
           <div class="ctl-i">${icon("power", "ic ctl-ic")}<div><div class="ctl-t">${esc(t("card.detail.breaker_power"))}</div><div class="ctl-s" data-d="pstate"></div></div></div>
           <button type="button" class="btn btn--power" data-act="d-power" data-d="pbtn"></button>
         </div>
         <div class="ctl-confirm" data-d="pconfirm" hidden>
           <div class="ctl-q" data-d="pq"></div>
           <div class="ctl-acts">
             <button type="button" class="btn" data-act="d-cancel">${esc(t("card.action.cancel"))}</button>
             <button type="button" class="btn btn--danger" data-act="d-confirm" data-d="pok"></button>
           </div>
         </div>
         <div class="note note--muted" data-d="pnote" hidden></div>`
      : `<div class="note note--muted">${icon("info")}<span>${this._html("card.detail.control_disabled", {
          option: option("card.detail.option_breaker_control"),
        })}</span></div>`;
    const blink = r.blink
      ? `<div class="ctl">
           <div class="ctl-i"><span class="ctl-led" data-d="bled"></span><div><div class="ctl-t">${esc(t("card.detail.identify"))}</div><div class="ctl-s">${esc(
          t("card.detail.identify_hint")
        )}</div></div></div>
           <button type="button" class="tgl" role="switch" aria-checked="false" aria-label="${esc(t("card.detail.blink_led"))}" data-act="d-blink" data-d="blink"><i></i></button>
         </div>`
      : `<div class="note note--muted">${icon("info")}<span>${this._html("card.detail.identify_disabled", {
          option: option("card.detail.option_identify"),
        })}</span></div>`;
    return `<section class="sec sec--ctl"><h3 class="sec-t">${esc(t("card.detail.controls"))}</h3>${power}${blink}</section>`;
  }

  _detailLiveHtml(s) {
    const r = s.roles || (s.link && s.link.roles) || {};
    const tile = (label, key, eid) =>
      `<button type="button" class="tile" data-act="more" data-eid="${esc(eid || "")}" ${eid ? "" : "disabled"}>
         <span class="tile-l">${esc(label)}</span><span class="tile-v" data-d="${key}">—</span>
       </button>`;
    const t = this._t;
    return `
      <section class="sec">
        <h3 class="sec-t">${esc(t("card.detail.live"))}</h3>
        <div class="tiles">
          ${tile(t("card.detail.power"), "w", r.watts)}
          ${tile(t("card.detail.current"), "a", r.amps)}
          <div class="tile tile--load">
            <span class="tile-l">${esc(t("card.detail.load"))}</span><span class="tile-v" data-d="load">—</span>
            <span class="meterbar"><i data-d="loadbar"></i></span>
          </div>
        </div>
      </section>`;
  }

  _detailSectionsHtml(s) {
    const r = s.roles;
    const is2p = s.poles === 2;
    const d = (key, vars) => this._t(`card.detail.${key}`, vars);
    const yesNo = (v) => (v === true ? d("yes") : v === false ? d("no") : "—");
    const raw = (v) => this._raw(v);
    const sections = [
      [
        d("energy"),
        [
          { label: d("today"), eid: r.dailyConsumption },
          { label: d("today_import"), eid: r.dailyImport },
          { label: d("lifetime"), eid: r.consumption },
          { label: d("lifetime_import"), eid: r.import },
        ],
      ],
      [
        d("protection"),
        [
          { label: this._t("card.alarm.over_current"), eid: r.overCurrent, kind: "problem" },
          { label: this._t("card.alarm.over_voltage"), eid: r.overVoltage, kind: "problem" },
          { label: this._t("card.alarm.under_voltage"), eid: r.underVoltage, kind: "problem" },
          { label: d("operational_state"), eid: r.operationalState, kind: "opstate" },
        ],
      ],
      [
        d("diagnostics"),
        [
          { label: d("breaker_state"), eid: r.breakerState, kind: "raw" },
          is2p ? { label: d("second_pole"), eid: r.breakerState, attr: "second_pole_state", fmt: raw } : null,
          { label: d("remote_state"), eid: r.breakerState, attr: "remote_state", fmt: raw },
          { label: d("previous_state"), eid: r.breakerState, attr: "previous_state", fmt: raw },
          { label: d("change_reason"), eid: r.breakerState, attr: "change_reason", fmt: raw },
          { label: d("circuit_type"), eid: r.breakerState, attr: "branch_type", fmt: (v) => (v ? String(v) : d("not_set")) },
          { label: d("critical"), eid: r.breakerState, attr: "critical", fmt: yesNo },
          { label: d("locked"), eid: r.breakerState, attr: "locked", fmt: yesNo },
          { label: d("meter_chip"), eid: r.breakerState, attr: "meter_chip_ok", fmt: (v) => (v === true ? d("ok") : v === false ? d("fault") : "—"), tone: (v) => (v === false ? "bad" : "") },
          { label: d("bluetooth"), eid: r.ble },
        ],
      ],
      [
        d("device"),
        [
          { label: d("model"), eid: r.status, attr: "model" },
          { label: d("rating"), eid: r.status, attr: "rating", fmt: (v) => (v != null ? `${v} A` : "—") },
          { label: d("remote_reset"), eid: r.status, attr: "canRemoteOn", fmt: (v) => d(v === true ? "remote_reset_yes" : "remote_reset_no") },
          { label: d("firmware"), eid: r.status, attr: "firmware" },
          { label: d("hardware"), eid: r.status, attr: "hardware" },
          { label: d("serial"), eid: r.status, attr: "serialNumber" },
          { label: d("status"), eid: r.status, kind: "onoff" },
        ],
      ],
    ];
    const others = (s.others || []).map((eid) => ({ label: this._friendly(eid, s.name), eid }));
    if (others.length) sections.push([d("other_entities"), others]);

    this._detailRowDefs = [];
    let html = "";
    for (const [title, rows] of sections) {
      const present = rows.filter((row) => row && row.eid);
      if (!present.length) continue;
      html += `<section class="sec"><h3 class="sec-t">${esc(title)}</h3><div class="rows">`;
      for (const row of present) {
        const idx = this._detailRowDefs.push(row) - 1;
        html += `<button type="button" class="row" data-act="more" data-eid="${esc(row.eid)}">
            <span class="row-l">${esc(row.label)}</span><span class="row-v" data-row="${idx}">—</span>${icon("chevron", "ic row-c")}
          </button>`;
      }
      html += "</div></section>";
    }
    return html;
  }

  _friendly(eid, deviceName) {
    const s = this._hass.states[eid];
    let name = (s && s.attributes && s.attributes.friendly_name) || eid;
    if (deviceName && name.startsWith(`${deviceName} `)) name = name.slice(deviceName.length + 1);
    return name;
  }

  _fmtState(s) {
    if (!s) return "—";
    if (s.state === "unavailable") return this._t("card.state.unavailable");
    if (s.state === "unknown") return this._t("card.state.unknown");
    if (typeof this._hass.formatEntityState === "function") {
      try {
        return this._hass.formatEntityState(s);
      } catch (_e) {
        /* fall through */
      }
    }
    const unit = s.attributes && s.attributes.unit_of_measurement;
    const n = numOrNull(s.state);
    const v = n !== null ? this._nf(n % 1 === 0 ? 0 : 2).format(n) : s.state;
    return unit ? `${v} ${unit}` : v;
  }

  _patchDetail() {
    const s = this._model && this._model.byPos.get(this._detailPos);
    if (!s) {
      if (this._dlgDetail.open) this._dlgDetail.close();
      return;
    }
    const els = this._detailEls || {};
    const c = this._detailCache || (this._detailCache = {});
    const st = this._hass.states;
    const hero = this._dlgDetail.querySelector(".hero");
    if (hero) {
      this._set(c, "art", `hero-${s.poles}${s.kind === "smart" ? "s" : "t"}-${s.handle || "on"}`, (v) => (hero.querySelector(".hero-img").src = art(v)));
      this._set(c, "led", s.led || "off", (v) => (hero.dataset.led = v));
      const rk = hero.querySelector("button.rk");
      if (rk) {
        this._set(c, "rk", `${s.switchOn}|${s.vis}|${s.switchAvailable}`, () => {
          rk.setAttribute("aria-checked", String(!!s.switchOn));
          rk.disabled = !s.switchAvailable || s.vis === "pending";
          rk.title = this._t(s.switchOn ? "card.action.turn_off_name" : "card.action.turn_on_name", { name: s.name });
        });
      }
    }
    if (s.kind !== "smart") return;

    const t = this._t;
    const word = t(
      {
        on: "card.state.on",
        off: "card.state.off",
        "remote-off": "card.state.off_remote",
        tripped: "card.state.tripped",
        unavailable: "card.state.unavailable",
        pending: s.pendingTarget === "on" ? "card.state.switching_on" : "card.state.switching_off",
      }[s.vis] || "card.state.unknown"
    );
    if (els.state) {
      this._set(c, "state", `${s.vis}|${word}`, () => {
        els.state.textContent = word;
        els.state.dataset.vis = s.vis;
      });
    }

    // Controls
    if (els.pbtn) {
      const off = s.switchOn;
      const blocked = !off && !s.canRemoteOn;
      const key = `${off}|${s.vis}|${s.switchAvailable}|${this._detailConfirm}|${blocked}`;
      this._set(c, "power", key, () => {
        els.pstate.textContent =
          s.vis === "pending"
            ? word
            : s.vis === "tripped"
            ? t("card.detail.power_tripped_hint")
            : off
            ? t("card.detail.power_on_hint")
            : s.vis === "remote-off"
            ? t("card.detail.power_remote_off_hint")
            : t("card.state.off");
        els.pbtn.textContent = t(off ? "card.action.turn_off" : "card.action.turn_on");
        els.pbtn.classList.toggle("btn--danger-outline", off);
        els.pbtn.classList.toggle("btn--primary", !off);
        els.pbtn.disabled = !s.switchAvailable || s.vis === "pending" || blocked;
        els.pconfirm.hidden = !this._detailConfirm;
        els.pbtn.hidden = !!this._detailConfirm;
        // The same question the confirmation dialog asks.
        els.pq.textContent = off
          ? [t("card.confirm.turn_off_title", { name: s.name }), t("card.confirm.turn_off_body"), s.canRemoteOn ? null : t("card.confirm.gen1_off_warning")]
              .filter(Boolean)
              .join(" ")
          : `${t("card.confirm.turn_on_title", { name: s.name })} ${t("card.confirm.turn_on_body")}`;
        els.pok.textContent = t(off ? "card.action.turn_off" : "card.action.turn_on");
        els.pok.className = `btn ${off ? "btn--danger" : "btn--primary"}`;
        els.pnote.hidden = !blocked;
        els.pnote.innerHTML = blocked
          ? `${icon("info")}<span>${esc(t("card.detail.gen1_note"))}</span>`
          : "";
      });
    }
    if (els.blink) {
      this._set(c, "blink", s.blinkOn, (v) => {
        els.blink.setAttribute("aria-checked", String(!!v));
        els.bled.classList.toggle("is-on", !!v);
      });
    }

    // Live
    const w = s.roles.watts ? this._num(s.roles.watts) : null;
    const a = s.roles.amps ? this._num(s.roles.amps) : null;
    if (els.w) this._set(c, "w", w, () => (els.w.innerHTML = w === null ? "—" : `${this._nf(0).format(w)}<small>W</small>`));
    if (els.a) this._set(c, "a", a, () => (els.a.innerHTML = a === null ? "—" : `${this._nf(1).format(a)}<small>A</small>`));
    if (els.load) {
      const load = s.rating && a !== null && a >= 0 ? (a / s.rating) * 100 : null;
      this._set(c, "load", load === null ? null : Math.round(load), (v) => {
        els.load.innerHTML = v === null ? "—" : `${v}<small>%</small>`;
        els.loadbar.style.width = v === null ? "0" : `${Math.min(100, Math.max(1, v))}%`;
        els.loadbar.dataset.level = v === null ? "" : v >= 80 ? "high" : v >= 50 ? "warn" : "ok";
      });
    }

    // Rows
    for (const row of this._detailRows || []) {
      const def = row.def;
      const stateObj = st[def.eid];
      let text;
      let tone = "";
      if (!stateObj) text = "—";
      else if (def.attr) {
        const v = stateObj.attributes ? stateObj.attributes[def.attr] : undefined;
        text = def.fmt ? def.fmt(v) : v == null || v === "" ? "—" : String(v);
        if (def.tone) tone = def.tone(v);
      } else if (stateObj.state === "unavailable" || stateObj.state === "unknown") {
        text = t(`card.state.${stateObj.state}`);
      } else if (def.kind === "problem") {
        text = stateObj.state === "on" ? t("card.detail.alarm") : stateObj.state === "off" ? t("card.detail.ok") : this._raw(stateObj.state);
        tone = stateObj.state === "on" ? "bad" : stateObj.state === "off" ? "good" : "";
      } else if (def.kind === "opstate") {
        text = this._raw(stateObj.state);
        tone = stateObj.state === "Normal" ? "good" : "bad";
      } else if (def.kind === "raw") {
        text = this._raw(stateObj.state);
        tone = /trip/i.test(stateObj.state) ? "bad" : "";
      } else if (def.kind === "onoff") {
        text = stateObj.state === "on" ? t("card.state.on") : stateObj.state === "off" ? t("card.state.off") : this._raw(stateObj.state);
      } else text = this._fmtState(stateObj);
      this._set(row.cache, "v", `${tone}|${text}`, () => {
        row.el.textContent = text;
        row.el.dataset.tone = tone;
      });
    }
  }

  _detailPower() {
    const s = this._model && this._model.byPos.get(this._detailPos);
    if (!s || !s.roles.power) return;
    if (!this._config.confirm) {
      this._switch(s, s.switchOn ? "off" : "on");
      return;
    }
    this._detailConfirm = true;
    this._patchDetail();
    const ok = this._detailEls.pok;
    if (ok) ok.focus();
  }

  _detailConfirmed() {
    const s = this._model && this._model.byPos.get(this._detailPos);
    this._detailConfirm = false;
    if (s && s.roles.power) this._switch(s, s.switchOn ? "off" : "on");
    else this._patchDetail();
  }

  _toggleBlink() {
    const s = this._model && this._model.byPos.get(this._detailPos);
    if (!s || !s.roles.blink) return;
    this._hass.callService("switch", s.blinkOn ? "turn_off" : "turn_on", { entity_id: s.roles.blink });
  }
}

// ── Styles ───────────────────────────────────────────────────────────────

const CARD_CSS = `
:host {
  display: block;
  /* The panel is drawn as it hangs on the wall: odd spaces on the left, in
     every language. No right-to-left translation ships yet; one would want
     the dialogs mirrored, not the panel. */
  direction: ltr;
  /* Set from the card's width in _onResize. */
  --u: 30px; /* one breaker space */
  --k: 0.62; /* thickness of the door surround (1 on wide cards) */
  --edge: 0.26; /* cover outside the labels */
  --fs: 12px; /* header type */
  --ldp-focus: var(--primary-color, #03a9f4);
  /* Print on the painted steel. */
  --ink: #26292b;
  --ink-2: #565a5e;
  --ink-3: #84888b;
  --ink-bad: #c3220f;
  --ink-warn: #a35f00;
  --ink-link: #1b5aa0;
}

ha-card {
  display: block;
  background: none;
  border: none;
  box-shadow: none;
  overflow: visible;
  padding: 0;
}
.content { display: block; }
.stage {
  display: flex;
  justify-content: center;
  padding: 4px 3px 16px;
  font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
  line-height: 1.2;
  -webkit-font-smoothing: antialiased;
}
button { font: inherit; }

/* ── Cover ──────────────────────────────────────────────────────────
   Everything from here to the dialogs is artwork placement. Lengths are
   multiples of --u because the images are: see G in the script. */
.cover {
  position: relative;
  isolation: isolate;
  box-sizing: border-box;
  width: 100%;
  max-width: calc(var(--u) * (7.282 + 1.56 * var(--k) + 2 * var(--edge)) + 440px);
  border-radius: calc(var(--u) * 0.05);
  box-shadow: 0 calc(var(--u) * 0.06) calc(var(--u) * 0.16) rgba(0, 0, 0, 0.34), 0 calc(var(--u) * 0.3) calc(var(--u) * 0.8) rgba(0, 0, 0, 0.18);
  color: var(--ink);
}
/* The plate itself: a rendered sample stretched as a nine-slice. */
.cover::before {
  content: "";
  position: absolute;
  inset: 0;
  z-index: -1;
  box-sizing: border-box;
  border: calc(var(--u) * var(--k) * 0.32) solid transparent;
  border-image: var(--art-cover) 48 fill / 1 / 0 stretch;
  pointer-events: none;
}
/* Light falls from above: the top of a tall panel is a touch brighter. */
.cover::after {
  content: "";
  position: absolute;
  inset: 0;
  z-index: 6;
  border-radius: inherit;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.07) 0, rgba(255, 255, 255, 0) 24%, rgba(0, 0, 0, 0) 62%, rgba(0, 0, 0, 0.055) 100%);
  pointer-events: none;
}
/* Dark themes: the cover stays white, as the real one is, and only loses its
   glare. Much below 0.9 the white turns gray and the panel looks faded. */
:host([appearance="dark"]) .cover {
  filter: brightness(0.92) contrast(1.05) saturate(0.92);
  box-shadow: 0 calc(var(--u) * 0.06) calc(var(--u) * 0.16) rgba(0, 0, 0, 0.6), 0 calc(var(--u) * 0.3) calc(var(--u) * 0.8) rgba(0, 0, 0, 0.4);
}

.screw {
  position: absolute;
  z-index: 2;
  width: calc(var(--u) * 0.72);
  height: calc(var(--u) * 0.72);
  /* the head sits at 50% / 41.7% of the sprite; the rest is its shadow */
  margin: calc(var(--u) * -0.3) 0 0 calc(var(--u) * -0.36);
  background: var(--art-screw-a) center / 100% 100% no-repeat;
  pointer-events: none;
}
.screw--tr, .screw--bl { background-image: var(--art-screw-b); }
.screw--tl, .screw--bl { left: calc(var(--u) * (0.32 * var(--k) + 0.5)); }
.screw--tr, .screw--br { right: calc(var(--u) * (0.32 * var(--k) + 0.5 - 0.36)); margin-left: 0; }
.screw--tl, .screw--tr { top: calc(var(--u) * (0.32 * var(--k) + 0.5)); }
.screw--bl, .screw--br { bottom: calc(var(--u) * (0.32 * var(--k) + 0.5 - 0.42)); margin-top: 0; }

/* ── Header: printed on the cover above the door ───────────────── */
.head {
  position: relative;
  z-index: 1;
  display: flex;
  flex-direction: column;
  gap: 0.6em;
  padding: calc(var(--u) * (0.32 * var(--k) + 0.2)) calc(var(--u) * (0.32 * var(--k) + 0.34)) calc(var(--u) * 0.12);
  font-size: var(--fs);
}
/* the first line sits between the two top screws */
.head-top { display: flex; align-items: center; justify-content: space-between; gap: 1em; min-height: calc(var(--u) * 0.62); padding: 0 calc(var(--u) * 0.72); }
.plate {
  min-width: 0;
  font-size: 1.2em;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.inds { display: flex; flex: none; gap: 0.95em; }
.ind {
  all: unset;
  display: inline-flex;
  align-items: center;
  gap: 0.38em;
  cursor: pointer;
  color: var(--ink-2);
  font-size: 0.72em;
  font-weight: 700;
  letter-spacing: 0.11em;
  text-transform: uppercase;
}
.ind b { font-weight: inherit; }
.ind:focus-visible, .m-main:focus-visible, .m-cell:focus-visible, .lbl:focus-visible {
  outline: 2px solid var(--ldp-focus);
  outline-offset: 2px;
  border-radius: 3px;
}
/* Pilot lights set into the cover. */
.pilot {
  width: 0.72em;
  height: 0.72em;
  border-radius: 50%;
  background: radial-gradient(circle at 38% 32%, #8d9296, #54595c 70%);
  box-shadow: 0 0 0 0.09em rgba(60, 62, 64, 0.55), 0 0.08em 0.06em rgba(255, 255, 255, 0.85);
}
.ind[data-state="on"] .pilot {
  background: radial-gradient(circle at 42% 36%, #eafff0 0, #46e06f 34%, #0f9a39 78%);
  box-shadow: 0 0 0 0.09em rgba(20, 70, 35, 0.6), 0 0 0.55em 0.1em rgba(60, 220, 105, 0.75);
}
.ind[data-state="off"] .pilot {
  background: radial-gradient(circle at 42% 36%, #ffe9e4 0, #ff5a3c 34%, #b81d08 78%);
  box-shadow: 0 0 0 0.09em rgba(90, 20, 10, 0.6), 0 0 0.55em 0.1em rgba(255, 80, 50, 0.7);
}
.ind[data-h="fw"][data-state="off"] { display: none; }
.ind[data-h="fw"][data-state="on"] .pilot {
  background: radial-gradient(circle at 42% 36%, #fff6dd 0, #ffb52e 34%, #c47a00 78%);
  box-shadow: 0 0 0 0.09em rgba(90, 55, 0, 0.6), 0 0 0.55em 0.1em rgba(255, 180, 50, 0.75);
}
.bars { display: inline-flex; align-items: flex-end; gap: 0.1em; height: 0.9em; }
.bars i { width: 0.2em; background: rgba(60, 64, 67, 0.28); border-radius: 0.04em; }
.bars i:nth-child(1) { height: 30%; }
.bars i:nth-child(2) { height: 53%; }
.bars i:nth-child(3) { height: 76%; }
.bars i:nth-child(4) { height: 100%; }
.ind[data-bars="1"] .bars i:nth-child(-n + 1),
.ind[data-bars="2"] .bars i:nth-child(-n + 2),
.ind[data-bars="3"] .bars i:nth-child(-n + 3),
.ind[data-bars="4"] .bars i:nth-child(-n + 4) { background: var(--ink); }

.meter { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: end; gap: 0.55em 2em; }
:host([compact]) .meter { grid-template-columns: minmax(0, 1fr); }
.m-main { all: unset; display: inline-grid; grid-template-columns: auto auto; justify-content: start; justify-self: start; column-gap: 0.55em; align-items: baseline; cursor: pointer; }
.m-main:disabled { cursor: default; }
.m-main .m-cap { grid-column: 1 / -1; }
.m-cap {
  color: var(--ink-3);
  font-size: 0.66em;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  /* A caption that is longer in another language takes a second line; the
     readings in that row stay level (see .m-cell). */
  max-width: 100%;
  overflow-wrap: anywhere;
}
.m-big {
  font-size: 2.15em;
  font-weight: 300;
  line-height: 1.05;
  letter-spacing: -0.015em;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.m-amps { color: var(--ink-2); font-size: 0.98em; font-variant-numeric: tabular-nums; white-space: nowrap; }
.m-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(8.4em, 1fr)); gap: 0.5em 0; min-width: 0; }
.m-cell {
  all: unset;
  display: flex;
  flex-direction: column;
  justify-content: flex-end;
  gap: 0.12em;
  min-width: 0;
  padding: 0 0.6em;
  border-left: 1px solid rgba(40, 44, 47, 0.2);
  cursor: pointer;
}
.m-val { font-size: 0.95em; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.m-alarm { grid-column: 1 / -1; display: flex; align-items: center; gap: 0.4em; color: var(--ink-bad); font-size: 0.92em; font-weight: 700; }
.m-alarm[hidden] { display: none; }
.m-alarm .ic { width: 1.2em; height: 1.2em; }
@media (hover: hover) {
  .ind:hover b, .m-main:hover .m-big, .m-cell:hover .m-val { text-decoration: underline; text-decoration-thickness: 1px; text-underline-offset: 0.18em; }
}

/* ── Door surround, dead front and breakers ────────────────────── */
.body {
  position: relative;
  z-index: 1;
  display: grid;
  /* label | surround + dead front edge | breakers | middle strip | breakers | edge | label */
  grid-template-columns:
    minmax(0, 1fr)
    calc(var(--u) * (0.78 * var(--k) + 0.08))
    calc(var(--u) * 3.136)
    calc(var(--u) * 0.85)
    calc(var(--u) * 3.136)
    calc(var(--u) * (0.78 * var(--k) + 0.08))
    minmax(0, 1fr);
  grid-template-rows:
    calc(var(--u) * (0.78 * var(--k) + 0.25) + var(--mainh, 0px))
    calc(var(--u) * 0.2)
    repeat(var(--rows), var(--u))
    calc(var(--u) * 0.2)
    calc(var(--u) * (0.78 * var(--k) + 0.25));
  padding: 0 calc(var(--u) * var(--edge));
}
.has-main { --mainh: calc(var(--u) * 2.86); }
/* The embossed surround, door opening and dead front rim: one nine-slice.
   Its middle is the flat dead front, so it also paints behind the breakers. */
.well {
  grid-column: 2 / 7;
  grid-row: 1 / -1;
  box-sizing: border-box;
  border: calc(var(--u) * var(--k) * 1.34) solid transparent;
  border-image: var(--art-frame) 201 fill / 1 / 0 stretch;
  pointer-events: none;
}
/* What shows between two breakers is the dark inside of the panel. */
.gap {
  grid-row: 2 / -2;
  margin: calc(var(--u) * 0.19) calc(var(--u) * 0.108);
  background: #151515;
}
.gap--l { grid-column: 3; }
.gap--r { grid-column: 5; }
.cap { display: block; width: 100%; height: 100%; pointer-events: none; user-select: none; }
.cap--tl { grid-column: 3; grid-row: 2; }
.cap--tr { grid-column: 5; grid-row: 2; }
.cap--bl { grid-column: 3; grid-row: -3; }
.cap--br { grid-column: 5; grid-row: -3; }

.bkr { position: relative; }
.bkr--left { grid-column: 3; }
.bkr--right { grid-column: 5; }
/* Each breaker image is one space tall plus a strip that holds only the
   shadow it casts on the space below. */
.sp {
  position: absolute;
  left: 0;
  top: 0;
  display: block;
  width: 100%;
  height: calc(100% + var(--u) * 0.42);
  pointer-events: none;
  user-select: none;
}
.bkr[data-vis="unavailable"]::after {
  content: "";
  position: absolute;
  inset: 3% 4.4%;
  background: rgba(240, 240, 240, 0.62);
  pointer-events: none;
}
.hit { all: unset; position: absolute; inset: 0; cursor: pointer; }
.rk {
  all: unset;
  position: absolute;
  box-sizing: border-box;
  cursor: pointer;
  border-radius: calc(var(--u) * 0.1);
  -webkit-tap-highlight-color: transparent;
}
.rk:disabled { cursor: not-allowed; }
.rk:focus-visible { outline: 2px solid var(--ldp-focus); outline-offset: -1px; }
@media (hover: hover) {
  .rk:hover:not(:disabled) {
    box-shadow: inset 0 0 0 1.5px color-mix(in srgb, var(--ldp-focus) 75%, transparent), 0 0 calc(var(--u) * 0.3) color-mix(in srgb, var(--ldp-focus) 40%, transparent);
  }
}
.rk:active:not(:disabled) { background: rgba(0, 0, 0, 0.06); }

/* Amp rating printed on the breaker. */
.ink { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; pointer-events: none; mix-blend-mode: multiply; }
.ink text { font-family: Arial, Helvetica, sans-serif; fill: #3c3c3c; fill-opacity: 0.88; }
.bkr--dumb .ink text, .bkr--link .ink text, .hero--std .ink text, .main .ink text { fill: #858585; }

/* The breaker's status LED, when lit: lens plus bloom. */
.led {
  position: absolute;
  width: calc(var(--u) * 0.6);
  height: calc(var(--u) * 0.6);
  margin: calc(var(--u) * -0.3) 0 0 calc(var(--u) * -0.3);
  border-radius: 50%;
  background: radial-gradient(circle, #fff 0, #ffe1da 6%, rgba(255, 74, 46, 0.96) 12%, rgba(255, 56, 32, 0.5) 24%, rgba(255, 44, 26, 0.16) 44%, rgba(255, 44, 26, 0) 66%);
  opacity: 0;
  pointer-events: none;
}
[data-led="on"] > .led { opacity: 1; }
[data-led="blink"] > .led { animation: ldp-blink 1s steps(1, end) infinite; }
@keyframes ldp-blink { 0% { opacity: 1; } 50% { opacity: 0; } }

/* Space numbers, printed down the middle of the dead front. */
.num {
  grid-column: 4;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 calc(var(--u) * 0.02);
  color: #74787b;
  font-size: clamp(6.5px, calc(var(--u) * 0.27), 11.5px);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  pointer-events: none;
}

/* Main breaker, seen through its own opening above the columns. */
.main { position: relative; grid-column: 3 / 6; grid-row: 1; align-self: end; justify-self: center; width: calc(var(--u) * 3.6); height: calc(var(--u) * 2.7); margin-bottom: calc(var(--u) * 0.16); }
.main-sp { position: absolute; inset: 0; display: block; width: 100%; height: 100%; user-select: none; }
.main-cap {
  position: absolute;
  left: calc(100% + var(--u) * 0.12);
  top: 50%;
  transform: translateY(-50%);
  color: var(--ink-2);
  font-size: clamp(8px, calc(var(--u) * 0.3), 12px);
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  white-space: nowrap;
  /* the dead front beside the main breaker, short of the door surround */
  max-width: calc(var(--u) * 1.55);
  overflow: hidden;
  text-overflow: ellipsis;
}
/* a word too long for that (see _fitMainCaption) runs down the breaker's side */
.main-cap--tall {
  max-width: none;
  max-height: calc(var(--u) * 2.6);
  writing-mode: vertical-rl;
  text-overflow: clip;
}

/* ── Circuit directory: printed on the cover beside the door ───── */
.lbl {
  all: unset;
  position: relative;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 0.06em;
  min-width: 0;
  padding: 0 calc(var(--u) * 0.2) calc(var(--u) * 0.04);
  cursor: pointer;
  color: var(--ink);
  font-size: clamp(10px, calc(var(--u) * 0.365), 14.5px);
  line-height: 1.16;
  -webkit-tap-highlight-color: transparent;
}
.lbl--left { grid-column: 1; align-items: flex-end; text-align: right; }
.lbl--right { grid-column: 7; align-items: flex-start; text-align: left; }
.lbl-top { display: flex; align-items: baseline; gap: 0.55em; max-width: 100%; }
.lbl--left .lbl-top { flex-direction: row-reverse; }
.lbl-name { flex: 0 1 auto; min-width: 0; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* a 2-pole breaker's label is two spaces tall: let a long name wrap once */
.lbl--tall .lbl-name { display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; white-space: normal; overflow-wrap: anywhere; }
.lbl-tag { flex: none; color: var(--ink-3); font-size: 0.72em; font-weight: 700; letter-spacing: 0.04em; }
.lbl-tag:empty { display: none; }
.lbl-tag--alarm { align-self: center; display: inline-flex; color: var(--ink-bad); }
.lbl-tag--alarm .ic { width: 1.2em; height: 1.2em; }
.lbl-sub {
  max-width: 100%;
  color: var(--ink-2);
  font-size: 0.84em;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.lbl-sub[data-tone="muted"] { color: var(--ink-3); }
.lbl-sub[data-tone="bad"] { color: var(--ink-bad); font-weight: 700; }
.lbl-sub[data-tone="warn"] { color: var(--ink-warn); font-weight: 600; }
.lbl-sub[data-tone="link"] { color: var(--ink-link); }
.lbl[data-vis="pending"] .lbl-sub { animation: ldp-pulse 1.1s ease-in-out infinite; }
@keyframes ldp-pulse { 50% { opacity: 0.45; } }
.lbl[data-vis="tripped"] .lbl-name, .lbl[data-alarm] .lbl-name { color: var(--ink-bad); }
.lbl[data-vis="unavailable"] .lbl-name { color: var(--ink-3); }
.lbl--link .lbl-name { color: var(--ink-link); }
/* Each entry sits on a ruled line; the line fills with how close the
   circuit runs to its rating. */
.lbl-bar {
  position: absolute;
  left: calc(var(--u) * 0.2);
  right: calc(var(--u) * 0.2);
  bottom: 0;
  height: max(1.5px, calc(var(--u) * 0.045));
  border-radius: 1px;
  background: rgba(30, 34, 37, 0.11);
  overflow: hidden;
}
.lbl-bar i { display: block; width: 0; height: 100%; background: #2f9a4f; transition: width 0.4s ease; }
.lbl--left .lbl-bar i { margin-left: auto; }
.lbl[data-load="warn"] .lbl-bar i { background: #d98d00; }
.lbl[data-load="high"] .lbl-bar i { background: #d5371f; }
.lbl[hot] .lbl-name, .lbl:focus-visible .lbl-name { text-decoration: underline; text-decoration-thickness: 1px; text-underline-offset: 0.16em; }
.bkr[hot] .sp { filter: brightness(1.035); }

.foot { height: calc(var(--u) * (0.32 * var(--k) + 0.86)); }

/* Phones: the rating is on the breaker and in the detail sheet. */
:host([compact]) .lbl-tag:not(.lbl-tag--alarm) { display: none; }
:host([narrow]) .lbl { padding-left: calc(var(--u) * 0.14); padding-right: calc(var(--u) * 0.14); }
:host([narrow]) .lbl-bar { left: calc(var(--u) * 0.14); right: calc(var(--u) * 0.14); }
:host([narrow]) .r-amps { display: none; }
/* three readings to a row, so each has room for its caption */
:host([narrow]) .m-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }

@media (prefers-reduced-motion: reduce) {
  [data-led="blink"] > .led, .lbl[data-vis="pending"] .lbl-sub { animation: none; opacity: 1; }
  .lbl-bar i { transition: none; }
}

/* ── Messages ───────────────────────────────────────────────── */
.msg { padding: 16px; font-size: 14px; color: var(--primary-text-color); background: var(--ha-card-background, var(--card-background-color, #fff)); border-radius: var(--ha-card-border-radius, 12px); border: 1px solid var(--divider-color, #e0e0e0); }
.msg-t { font-weight: 600; margin-bottom: 6px; }
.msg-b { color: var(--secondary-text-color); line-height: 1.45; }
.diags { margin: 8px 0; padding: 8px 10px; border-radius: 8px; background: var(--secondary-background-color, #f5f5f5); font-family: var(--code-font-family, monospace); font-size: 12px; }
.diag--ok { color: var(--success-color, #43a047); }
.diag--bad { color: var(--error-color, #db4437); }

/* ── Dialogs ────────────────────────────────────────────────── */
dialog.dlg {
  padding: 0;
  border: none;
  background: transparent;
  max-width: none;
  max-height: none;
  overflow: visible;
  color: var(--primary-text-color, #1f1f1f);
  font-family: var(--ha-font-family-body, var(--paper-font-body1_-_font-family, Roboto, "Helvetica Neue", Arial, sans-serif));
  font-size: 14px;
  line-height: 1.4;
  -webkit-font-smoothing: antialiased;
}
dialog.dlg::backdrop { background: rgba(0,0,0,.5); }
dialog.dlg[open] .dlg-in { animation: ldp-pop .18s ease-out; }
@keyframes ldp-pop { from { opacity: 0; transform: translateY(8px) scale(.98); } to { opacity: 1; transform: none; } }
.dlg-in {
  box-sizing: border-box;
  width: min(460px, calc(100vw - 20px));
  max-height: calc(100vh - 28px);
  max-height: calc(100dvh - 28px);
  overflow: auto;
  overscroll-behavior: contain;
  background: var(--ha-card-background, var(--card-background-color, #fff));
  border-radius: var(--ha-dialog-border-radius, 20px);
  box-shadow: 0 24px 64px rgba(0,0,0,.35), 0 2px 8px rgba(0,0,0,.2);
}
.dlg--sub .dlg-in { width: min(640px, calc(100vw - 20px)); }
.dlg--confirm .dlg-in { width: min(400px, calc(100vw - 20px)); padding: 20px 20px 16px; }
.ic { width: 20px; height: 20px; fill: currentColor; flex: none; }
.icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border: 0;
  border-radius: 50%;
  background: none;
  color: var(--secondary-text-color, #666);
  cursor: pointer;
}
.icon-btn:hover { background: color-mix(in srgb, var(--primary-text-color, #000) 8%, transparent); color: var(--primary-text-color); }
.icon-btn:focus-visible, .btn:focus-visible, .row:focus-visible, .tile:focus-visible, .tgl:focus-visible { outline: 2px solid var(--primary-color, #03a9f4); outline-offset: 2px; }

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  min-height: 38px;
  padding: 0 16px;
  border-radius: 19px;
  border: 1px solid var(--divider-color, #d0d0d0);
  background: none;
  color: var(--primary-text-color, #1f1f1f);
  font: inherit;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
}
.btn:hover { background: color-mix(in srgb, var(--primary-text-color, #000) 6%, transparent); }
.btn:disabled { opacity: .45; cursor: not-allowed; }
.btn[hidden] { display: none; }
.btn .ic { width: 18px; height: 18px; }
.btn--primary { background: var(--primary-color, #03a9f4); border-color: transparent; color: var(--text-primary-color, #fff); }
.btn--primary:hover { background: color-mix(in srgb, var(--primary-color, #03a9f4) 88%, #000); }
.btn--danger { background: var(--error-color, #db4437); border-color: transparent; color: #fff; }
.btn--danger:hover { background: color-mix(in srgb, var(--error-color, #db4437) 88%, #000); }
.btn--danger-outline { color: var(--error-color, #db4437); border-color: color-mix(in srgb, var(--error-color, #db4437) 55%, transparent); }
.btn--tonal { background: color-mix(in srgb, var(--primary-color, #03a9f4) 14%, transparent); border-color: transparent; color: var(--primary-color, #03a9f4); }
.btn--text { border-color: transparent; color: var(--primary-color, #03a9f4); padding: 0 10px; }

/* Detail header */
.dh {
  position: sticky;
  top: 0;
  z-index: 3;
  display: flex;
  gap: 16px;
  align-items: center;
  padding: 18px 12px 14px 18px;
  background: var(--ha-card-background, var(--card-background-color, #fff));
  border-bottom: 1px solid var(--divider-color, #e5e5e5);
}
.dh-art, .cf-art { flex: none; }
.dh-txt { flex: 1 1 auto; min-width: 0; }
.dh-where, .cf-where { font-size: 12px; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; color: var(--secondary-text-color, #6b6b6b); }
.dh-name { margin: 2px 0 8px; font-size: 20px; line-height: 1.25; font-weight: 600; overflow-wrap: anywhere; }
.dh-x { align-self: flex-start; margin-top: -6px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 24px;
  padding: 0 9px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 500;
  white-space: nowrap;
  background: color-mix(in srgb, var(--primary-text-color, #000) 7%, transparent);
  color: var(--primary-text-color);
}
.chip--state::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: #9aa0a6; }
.chip--state[data-vis="on"]::before { background: #2fb350; box-shadow: 0 0 6px rgba(47,179,80,.7); }
.chip--state[data-vis="tripped"] { color: var(--error-color, #db4437); }
.chip--state[data-vis="tripped"]::before { background: var(--error-color, #db4437); }
.chip--state[data-vis="remote-off"]::before, .chip--state[data-vis="pending"]::before { background: #f0a417; }
.chip--state[data-vis="off"]::before { background: #fff; box-shadow: inset 0 0 0 1px rgba(0,0,0,.35); }

.hero {
  position: relative;
  flex: none;
  /* the product shot is 1.14 x 3.796 inches (2.14 wide for a 2-pole unit) */
  --h: 220px;
  --u: calc(var(--h) / 3.796);
  width: calc(var(--h) * 0.3003);
  height: var(--h);
  filter: drop-shadow(0 5px 6px rgba(0,0,0,.26));
}
.hero--2p { width: calc(var(--h) * 0.5637); }
.hero-img { position: absolute; inset: 0; display: block; width: 100%; height: 100%; user-select: none; }
.cf-art .hero { --h: 150px; }

.dlg-body { padding: 4px 18px 8px; }
.sec { padding: 14px 0 6px; }
.sec + .sec { border-top: 1px solid var(--divider-color, #ececec); }
.sec-t { margin: 0 0 8px; font-size: 12px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: var(--secondary-text-color, #6b6b6b); }
.ctl { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 0; }
.ctl-i { display: flex; align-items: center; gap: 12px; min-width: 0; }
.ctl-ic { width: 22px; height: 22px; color: var(--secondary-text-color); }
.ctl-i > div { min-width: 0; }
.ctl-t { font-weight: 500; overflow-wrap: anywhere; }
.ctl-s { font-size: 13px; color: var(--secondary-text-color, #6b6b6b); overflow-wrap: anywhere; }
.ctl-confirm {
  margin: 4px 0 8px;
  padding: 12px;
  border-radius: 12px;
  background: color-mix(in srgb, var(--error-color, #db4437) 9%, transparent);
}
.ctl-confirm[hidden] { display: none; }
.ctl-q { margin-bottom: 10px; overflow-wrap: anywhere; }
.ctl-acts, .cf-acts { display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap; }
.ctl-led {
  width: 14px;
  height: 14px;
  margin: 0 4px;
  border-radius: 50%;
  background: radial-gradient(circle at 40% 35%, #a0a4a8, #5d6165 70%);
  box-shadow: inset 0 1px 2px rgba(0,0,0,.5);
  flex: none;
}
.ctl-led.is-on { background: radial-gradient(circle at 40% 35%, #ffe9e4, #ff5a3c 45%, #c2260e); box-shadow: 0 0 8px rgba(255,90,60,.9); animation: ldp-alarm 1s ease-in-out infinite; }
.tgl {
  position: relative;
  flex: none;
  width: 46px;
  height: 26px;
  border: 0;
  border-radius: 13px;
  background: color-mix(in srgb, var(--primary-text-color, #000) 22%, transparent);
  cursor: pointer;
  transition: background .15s ease;
}
.tgl i {
  position: absolute;
  top: 3px;
  left: 3px;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: #fff;
  box-shadow: 0 1px 3px rgba(0,0,0,.35);
  transition: transform .15s ease;
}
.tgl[aria-checked="true"] { background: var(--primary-color, #03a9f4); }
.tgl[aria-checked="true"] i { transform: translateX(20px); }
.note { display: flex; gap: 10px; align-items: flex-start; margin: 6px 0; font-size: 13px; line-height: 1.45; }
.note > span { min-width: 0; overflow-wrap: anywhere; }
.note[hidden] { display: none; }
.note .ic { width: 18px; height: 18px; margin-top: 1px; color: var(--secondary-text-color); }
.note--muted { color: var(--secondary-text-color, #6b6b6b); }
code { font-family: var(--code-font-family, monospace); font-size: .92em; padding: 1px 4px; border-radius: 4px; background: color-mix(in srgb, var(--primary-text-color, #000) 7%, transparent); }

.tiles { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
.tile {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  min-width: 0;
  padding: 10px 12px 12px;
  border-radius: 12px;
  border: 0;
  background: color-mix(in srgb, var(--primary-text-color, #000) 5%, transparent);
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.tile:disabled, .tile--load { cursor: default; }
button.tile:hover:not(:disabled) { background: color-mix(in srgb, var(--primary-text-color, #000) 9%, transparent); }
.tile-l { font-size: 12px; color: var(--secondary-text-color, #6b6b6b); }
.tile-v { font-size: 22px; font-weight: 500; font-variant-numeric: tabular-nums; white-space: nowrap; }
.tile-v small { font-size: 13px; font-weight: 500; margin-left: 3px; color: var(--secondary-text-color); }
.meterbar { display: block; width: 100%; height: 4px; margin-top: 6px; border-radius: 2px; background: color-mix(in srgb, var(--primary-text-color, #000) 10%, transparent); overflow: hidden; }
.meterbar i { display: block; height: 100%; width: 0; border-radius: inherit; background: #2fb350; transition: width .5s ease; }
.meterbar i[data-level="warn"] { background: #f0a417; }
.meterbar i[data-level="high"] { background: var(--error-color, #db4437); }

.rows { display: flex; flex-direction: column; }
.row {
  display: flex;
  align-items: center;
  gap: 10px;
  min-height: 40px;
  margin: 0 -8px;
  padding: 0 4px 0 8px;
  border: 0;
  border-radius: 10px;
  background: none;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.row:hover { background: color-mix(in srgb, var(--primary-text-color, #000) 5%, transparent); }
.row-l { flex: 1 1 auto; min-width: 0; color: var(--primary-text-color); }
.row-v { flex: 0 1 auto; min-width: 0; text-align: right; color: var(--secondary-text-color, #6b6b6b); font-variant-numeric: tabular-nums; overflow-wrap: anywhere; }
.row-v[data-tone="good"] { color: var(--success-color, #2e9e4a); }
.row-v[data-tone="bad"] { color: var(--error-color, #db4437); font-weight: 600; }
.row-c { width: 18px; height: 18px; color: var(--secondary-text-color); opacity: .6; }
.dlg-foot {
  position: sticky;
  bottom: 0;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 10px 14px 14px;
  background: var(--ha-card-background, var(--card-background-color, #fff));
  border-top: 1px solid var(--divider-color, #e5e5e5);
}

/* Confirm */
.cf { display: flex; gap: 16px; align-items: center; margin-bottom: 18px; }
.cf-txt { flex: 1 1 auto; min-width: 0; }
.cf-title { margin: 2px 0 6px; font-size: 18px; font-weight: 600; line-height: 1.3; overflow-wrap: anywhere; }
.cf-body { margin: 0; color: var(--secondary-text-color, #555); overflow-wrap: anywhere; }

/* Sub-panel */
.sub-h { position: sticky; top: 0; z-index: 2; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 8px 6px 20px; background: var(--ha-card-background, var(--card-background-color, #fff)); }
.sub-t { margin: 0; font-size: 18px; font-weight: 600; }
.sub-b { padding: 0 10px 14px; }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
`;

// ── Visual editor ────────────────────────────────────────────────────────

function editorSchema(t) {
  return [
    {
      name: "device_id",
      required: true,
      // Only panels have a line-frequency sensor — this keeps breakers, CT
      // clamps and Decora devices (all on the same integration) out of the list.
      selector: { device: { filter: [{ integration: "ldata" }], entity: [{ domain: "sensor", device_class: "frequency" }] } },
    },
    { name: "title", selector: { text: {} } },
    {
      type: "grid",
      name: "",
      schema: [
        { name: "show_power", selector: { boolean: {} } },
        { name: "show_alarms", selector: { boolean: {} } },
        { name: "toggle", selector: { boolean: {} } },
        { name: "confirm", selector: { boolean: {} } },
        { name: "show_panel_info", selector: { boolean: {} } },
      ],
    },
    {
      name: "appearance",
      selector: {
        select: {
          mode: "dropdown",
          options: [
            { value: "auto", label: t("editor.appearance_auto") },
            { value: "light", label: t("editor.appearance_light") },
            { value: "dark", label: t("editor.appearance_dark") },
          ],
        },
      },
    },
    { name: "main_breaker", selector: { number: { min: 0, max: 600, step: 5, mode: "box", unit_of_measurement: "A" } } },
  ];
}

const EDITOR_LABELS = {
  device_id: "editor.panel",
  title: "editor.title",
  show_power: "editor.show_power",
  show_alarms: "editor.show_alarms",
  toggle: "editor.toggle",
  confirm: "editor.confirm",
  show_panel_info: "editor.show_panel_info",
  appearance: "editor.appearance",
  main_breaker: "editor.main_breaker",
};

const EDITOR_HELP = {
  device_id: "editor.panel_help",
  main_breaker: "editor.main_breaker_help",
};

const EDITOR_DEFAULTS = {
  show_power: true,
  show_alarms: true,
  toggle: true,
  confirm: true,
  show_panel_info: true,
  appearance: "auto",
};

class LdataPanelCardEditor extends LanguageMixin(HTMLElement) {
  constructor() {
    super();
    this._t = englishOnly;
  }

  setConfig(config) {
    this._config = config || {};
    this._render();
  }

  set hass(hass) {
    this._hass = hass;
    this._render();
  }

  disconnectedCallback() {
    this._forgetLanguage();
  }

  _languageChanged() {
    this._render();
  }

  _render() {
    if (!this._hass || !this._config) return;
    const language = this._syncLanguage(this._hass);
    if (language === null) return;
    if (!this._form) {
      if (!customElements.get("ha-form")) {
        // ha-form is lazy-loaded by the frontend; try again once it exists.
        customElements.whenDefined("ha-form").then(() => this._render());
        return;
      }
      this._form = document.createElement("ha-form");
      this._form.computeLabel = (s) => (EDITOR_LABELS[s.name] ? this._t(EDITOR_LABELS[s.name]) : s.name);
      this._form.computeHelper = (s) => (EDITOR_HELP[s.name] ? this._t(EDITOR_HELP[s.name]) : undefined);
      this._form.addEventListener("value-changed", (ev) => {
        const value = { ...this._config, ...ev.detail.value };
        for (const [k, v] of Object.entries(EDITOR_DEFAULTS)) if (value[k] === v) delete value[k];
        for (const k of ["title", "main_breaker"]) if (value[k] === "" || value[k] === null || value[k] === 0) delete value[k];
        this._config = value;
        this.dispatchEvent(new CustomEvent("config-changed", { detail: { config: value }, bubbles: true, composed: true }));
      });
      this.appendChild(this._form);
    }
    // A new schema object makes the form draw its labels again, so it is
    // replaced only when the language is.
    if (language || !this._schema) this._schema = editorSchema(this._t);
    this._form.hass = this._hass;
    this._form.schema = this._schema;
    this._form.data = { ...EDITOR_DEFAULTS, ...this._config };
  }
}

// ── Sidebar page ─────────────────────────────────────────────────────────
// The integration can add this page to Home Assistant's sidebar (an option,
// off by default; see sidebar.py). It shows a card for each load center; the
// integration passes their device ids in the panel's config.

const MENU_ICON = "M3,6H21V8H3V6M3,11H21V13H3V11M3,16H21V18H3V16Z";

const PAGE_CSS = `
:host {
  display: block;
  box-sizing: border-box;
  min-height: 100vh;
  min-height: 100dvh;
  background: var(--primary-background-color, #fafafa);
  color: var(--primary-text-color, #212121);
  font-family: var(--ha-font-family-body, var(--paper-font-body1_-_font-family, Roboto, "Helvetica Neue", Arial, sans-serif));
  -webkit-font-smoothing: antialiased;
  /* Room for a phone's notch and home indicator. The page is registered as
     handling these itself; the "content" insets leave out the side the
     sidebar already covers. */
  --ldp-left: var(--safe-area-content-inset-left, var(--safe-area-inset-left, 0px));
  --ldp-right: var(--safe-area-content-inset-right, var(--safe-area-inset-right, 0px));
}
.bar {
  position: sticky;
  top: 0;
  z-index: 4;
  box-sizing: border-box;
  display: flex;
  align-items: center;
  height: calc(var(--header-height, 56px) + var(--safe-area-inset-top, 0px));
  padding: var(--safe-area-inset-top, 0px) calc(12px + var(--ldp-right)) 0 calc(12px + var(--ldp-left));
  background: var(--app-header-background-color, var(--primary-color, #03a9f4));
  color: var(--app-header-text-color, #fff);
  border-bottom: var(--app-header-border-bottom, none);
}
.menu { display: flex; flex: none; }
.menu-btn {
  all: unset;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  cursor: pointer;
  -webkit-tap-highlight-color: transparent;
}
.menu-btn[hidden] { display: none; }
.menu-btn:focus-visible { outline: 2px solid currentColor; outline-offset: -4px; }
.menu-btn svg { width: 24px; height: 24px; fill: currentColor; }
.bar-title {
  flex: 1 1 auto;
  min-width: 0;
  margin: 0;
  padding: 0 12px;
  font-size: var(--ha-font-size-xl, 20px);
  font-weight: var(--ha-font-weight-normal, 400);
  line-height: 1.3;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.page {
  box-sizing: border-box;
  padding: 20px calc(12px + var(--ldp-right)) calc(32px + var(--safe-area-inset-bottom, 0px)) calc(12px + var(--ldp-left));
}
/* One load center sits in the middle of the page; more share the width and
   stack when there is no room side by side. */
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 520px), 1fr));
  gap: 28px 24px;
  align-items: start;
  max-width: 900px;
  margin: 0 auto;
}
.grid[data-count="2"] { max-width: 1824px; }
.grid[data-count="3"] { max-width: 2748px; }
.grid[hidden], .empty[hidden] { display: none; }
.unit { min-width: 0; width: 100%; max-width: 900px; justify-self: center; }
.empty { max-width: 440px; margin: 16vh auto 0; padding: 0 8px; text-align: center; }
.empty-t { margin: 0 0 8px; font-size: 20px; font-weight: 500; line-height: 1.3; }
.empty-b { margin: 0; color: var(--secondary-text-color, #727272); font-size: 14px; line-height: 1.5; }
@media (max-width: 599px) {
  .bar { padding-left: calc(4px + var(--ldp-left)); padding-right: calc(4px + var(--ldp-right)); }
  .page { padding-top: 12px; padding-left: calc(4px + var(--ldp-left)); padding-right: calc(4px + var(--ldp-right)); }
}
`;

class LdataSidebarPanel extends LanguageMixin(HTMLElement) {
  constructor() {
    super();
    this._t = englishOnly;
    this._cards = new Map(); // device id -> card element
    this._narrow = false;
  }

  // Home Assistant sets these four on every custom panel.
  set hass(hass) {
    this._hass = hass;
    this._update();
  }

  get hass() {
    return this._hass;
  }

  set narrow(narrow) {
    this._narrow = !!narrow;
    this._update();
  }

  get narrow() {
    return this._narrow;
  }

  set panel(panel) {
    this._panel = panel;
    this._update();
  }

  get panel() {
    return this._panel;
  }

  set route(route) {
    this._route = route;
  }

  get route() {
    return this._route;
  }

  connectedCallback() {
    this._update();
  }

  disconnectedCallback() {
    this._forgetLanguage();
  }

  _languageChanged() {
    this._update();
  }

  _init() {
    const root = this.attachShadow({ mode: "open" });
    root.innerHTML = `
      <style>${PAGE_CSS}</style>
      <div class="bar">
        <div class="menu"></div>
        <h1 class="bar-title"></h1>
      </div>
      <div class="page">
        <div class="grid" hidden></div>
        <div class="empty" hidden><h2 class="empty-t"></h2><p class="empty-b"></p></div>
      </div>`;
    this._els = {
      menu: root.querySelector(".menu"),
      title: root.querySelector(".bar-title"),
      grid: root.querySelector(".grid"),
      empty: root.querySelector(".empty"),
      emptyTitle: root.querySelector(".empty-t"),
      emptyBody: root.querySelector(".empty-b"),
    };
  }

  _update() {
    const hass = this._hass;
    if (!hass) return;
    if (!this.shadowRoot) this._init();
    const waiting = this._syncLanguage(hass) === null;
    const panel = this._panel || {};

    // Until the user's language is in, the bar shows the title the sidebar
    // has (which the integration wrote in the server's language).
    const title = waiting ? panel.title || "" : this._t("sidebar.title");
    if (title !== this._title) {
      this._title = title;
      this._els.title.textContent = title;
    }
    this._renderMenu(hass);

    const devices = hass.devices;
    const listed = (panel.config && Array.isArray(panel.config.panels) ? panel.config.panels : [])
      .map((item) => item && item.device_id)
      .filter((id) => typeof id === "string" && id && (!devices || devices[id]));
    const ids = [...new Set(listed)];
    const key = ids.join("|");
    if (key !== this._cardsKey) {
      this._cardsKey = key;
      const cards = new Map();
      const grid = this._els.grid;
      grid.textContent = "";
      for (const id of ids) {
        let card = this._cards.get(id);
        if (!card) {
          card = document.createElement("ldata-panel-card");
          card.setConfig({ device_id: id });
        }
        cards.set(id, card);
        const unit = document.createElement("section");
        unit.className = "unit";
        unit.appendChild(card);
        grid.appendChild(unit);
      }
      this._cards = cards;
      grid.dataset.count = String(Math.min(ids.length, 3));
      grid.hidden = !ids.length;
    }
    for (const card of this._cards.values()) card.hass = hass;

    const empty = !ids.length && !waiting;
    if (empty) {
      this._els.emptyTitle.textContent = this._t("sidebar.empty_title");
      this._els.emptyBody.textContent = this._t("sidebar.empty_body");
    }
    this._els.empty.hidden = !empty;
  }

  // Home Assistant's own menu button, which also carries the notification
  // dot. The frontend loads that element lazily, so until it exists a plain
  // button stands in for it. Older frontends feed it through these two
  // properties; newer ones have it read what it needs from the page around it.
  _renderMenu(hass) {
    const holder = this._els.menu;
    if (customElements.get("ha-menu-button")) {
      if (!this._menu || this._menu.localName !== "ha-menu-button") {
        this._menu = document.createElement("ha-menu-button");
        holder.textContent = "";
        holder.appendChild(this._menu);
      }
      this._menu.hass = hass;
      this._menu.narrow = this._narrow;
      return;
    }
    if (!this._menu) {
      this._menu = document.createElement("button");
      this._menu.type = "button";
      this._menu.className = "menu-btn";
      this._menu.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="${MENU_ICON}"/></svg>`;
      this._menu.addEventListener("click", () => {
        this.dispatchEvent(new CustomEvent("hass-toggle-menu", { bubbles: true, composed: true }));
      });
      holder.appendChild(this._menu);
      customElements.whenDefined("ha-menu-button").then(() => this._update());
    }
    // Same rule as the real one: the sidebar is out of sight.
    this._menu.hidden = hass.kioskMode === true || !(this._narrow || hass.dockedSidebar === "always_hidden");
    const label = (typeof hass.localize === "function" && hass.localize("ui.sidebar.sidebar_toggle")) || "Sidebar toggle";
    if (this._menu.getAttribute("aria-label") !== label) this._menu.setAttribute("aria-label", label);
  }
}

if (!customElements.get("ldata-panel-card")) {
  customElements.define("ldata-panel-card", LdataPanelCard);
}
if (!customElements.get("ldata-panel-card-editor")) {
  customElements.define("ldata-panel-card-editor", LdataPanelCardEditor);
}
if (!customElements.get("ldata-sidebar-panel")) {
  customElements.define("ldata-sidebar-panel", LdataSidebarPanel);
}

// The entry in the dashboard's card picker. The picker reads these texts when
// it opens — on a new dashboard, before any card exists — so the user's
// language is fetched as soon as this file loads, where the connection is
// already up.
window.customCards = window.customCards || [];
let pickerEntry = window.customCards.find((c) => c.type === "ldata-panel-card");
if (!pickerEntry) {
  pickerEntry = { type: "ldata-panel-card" };
  window.customCards.push(pickerEntry);
}
Object.assign(pickerEntry, {
  name: EN.editor.card_name,
  description: EN.editor.card_description,
  preview: true,
  documentationURL: "https://github.com/rwoldberg/ldata-ha#panel-card-lovelace",
});
let pickerLanguage = null;
const localizePicker = (entry) => {
  if (!entry.done || entry.lang === pickerLanguage) return;
  pickerLanguage = entry.lang;
  const t = translator(entry);
  pickerEntry.name = t("editor.card_name");
  pickerEntry.description = t("editor.card_description");
};
i18nWaiters.add(localizePicker);
try {
  const main = document.querySelector("home-assistant");
  if (main && main.hass) localizePicker(i18nEntry(main.hass));
} catch (err) {
  // English it is, until a card asks for the language itself
}

console.info(`%c LDATA-PANEL-CARD %c ${CARD_VERSION} `, "color:#fff;background:#3b6e3b;font-weight:700", "color:#3b6e3b;background:#eee");
