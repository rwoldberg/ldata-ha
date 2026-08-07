"""Constants for the Leviton LDATA integration."""

DOMAIN = "ldata"
MANUFACTURER = "Leviton"

# Config subentry type used to group each panel's devices/entities separately
# from the rest of the account in HA's Devices & Services UI. One subentry is
# created per discovered panel (unique_id = panel id), keyed by the panel's
# own id/serialNumber — see __init__.py's subentry reconciliation.
PANEL_SUBENTRY_TYPE = "panel"

# Same idea as PANEL_SUBENTRY_TYPE, but for Decora Smart Wi-Fi devices, which
# have no panel to group under. Leviton's own "room" concept (residentialRoomId
# on each iotSwitch/iotBridge device, residentialRooms for the id -> name map)
# is the natural grouping — it's what the Leviton app itself organizes devices
# by (e.g. "Basement Office"). One subentry per discovered room (unique_id =
# residentialRoomId) — see __init__.py's subentry reconciliation.
DECORA_ROOM_SUBENTRY_TYPE = "decora_room"

# Config entry data key holding the single residence this entry is scoped
# to. Set during config flow for new setups (see config_flow.py's residence
# picker); absent on entries created before this feature existed, in which
# case ldata_service.py falls back to its original behavior of discovering
# and using every residence the account has access to.
CONF_RESIDENCE_ID = "residence_id"
RESIDENCE_IMPORT_SOURCE = "residence_import"

LOGGER_NAME = "ldata"

THREE_PHASE = "three_phase"
THREE_PHASE_DEFAULT = False
ALLOW_BREAKER_CONTROL = "allow_breaker_control"
ALLOW_BREAKER_CONTROL_DEFAULT = False
ENABLE_DECORA = "enable_decora"
ENABLE_DECORA_DEFAULT = False

HA_INFORM_RATE = "ha_inform_rate"
HA_INFORM_RATE_DEFAULT = 60.0
HA_INFORM_RATE_MIN = 2.0
HA_INFORM_RATE_MAX = 600.0

# CT REST poll interval (seconds) — v1 firmware panels only.
# On v2+ firmware, CT energy counters are period counters (not lifetime totals)
# and CT REST polling is disabled entirely; CT power arrives via WS IotCt events.
# On v1 panels, a bandwidth toggle (1→0→1) is needed to force the panel to
# refresh its hardware energy counters before the REST fetch.
CT_POLL_INTERVAL = 300.0

# Settle delay (seconds) after a bandwidth toggle before fetching CT/breaker data.
# After bandwidth:0 the panel briefly disconnects; waiting before the REST fetch
# avoids 502 responses caused by the panel not yet having reconnected.
CT_BANDWIDTH_SETTLE_SECS = 15

# Retry delays (seconds) for CT/breaker fetch after a 502 / None response.
# Each entry is a wait before the next attempt, in order.
# Total extra time if all retries fail: sum(CT_FETCH_RETRY_DELAYS) seconds.
CT_FETCH_RETRY_DELAYS = [15, 25]  # 2 retries → up to 40s extra per cycle

# Gap handling for breaker daily energy sensors (power×time fallback).
# When no data arrives for longer than the threshold, power×time integration
# can produce phantom spikes (power outage) or inaccurate readings (network loss).
# Only used when hardware energy counters are unavailable (older firmware).
GAP_HANDLING = "gap_handling"
GAP_HANDLING_SKIP = "skip"           # Don't accumulate energy during the gap
GAP_HANDLING_EXTRAPOLATE = "extrapolate"  # Use last known power across the gap
GAP_HANDLING_AVERAGE = "average"     # Average last known + recovery power across the gap
GAP_HANDLING_DEFAULT = GAP_HANDLING_SKIP
GAP_HANDLING_LABELS = {
    GAP_HANDLING_SKIP: "Skip — Don't accumulate energy during gaps",
    GAP_HANDLING_EXTRAPOLATE: "Extrapolate — Assume last known power continued",
    GAP_HANDLING_AVERAGE: "Average — Use mean of last and recovery power",
}
GAP_HANDLING_OPTIONS = list(GAP_HANDLING_LABELS)

GAP_THRESHOLD = "gap_threshold"      # Gap threshold in minutes
GAP_THRESHOLD_DEFAULT = 5.0          # 5 minutes — well above normal update intervals
GAP_THRESHOLD_MIN = 1.0
GAP_THRESHOLD_MAX = 30.0

# Transient None tolerance: how many consecutive None readings before
# switching away from hardware counter mode.  A single None from a
# reconnect / parse_panels glitch should NOT trigger a permanent mode switch.
HW_COUNTER_NONE_TOLERANCE = 3

# Sanity cap for daily energy (kWh).  No single residential breaker can
# realistically consume more than this in one day.  A 200A panel at 240V
# running 24h = 1152 kWh, so 500 kWh per breaker is extremely generous.
MAX_DAILY_ENERGY_KWH = 500.0

_LEG1_POSITIONS = [ 1, 2, 5, 6,  9, 10, 13, 14, 17, 18, 21, 22, 25, 26, 29, 30, 33, 34, 37, 38, 41, 42, 45, 46, 49, 50, 53, 54, 57, 58, 61, 62, 65, 66 ]

# ── Decora Smart Wi-Fi Device Constants ──────────────────────────────────
# A separate Leviton product line (switches/dimmers/fans/outlets/GFCIs/
# bridges) from the LDATA/WHEM breaker panels above — different API
# (iotSwitches/iotBridges), different device family, gated behind
# ENABLE_DECORA since most LDATA users won't have any of these.

POWER_ON = "ON"
POWER_OFF = "OFF"

# Device type classification
DEVICE_TYPE_BRIDGE = "bridge"
DEVICE_TYPE_CONTROLLER = "controller"
DEVICE_TYPE_FAN = "fan"
DEVICE_TYPE_GFCI = "gfci"
DEVICE_TYPE_LIGHT = "light"
DEVICE_TYPE_OUTLET = "outlet"
DEVICE_TYPE_SWITCH = "switch"

# Supported Decora Smart Wi-Fi device models
# Each entry: (model, [device_types], generation)
# Generation: 1 = DW (1st gen Wi-Fi), 2 = D2 (2nd gen Wi-Fi), 3 = DN/MLWSB (No-Neutral via bridge)
SUPPORTED_DECORA_DEVICES = [
    ("D215O", [DEVICE_TYPE_OUTLET], 2),
    ("D215P", [DEVICE_TYPE_OUTLET], 2),
    ("D215R", [DEVICE_TYPE_OUTLET], 2),
    ("D215S", [DEVICE_TYPE_SWITCH], 2),
    ("D23LP", [DEVICE_TYPE_LIGHT], 2),
    ("D24SF", [DEVICE_TYPE_FAN], 2),
    ("D26HD", [DEVICE_TYPE_LIGHT], 2),
    ("D2ELV", [DEVICE_TYPE_LIGHT], 2),
    ("D2GF1", [DEVICE_TYPE_GFCI], 2),
    ("D2GF2", [DEVICE_TYPE_GFCI], 2),
    ("D2MSD", [DEVICE_TYPE_LIGHT], 2),
    ("D2SCS", [DEVICE_TYPE_CONTROLLER, DEVICE_TYPE_SWITCH], 2),
    ("DN15S", [DEVICE_TYPE_SWITCH], 3),
    ("DN6HD", [DEVICE_TYPE_LIGHT], 3),
    ("DW15A", [DEVICE_TYPE_OUTLET], 1),
    ("DW15P", [DEVICE_TYPE_OUTLET], 1),
    ("DW15R", [DEVICE_TYPE_OUTLET], 1),
    ("DW15S", [DEVICE_TYPE_SWITCH], 1),
    ("DW1KD", [DEVICE_TYPE_LIGHT], 1),
    ("DW3HL", [DEVICE_TYPE_LIGHT], 1),
    ("DW4BC", [DEVICE_TYPE_CONTROLLER], 1),
    ("DW4SF", [DEVICE_TYPE_FAN], 1),
    ("DW6HD", [DEVICE_TYPE_LIGHT], 1),
    ("DWVAA", [DEVICE_TYPE_LIGHT], 1),
    ("MLWSB", [DEVICE_TYPE_BRIDGE], 3),
]

DECORA_MODELS_ALL = [d[0] for d in SUPPORTED_DECORA_DEVICES]
DECORA_MODELS_LIGHT = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_LIGHT in d[1]]
DECORA_MODELS_FAN = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_FAN in d[1]]
DECORA_MODELS_SWITCH = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_SWITCH in d[1]]
DECORA_MODELS_OUTLET = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_OUTLET in d[1]]
DECORA_MODELS_GFCI = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_GFCI in d[1]]
DECORA_MODELS_CONTROLLER = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_CONTROLLER in d[1]]
DECORA_MODELS_BRIDGE = [d[0] for d in SUPPORTED_DECORA_DEVICES if DEVICE_TYPE_BRIDGE in d[1]]
