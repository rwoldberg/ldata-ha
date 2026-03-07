"""Constants for the Leviton LDATA integration."""

DOMAIN = "ldata"
MANUFACTURER = "Leviton"

LOGGER_NAME = "ldata"

THREE_PHASE = "three_phase"
THREE_PHASE_DEFAULT = False
ALLOW_BREAKER_CONTROL = "allow_breaker_control"
ALLOW_BREAKER_CONTROL_DEFAULT = False

HA_INFORM_RATE = "ha_inform_rate"
HA_INFORM_RATE_DEFAULT = 60.0
HA_INFORM_RATE_MIN = 2.0
HA_INFORM_RATE_MAX = 600.0

# CT-only poll interval for v2 firmware panels.
# The bandwidth toggle (1→0→1) needed to refresh CT energy counters can
# cause brief zero readings on breakers. Use 30s to balance CT freshness
# against breaker stability. The WS still delivers power every ~5-6s.
CT_POLL_INTERVAL = 60.0

# WebSocket heartbeat interval. Sends a lightweight GET /apiversion to
# keep the connection alive and the auth token fresh.
WS_HEARTBEAT_INTERVAL = 60.0

# Gap handling for breaker daily energy sensors (power×time fallback).
# When no data arrives for longer than the threshold, power×time integration
# can produce phantom spikes (power outage) or inaccurate readings (network loss).
# Only used when hardware energy counters are unavailable (older firmware).
GAP_HANDLING = "gap_handling"
GAP_HANDLING_SKIP = "skip"           # Don't accumulate energy during the gap
GAP_HANDLING_EXTRAPOLATE = "extrapolate"  # Use last known power across the gap
GAP_HANDLING_AVERAGE = "average"     # Average last known + recovery power across the gap
GAP_HANDLING_DEFAULT = GAP_HANDLING_SKIP
GAP_HANDLING_OPTIONS = [GAP_HANDLING_SKIP, GAP_HANDLING_EXTRAPOLATE, GAP_HANDLING_AVERAGE]

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
