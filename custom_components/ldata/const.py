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
