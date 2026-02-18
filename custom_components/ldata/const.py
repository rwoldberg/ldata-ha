"""Constants for the Leviton LDATA integration."""

DOMAIN = "ldata"
MANUFACTURER = "Leviton"

LOGGER_NAME = "ldata"

THREE_PHASE = "three_phase"
THREE_PHASE_DEFAULT = False
ALLOW_BREAKER_CONTROL = "allow_breaker_control"
ALLOW_BREAKER_CONTROL_DEFAULT = False

HA_INFORM_RATE = "ha_inform_rate"
HA_INFORM_RATE_DEFAULT = 30.0
HA_INFORM_RATE_MIN = 2.0
HA_INFORM_RATE_MAX = 600.0

# CT-only poll interval for v2 firmware panels.
# The bandwidth toggle (1→0→1) needed to refresh CT energy counters can
# cause brief zero readings on breakers. Use 30s to balance CT freshness
# against breaker stability. The WS still delivers power every ~5-6s.
CT_POLL_INTERVAL = 30.0

_LEG1_POSITIONS = [ 1, 2, 5, 6,  9, 10, 13, 14, 17, 18, 21, 22, 25, 26, 29, 30, 33, 34, 37, 38, 41, 42, 45, 46, 49, 50, 53, 54, 57, 58, 61, 62, 65, 66 ]
_LEG2_POSITIONS = [ 3, 4, 7, 8, 11, 12, 15, 16, 19, 20, 23, 24, 27, 28, 31, 32, 35, 36, 39, 40, 43, 44, 47, 48, 51, 52, 55, 56, 59, 60, 63, 64 ]
