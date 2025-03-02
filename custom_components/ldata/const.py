"""Constants for the Leviton LDATA integration."""

DOMAIN = "ldata"
MANUFACTURER = "Leviton"

LOGGER_NAME = "ldata"

SENSORS = {
    "breaker": {"icon": "mdi:electric-switch-closed"},
    "amps": {"icon": "mdi:lightning-bolt-circle", "measurement": "A"},
    "pwr": {"icon": "mdi:power-plug", "measurement": "W"},
    "volts": {"icon": "mdi:flash-triangle", "measurement": "V"},
}

UPDATE_INTERVAL = "update_interval"
UPDATE_INTERVAL_DEFAULT = 60
UPDATE_INTERVAL_MIN = 10
DATA_UPDATED = "ldata_data_updated"
THREE_PHASE = "three_phase"
THREE_PHASE_DEFAULT = False
READ_ONLY = "read_only"
READ_ONLY_DEFAULT = True

_LEG1_POSITIONS = [ 1, 2, 5, 6,  9, 10, 13, 14, 17, 18, 21, 22, 25, 26, 29, 30, 33, 34, 37, 38, 41, 42, 45, 46, 49, 50, 53, 54, 57, 58, 61, 62, 65, 66 ]
_LEG2_POSITIONS = [ 3, 4, 7, 8, 11, 12, 15, 16, 19, 20, 23, 24, 27, 28, 31, 32, 35, 36, 39, 40, 43, 44, 47, 48, 51, 52, 55, 56, 59, 60, 63, 64 ]
