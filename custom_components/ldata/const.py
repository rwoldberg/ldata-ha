"""Constants for the Leviton LDATA integration."""

DOMAIN = "ldata"
MANUFACTURER = "Leviton"

SENSORS = {
    "breaker": {"icon": "mdi:electric-switch-closed"},
    "amps": {"icon": "mdi:lightning-bolt-circle", "measurement": "A"},
    "pwr": {"icon": "mdi:power-plug", "measurement": "W"},
    "volts": {"icon": "mdi:flash-triangle", "measurement": "V"},
}

UPDATE_INTERVAL = "update_interval"
UPDATE_INTERVAL_DEFAULT = 60
DATA_UPDATED = "ldata_data_updated"
