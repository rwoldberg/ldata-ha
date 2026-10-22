# Changelog

All notable changes to the Leviton LDATA integration are documented here.

## 2.0.14 - Unreleased

### Changed
- **The panel status refresh runs every 110 seconds instead of 120.** Leviton's server closes idle connections at 120 seconds, so about 1 refresh in 20 hit a dropped connection and logged an error. (#111)

### Fixed
- **Lifetime energy no longer jumps by thousands of kWh on some hubs.** On a DAU or LDATA hub whose energy counters don't behave like true lifetime totals, a breaker's Consumption/Import sensor could leap far beyond what the breaker could physically draw after a restart, wrecking Energy dashboard totals. A reading the breaker couldn't have drawn since the last one is now ignored, and a panel whose counters keep decreasing, jumping, or reading far below the total already recorded switches to estimating energy from power over time, with a warning in the log. Use the **Reset energy sensor baseline** service to accept a value that was held back. (#115)
- **Quiet houses no longer cause constant WebSocket reconnects.** When nothing was drawing power for a few minutes, the integration mistook the silence for a dead connection and reconnected every 7 to 9 minutes, losing about 11 seconds of updates each time. It now treats Leviton's 30-second keepalive as proof the connection is alive. (#111, see #83)
- **Failed reconnects no longer hammer Leviton's servers.** If Leviton closed a new connection immediately, the integration retried about once a second until Leviton rate-limited it (HTTP 429). Retries now back off from 10 seconds up to 5 minutes. (#111)
- **Panel status refresh errors are retried quietly.** A dropped connection is retried once, and a warning is logged only after three failed refreshes in a row. (#111)
- **Saving integration options no longer wipes your solar settings or causes repeated reloads.** Saving options erased the solar and suppressed import-sensor lists, so solar import sensors could disappear and hidden ones could return. Each reload also added another listener, so after several reloads one options change reloaded the integration several times. It now reloads once, and only when an option actually changed. Unloading the integration now also stops its background tasks cleanly. (#110)
- **Daily energy now resets at midnight after a very low day.** A daily sensor that finished the day at 0.05 kWh or less didn't reset, so Home Assistant under-counted the next day. (#112)
- **The reset-panel-energy service now finds breaker sensors.** Choosing a breaker reset nothing, and choosing a panel or CT skipped every breaker sensor. (#112)
- **Leftover breaker devices from versions before 2.0.9 are cleaned up.** They held only dead entities and caused a "Could not resolve a panel or Decora room" warning per breaker at every startup. You can now also delete a device that is no longer in use from its device page. (#113, see #86)
- **LDATA panels now receive live updates over the WebSocket.** Panels were subscribed in a way that delivered nothing for LDATA hubs, so panel-level readings only refreshed on the periodic poll. They now update live, and Cloud Connected, frequency and Wi-Fi signal follow the same rules as the periodic refresh. (#114)

## 2.0.13 - 2026-10-15

### Changed
- **Daily energy sensors no longer publish a `last_update_time` attribute.** It changed on every update, forcing a database write for each daily energy sensor even when the reading hadn't moved. Dropping it reduces database writes and Home Assistant event traffic. If you used that attribute in a template or automation, use the sensor's own `last_updated` instead. (#101)
- **Panel voltage shows "unknown" instead of 0 V when the panel doesn't report it.** The Voltage Leg 1 / Leg 2 sensors previously showed a misleading 0 V, which looked like a dead leg, whenever Leviton's data was missing a reading. A real 0 V reading is still shown as 0 V. (#107)
- **A wired LDATA hub no longer gets a Wi-Fi Signal sensor that can never show a value.** Hubs connected over Ethernet report no Wi-Fi signal, so the sensor sat on "unknown" forever. It is no longer created for them, and an existing one is removed on the next start. Wi-Fi hubs are unaffected, and the sensor now clears its reading instead of holding a stale one if a hub stops reporting a signal. (#105)

### Fixed
- **Firmware update entities are no longer filed as diagnostic.** Home Assistant categorized the panel and Decora firmware update entities as diagnostic by default, so they were listed under Diagnostic on the device page instead of with the device's main entities. They are still not counted in the "Updates available" sidebar badge or Settings card, which only count updates Home Assistant can install.
- **LDATA panel readings no longer freeze after setup.** Voltage, frequency, over/under-voltage alarms, Wi-Fi signal and firmware version on LDATA panels now refresh every couple of minutes instead of staying at their startup values until you reload the integration. Setup also no longer fails if a panel reports no firmware version. (#104)
- **Breaker details stay current.** The firmware, hardware, rating and model shown on each breaker, and the firmware version on its device page, now update after a breaker firmware change instead of waiting for a reload. (#106)
- **A panel reporting 0 V is no longer ignored on WHEMS panels.** A real 0 V leg reading now shows as 0 V instead of keeping the previous voltage. (#108)
- **Cloud Connected now turns off when your panel goes offline, and back on when it returns** — without reloading the integration. Previously it could stay "on" indefinitely, and Home Assistant could stop receiving updates altogether after one of Leviton's routine reconnects. Sensors still show their last known values while the panel is offline. (#103, fixes #102)
- **Your account password could be visible in the integration's name.** Setups created between April 2023 and October 2025 were titled with the password included, shown on the Devices & Services page and written to logs. These are now renamed automatically to `Leviton LDATA (your email)`, and a warning in the log tells you it happened. If yours was affected, consider changing your Leviton password — the old name may still be in past logs and backups. (#100)

## 2.0.12 - 2026-09-23

### Added
- **Firmware update entities for your panel and Decora Smart Wi-Fi devices**, using Home Assistant's native Update platform. When Leviton has a newer firmware version available, the entity turns on, so you can set up a notification automation instead of checking the My Leviton app. Because the integration cannot install firmware, Home Assistant does not count these entities in the "Updates available" sidebar badge or Settings card. Installing an update still happens there — this integration only reports availability.

### Changed
- **The breaker "Blink LED" switch is now opt-in**, behind a new **Allow Identify** option (off by default), separate from Allow Breaker Control. Previously it was always created, even on a fully read-only setup — if you use it to physically locate breakers, enable it under Settings > Devices & Services > Leviton LDATA > Configure after upgrading. (#91)
- **The panel's Firmware Update entity moved from a sensor to Home Assistant's Update platform** (`update.*` instead of `sensor.*`). If you had an automation or dashboard card on the old `sensor.<panel>_firmware_update` entity, it will stop updating after this upgrade — point it at the new `update.*` entity instead, then remove the orphaned old one from Settings > Devices & Services > Entities.

### Fixed
- **Keeping your panel's live updates flowing now matches Leviton's latest app (API 1.66.0).** Leviton quietly switched the internal request that keeps data flowing from PUT to PATCH — no visible symptoms yet, but this keeps the integration working if Leviton drops the old method.

## 2.0.11 - 2026-09-18

### Added
- **Breaker Over Voltage alarm** — a new sensor for each smart breaker, alongside the existing Over Current and Under Voltage alarms. (#94)
- **Breaker State diagnostic sensor** — shows Leviton's raw breaker state (e.g. manual shutoff vs. a software trip, AFCI/GFCI fault, overload, or short circuit) instead of a simplified on/off, plus details like trip reason and lock status. (#95)
- **Panel Firmware Update sensor** — shows whether a firmware update is available for your panel, and the currently installed version. Purely informational; installing an update still happens in the My Leviton app. (#96)

### Fixed
- **Daily energy no longer resets on restart.** Breaker and CT daily consumption/import totals were being wiped back to 0 every time Home Assistant restarted, even mid-day. Restored totals are now kept if they're genuinely from today. (#93)
- **Upgrading from a 1.x version could get stuck asking to re-authenticate.** Older installs are now migrated automatically using your already-saved login, instead of forcing a manual sign-in. (#92)
- **Decora Wi-Fi bridges no longer break device setup.** Accounts with a Leviton Wi-Fi bridge could fail to connect properly, and the bridge's "Identify" button didn't work. Bridges are now handled correctly and no longer risk being confused with another bridge on the same account. (#97)
- Panel, breaker, and Decora device firmware versions shown in Home Assistant now update live instead of only refreshing after a restart.
- **Panel firmware version now updates live.** The panel's installed firmware version, shown on the device page and used by the Firmware Update sensor, now refreshes as new data arrives instead of only after a restart. (follow-up to #96)
- Improved compatibility with upcoming Home Assistant releases by moving off two internal APIs that Home Assistant has marked for removal. No visible change today — this just keeps the integration working on future Home Assistant updates.
- **An expired login could force you to re-authenticate even though your saved password still worked.** This is now handled automatically — the integration retries your stored username and password before ever asking you to sign in again. (#98)