# Changelog

All notable changes to the Leviton LDATA integration are documented here.

## 2.0.12 - 2026-09-23

### Added
- **Firmware update entities for your panel and Decora Smart Wi-Fi devices**, using Home Assistant's native Update platform. When Leviton has a newer firmware version available, it now shows up under Settings > Updates (with the usual sidebar badge), so you can set up a notification automation instead of checking the My Leviton app. Installing an update still happens there — this integration only reports availability.

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
- **Daily energy now correctly resets at midnight for older panels.** On panels without hardware energy counters, daily totals could get stuck growing forever (never resetting at midnight) or stuck at zero — this is fixed.
- **Upgrading from a 1.x version could get stuck asking to re-authenticate.** Older installs are now migrated automatically using your already-saved login, instead of forcing a manual sign-in. (#92)
- **Decora Wi-Fi bridges no longer break device setup.** Accounts with a Leviton Wi-Fi bridge could fail to connect properly, and the bridge's "Identify" button didn't work. Bridges are now handled correctly and no longer risk being confused with another bridge on the same account. (#97)
- Panel, breaker, and Decora device firmware versions shown in Home Assistant now update live instead of only refreshing after a restart.
- **Panel firmware version was showing "unknown."** The panel's installed firmware version — shown on the device page and used by the Firmware Update sensor — was reading from a field that doesn't exist on newer WHEMS-based panels, so it always displayed "unknown." It now reads the correct field and updates live as new data arrives. (follow-up to #96)
- Improved compatibility with upcoming Home Assistant releases by moving off two internal APIs that Home Assistant has marked for removal. No visible change today — this just keeps the integration working on future Home Assistant updates.
- **An expired login could force you to re-authenticate even though your saved password still worked.** This is now handled automatically — the integration retries your stored username and password before ever asking you to sign in again. (#98)
