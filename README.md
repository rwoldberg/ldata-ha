![GitHub Release](https://img.shields.io/github/v/release/rwoldberg/ldata-ha) ![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/rwoldberg/ldata-ha/latest/total)  ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/rwoldberg/ldata-ha/total?label=Total%20Downloads&color=blue)


# ldata-ha
# leviton LDATA and LWHEM integration for Home Assistant (https://my.leviton.com/)

This is a home assistant integration for the LDATA and LWHEM hubs for levitons smart breakers. It can also optionally discover and control Decora Smart Wi-Fi devices (switches, dimmers, fans, outlets, GFCIs) on the same account — see [Decora Smart Wi-Fi Support](#decora-smart-wi-fi-support) below.

<br>

If this integration has been useful to you, please consider chipping in and buying us a coffee!

RWoldberg
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/RWoldberg)

MrToast99
[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/mrtoast99)

## Install

Use HACS and add as a custom repo. Once the integration is installed go to your integrations and follow the configuration options to specify the below:

- Username (my.leviton.com Username)
- Password (my.leviton.com Password)
- 2FA (If Enabled)

## Installation

Recommended installation is via the [Home Assistant Community Store (HACS)](https://hacs.xyz/). [![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

### 1. Install via HACS custom repository

If you do not wish to use HACS, then please download the latest version from the [releases page](https://github.com/rwoldberg/ldata-ha/releases) and proceed to Step 2.

1. Navigate to the HACS add-on
2. Select 'Custom Repositories'
2. Add 'https://github.com/rwoldberg/ldata-ha' as the repository and 'Integration' as the Categroy
3. Restart Home Assistant


<img width="450" alt="Select Custom Repositories " src="https://user-images.githubusercontent.com/2048887/220187592-3c88bb8f-fd4f-412f-aebe-6c8202bb552c.png">

<img width="450" alt="Add ldata-ha" src="https://user-images.githubusercontent.com/2048887/220187501-0f339218-4b07-4ee1-9e75-81c1f3f55e3f.png">

### 2. Configure via Home Assistant

1. Navigate to Home Assistant Settings > Devices & Services
2. Click `+ Add Integration`
3. Search for `LDATA`
4. Complete the guided configuration

<img width="450" alt="Configure LDATA from Home Assistant" src="https://user-images.githubusercontent.com/2048887/220187938-142446b6-81f9-491f-a880-b54f5ec33591.png">


## Panel Card (Lovelace)

A custom Lovelace card that renders a visual representation of a physical panel — breakers laid out in their real slot positions, live Watts/Amps, alarm highlighting, and an on/off switch per breaker (if 'Allow Control is enabled').

Features:
- Auto-discovers breakers for a panel via Home Assistant's device registry — no manual entity list to maintain.
- Left/right column placement and slot numbering match the physical panel (odd positions left, even positions right).
- 2-pole (240V) breakers render as a single double-height slot spanning both of their positions (e.g. `5/7`), not squeezed into one row.
- Panel mounting orientation (normal vs. rotated 180°) is auto-detected from Leviton's own data — no config needed unless you want to force an orientation.
- Optional live power/current readout and over-current/under-voltage alarm highlighting per slot.
- When breaker control is enabled, each slot shows its own on/off switch — pressing it asks for confirmation before actually toggling. Clicking anywhere else on a slot opens that breaker's device page.
- Attempting to turn on a Gen1 breaker (hardware that can be tripped remotely but not reset remotely) shows an informational dialog instead of a confirmation — Gen1 breakers must be reset by hand at the panel.
- Optional linking of a "dumb" (non-smart) breaker to the downstream sub-panel it physically feeds — the linked slot shows that sub-panel's own live Watts/Amps and gets its own distinct color, instead of the plain grey "unmonitored" fill. Clicking it opens the sub-panel's own full breaker layout in a popup.

### 1. Install the card file

Nothing to do here for most setups — the integration serves the card directly from its own `custom_components/ldata/www/` folder and registers it as a Lovelace resource automatically, so there's no file to copy and no manual "Add Resource" step. Just make sure the integration is installed and Home Assistant has been **restarted** (not just reloaded) since — this registration happens once at startup.

If your dashboard is in legacy YAML mode (not the default UI/storage mode), auto-registration doesn't apply and you'll need to add the resource manually: URL `/ldata_static/ldata-panel-card.js`, type **JavaScript Module**.

If the card isn't picking up an update after a new release, a hard browser refresh (Ctrl+Shift+R / Cmd+Shift+R) usually clears it; the underlying file is always current as soon as `custom_components/ldata` is updated and HA is restarted.

### 2. Add the card to a dashboard

1. Edit a dashboard, click **+ Add Card**, and choose **Manual** (or **Custom: LDATA Panel Card** if it appears in the picker).
2. Use the YAML below, filling in `device_id` with your panel's device (find it under **Settings > Devices & Services > Devices**, click your LDATA/LWHEM panel — not a breaker — and copy the device ID from the page URL).

```yaml
type: custom:ldata-panel-card
device_id: <panel device id>
title: "Main Panel"        # optional, defaults to the device's name
show_power: true           # optional, show live Watts/Amps per slot
show_alarms: true          # optional, highlight over-current/under-voltage alarms
toggle: true                # optional, show an on/off switch on each slot when control is enabled
# rotate_180: true          # optional override — only set this if auto-detected orientation is wrong
```

If you have multiple panels, add one card per panel, each with its own `device_id`.

### Showing live CT (Grid/Solar) Watts and Amps above the panel card

The panel card itself only shows breakers — for a live whole-panel reading, add standard Home Assistant cards above it using your CT clamp's own sensors. Each CT is its own device, named after its usage type (e.g. "Grid", "Solar") — find its Watts/Amps entity IDs under **Settings > Devices & Services > Devices**, click the CT device (linked under your panel), and copy them from its Sensors tab.

```yaml
cards:
  - type: horizontal-stack
    cards:
      - type: tile
        entity: sensor.grid_watts
        name: Grid Power
      - type: tile
        entity: sensor.grid_amps
        name: Grid Current

  # If your panel also has a Solar CT, add a second row the same way:
  # - type: horizontal-stack
  #   cards:
  #     - type: tile
  #       entity: sensor.solar_watts
  #       name: Solar Power
  #     - type: tile
  #       entity: sensor.solar_amps
  #       name: Solar Current

  - type: custom:ldata-panel-card
    device_id: <panel device id>
    title: "Main Panel"
```

A `glance` card is a more compact alternative to the `tile`/`horizontal-stack` pair above:

```yaml
  - type: glance
    title: Grid
    entities:
      - entity: sensor.grid_watts
        name: Power
      - entity: sensor.grid_amps
        name: Current
```

Or use `sensor` cards with `graph: line` if you'd rather see a trend line under each value instead of just the live number:

```yaml
  - type: horizontal-stack
    cards:
      - type: sensor
        graph: line
        entity: sensor.grid_watts
        name: Grid Power
      - type: sensor
        graph: line
        entity: sensor.grid_amps
        name: Grid Current
```

### Doing the same for a nested/sub-panel (e.g. a panel 2)

If you have a second physical panel (a sub-panel fed from the main one) that shows up as its own device under **Settings > Devices & Services** — separate from your main panel — the integration treats it exactly the same as the main panel: its own breakers, its own CT clamp(s) if it has any, and its own `device_id`. There's nothing "nested" about it structurally, so just repeat the exact same pattern with that panel's own `device_id` and its own CT entity IDs:

```yaml
cards:
  # Main panel
  - type: horizontal-stack
    cards:
      - type: tile
        entity: sensor.grid_watts
        name: Grid Power
      - type: tile
        entity: sensor.grid_amps
        name: Grid Current
  - type: custom:ldata-panel-card
    device_id: <main panel device id>
    title: "Main Panel"

  # Panel 2 (sub-)panel — same pattern, its own device_id and CT entities
  - type: horizontal-stack
    cards:
      - type: tile
        entity: sensor.Panel_2_grid_watts
        name: Panel2 Grid Power
      - type: tile
        entity: sensor.Panel_2_grid_amps
        name: Panel 2 Grid Current
  - type: custom:ldata-panel-card
    device_id: <Panel 2 panel device id>
    title: "Panel 2 Panel"
```

If the sub-panel doesn't have its own CT clamp, it won't have a "Grid Power"-style entity of its own — in that case the closest equivalent is the Watts/Amps of whichever breaker on the main panel feeds power to it (every smart breaker has its own Watts/Amps sensors, same as any other breaker).

### Linking a "dumb" breaker to the sub-panel it feeds

If a sub-panel is fed by a **"dumb" (non-smart) breaker** on the main panel — no monitoring data of its own, just a physical slot — the card has no way to know that breaker feeds another panel; Leviton's API doesn't report that relationship at all. You can tell the card about it by hand in the main panel's card config, and it'll show that sub-panel's own live Watts/Amps directly on the dumb breaker's slot, with a distinct blue fill so it reads at a glance as "feeds another panel" rather than "just unmonitored":

```yaml
type: custom:ldata-panel-card
device_id: <main panel device id>
sub_panels:
  - breaker_position: 9                    # the dumb breaker's slot number (the badge shown on its tile)
    panel_device_id: <sub-panel device id>  # find under Settings > Devices & Services > Devices, same as device_id above
    rating: 50                             # optional — see below
```

Add one entry per dumb breaker you want linked — a single card can link more than one, e.g. if a panel has two dumb breakers each feeding a different sub-panel.

Leviton's API never reports a rating for a dumb breaker (it's not a smart device, so there's no data on it at all) — if you know the breaker's own max amp rating (e.g. it's a 50A double-pole feeding the sub-panel), add `rating` and it shows up the same way a smart breaker's does, right before the Watts/Amps readout.

Clicking the linked slot (or its sub-panel name, which is its own clickable link) opens that sub-panel's own full breaker layout right there in a popup — a live, independent `ldata-panel-card` for the sub-panel's `device_id`, with nothing more to configure than what's already in the entry above. Close it with the ✕, Escape, or by clicking outside it.

If you'd rather leave this card entirely and jump to a real dashboard view instead — say the sub-panel already has its own `ldata-panel-card` on some other dashboard — add `view_path` with the URL path to it (open that dashboard/view in your browser and copy the path after the domain, e.g. `/lovelace/DASHBOARD_NAME`) and it replaces the popup with a normal page navigation:

```yaml
sub_panels:
  - breaker_position: 9
    panel_device_id: <sub-panel device id>
    view_path: /lovelace/DASHBOARD_NAME   # optional override — see above
```

There's no registry mapping a device id to "the dashboard view showing its card" — a device can appear on any number of dashboards or none — so this can't be auto-detected; the popup is the default precisely because it needs nothing beyond `panel_device_id`, and `view_path` only takes effect once you set it explicitly.

## Decora Smart Wi-Fi Support

Optional support for Leviton's **Decora Smart Wi-Fi** product line — a separate line of devices from the LDATA/WHEM breaker panels above (switches, dimmers, fans, outlets, GFCI outlets, and Wi-Fi bridges), fetched from the same Leviton cloud account via a different API. Off by default — most LDATA users don't have any of these, and leaving it off avoids extra API calls on every update.

### Enabling it

Turn on **Enable Decora Smart Wi-Fi devices** — either during initial setup, or later via **Settings > Devices & Services > Leviton LDATA > Configure**. Home Assistant will discover every supported Decora device on your account automatically; no device IDs or manual entity setup required.

### What gets created

Each Decora device becomes its own HA device, with entities depending on its type:

- **Lights & dimmers** — a `light` entity (on/off, plus brightness if the device supports dimming).
- **Fans** — a `fan` entity (on/off, plus speed if supported).
- **Switches, outlets, and GFCI outlets** — a `switch` entity.
- **GFCI outlets specifically** — an additional fault-status `binary_sensor` and `sensor` (Protected/Fault/Test), plus a buzzer enable/disable `switch` and a silence-alert `button`.
- **Every device** — a Wi-Fi signal strength `sensor`, a connectivity `binary_sensor`, and an identify `button` (blinks the device's LED so you can find it physically).
- **Dimmable/motion-capable devices** — config `select` entities for things like auto-shutoff time, status LED behavior, fade rate, and motion sensor timing/mode, where the device reports support for them.

Devices update in real time over the same WebSocket connection used for breaker/panel data, so state changes (e.g. flipping a physical switch) reflect in HA immediately.

### Supported Decora devices

**Controllers**

    D2SCS
    DW4BC

**Fans**

    D24SF
    DW4SF

**GFCI Outlets**

    D2GF1
    D2GF2

**Lights**

    D23LP
    D26HD
    D2ELV
    D2MSD
    DN6HD
    DW1KD
    DW3HL
    DW6HD
    DWVAA

**Motion Sensors** (capability of the light above, not a separate device)

    D2MSD

**Outlets**

    D215O
    D215P
    D215R
    DW15A
    DW15P
    DW15R

**Switches**

    D215S
    D2SCS
    DW15S
    DN15S

**Wi-Fi Bridge**

    MLWSB

If you add a new Decora device to your account, reload the integration to pick it up.

## Options

Addon is auto reloading on submit.
- HA Inform Rate (Seconds)
  - How often to update sensors in Home Assistant (2-600 seconds). Lower values = more responsive but higher system load and DB writes.
 
  - The older 1.x you could adjust the "polling rate" or how often to ask Leviton for new data, with Websocket you ask once and it turns on a fuacet of data, as any value changes it's past back to you (@ .5-1 sec rate) so the 'HA infrom rate' listens to the stream but only passes values to HA for DB writing at the rate you set.

- 120/208V Network Service (Apartment/Condo) (default off)
  - Enable this ONLY if you live in an apartment or building with a 120/208V Network setup. This correctly calculates 2-pole breaker voltages using 208V math instead of 240V. Do not enable this for a standard residential house.

- Allow Breaker Control (default off)
  - HA will not create Switch entities for breaker control (Breakers are only treated as Sensors)

- Enable Decora Smart Wi-Fi devices (default off)
  - Discovers and creates entities for Decora Smart Wi-Fi switches, dimmers, fans, outlets, and GFCIs on your account (a separate Leviton product line from the LDATA/WHEM breaker panels). Leave off if you don't have any — it avoids extra API calls on every update. Can be set at initial setup or toggled later here.

- Log General Integration Errors
  - Integration crashes or web errors

- Log Data Validation Warning (Spikes/Resets)
  - Outputs Warnings of Data inconsistancies from Leviton to log

- Log Raw WebSocket String
  - Log the exact, unparsed JSON string received directly from the Leviton WebSocket (WARNING: Contains unredacted tokens/IDs).
  
- Log All Parsed Data
  - Log the complete parsed data dictionary (after redaction) that the integration retains from the API/WebSocket.

- Enable Specific Field Logging
  - Outputs any specified field to log (field names can be seen by breifly enabling and looking at "Log Full WebSocket Data")

<img width="548" height="914" alt="options" src="https://github.com/user-attachments/assets/4d756e48-0c5e-4a97-8a2f-073d1a97f563" />

<br>
<br>
<br>

# Known Issues (Leviton Lacking support)

- CT clamp and Breaker lifetime values are only available via triggering a Poll request then WS gets a update **(NOTE as of WHEM firmware v2.1.0 these lifetime values no longer function)**
- BLErssi on 2-pole breakers always 0 due to not reporting from Leviton

<br>
<br>
<br>
This is a DIY integration and is not supported or affiliated with Leviton in any way.

