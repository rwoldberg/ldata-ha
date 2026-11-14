![GitHub Release](https://img.shields.io/github/v/release/rwoldberg/ldata-ha) ![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/rwoldberg/ldata-ha/latest/total)  ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/rwoldberg/ldata-ha/total?label=Total%20Downloads&color=blue)


# ldata-ha
# leviton LDATA and LWHEM integration for Home Assistant (https://my.leviton.com/)

This is a home assistant integration for the LDATA and LWHEM hubs for levitons smart breakers. It can also optionally discover and control Decora Smart Wi-Fi devices (switches, dimmers, fans, outlets, GFCIs) on the same account � see [Decora Smart Wi-Fi Support](#decora-smart-wi-fi-support) below.

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

A custom Lovelace card that shows your panel as it looks on the wall. It isn't a drawing: the card is assembled from ray-traced images of a Leviton load center and its breakers, modeled from Leviton's own product photos. You get the white cover with its embossed door surround, the dead front, and every breaker in its real space.

Features:
- Auto-discovers breakers for a panel via Home Assistant's device registry — no manual entity list to maintain.
- Sized to your panel: a 20-space panel shows 10 rows, a 42-space panel 21. Breakers keep their true proportions at any card width and the circuit labels take the rest. On a phone the labels drop the amp reading and rating (both still in the breaker's details) so circuit names stay readable.
- Breakers show what the hardware shows, following Leviton's own handle and LED table: a green handle window when on, a white one with the handle switched over when turned off by hand, red with the handle centered when tripped. A breaker switched off remotely keeps its green handle and lights its "OFF" LED, as the real one does.
- Left/right column placement and space numbering match the physical panel (odd positions left, even positions right). 2-pole (240V) breakers span both of their positions with the single handle where Leviton puts it, open spaces show filler plates, and non-smart breakers are shown as standard Leviton breakers.
- Panel mounting orientation (normal vs. rotated 180°) is auto-detected from Leviton's own data — no config needed unless you want to force an orientation.
- Each circuit is labeled beside the door with its name, live power and current. The line under a label fills to show how close the circuit runs to its rating (amber above 50%, red above 80%). Over-current, over-voltage, under-voltage and fault alarms turn the label red.
- Click a breaker's rocker to switch it. The card asks for confirmation first and shows the breaker as switching until Leviton confirms the change. Needs **Allow Breaker Control** in the integration options.
- Click a label, or anywhere else on a breaker, for its detail sheet: on/off control, Identify (Blink LED), live power, current and load, today's and lifetime energy, every alarm, the raw breaker state and last change reason, Bluetooth signal, model, firmware and serial number. Each row opens Home Assistant's own dialog (with history) for that entity, and **Device page** goes to the breaker's device.
- Gen1 breakers can be tripped remotely but not reset remotely — trying to turn one on explains that instead of sending a command that would do nothing.
- Above the door, the cover shows the panel's load, each leg's voltage and current, line frequency, today's energy and your CT clamps (e.g. Grid, Solar), with pilot lights for the cloud connection, Wi-Fi signal, and a firmware update when one is available.
- Knows your sub-panels once you say which breaker feeds each one (see [Sub-panels](#sub-panels)): the feeding breaker shows the sub-panel's live Watts/Amps, and clicking it opens the sub-panel.
- Follows your theme: with a dark theme the panel is shown under dimmer lighting.
- Speaks your language: the card's texts follow the language set in your Home Assistant profile (see [Languages](#languages)).
- Can also be a page of its own in Home Assistant's sidebar, with no dashboard to set up (see [Sidebar page](#sidebar-page)).

### 1. Install the card file

Nothing to do here for most setups — the integration serves the card directly from its own `custom_components/ldata/www/` folder and registers it as a Lovelace resource automatically, so there's no file to copy and no manual "Add Resource" step. Just make sure Home Assistant has been **restarted** (not just reloaded) after installing or updating the integration. The registration runs at startup, and after an update it points browsers at the new card, so no hard refresh is needed. The card's images are served from the same folder, so there is nothing else to install.

If your dashboard is in legacy YAML mode (not the default UI/storage mode), auto-registration doesn't apply and you'll need to add the resource manually: URL `/ldata_static/ldata-panel-card.js`, type **JavaScript Module**. Use that exact URL rather than a copy of the file somewhere else, so the card can find its images next to it. After an update, a hard browser refresh (Ctrl+Shift+R / Cmd+Shift+R) picks up the new card.

### 2. Add the card to a dashboard

1. Edit a dashboard, click **+ Add Card**, and choose **LDATA Panel Card**. It picks your panel automatically; if you have more than one, choose the panel in the card's editor, where the options below can also be set.
2. Or choose **Manual** and use the YAML below, filling in `device_id` with your panel's device (find it under **Settings > Devices & Services > Devices**, click your LDATA/LWHEM panel — not a breaker — and copy the device ID from the page URL).

```yaml
type: custom:ldata-panel-card
device_id: <panel device id>
title: "Main Panel"        # optional, defaults to the device's name
show_power: true           # optional, live Watts/Amps on each circuit label
show_alarms: true          # optional, flag over-current/over-voltage/under-voltage alarms
toggle: true               # optional, let each breaker's rocker switch it (needs Allow Breaker Control)
confirm: true              # optional, ask before switching a breaker
show_panel_info: true      # optional, the panel's own readings above the door
appearance: auto           # optional, auto (follow theme), light, or dark (dimmed lighting)
# main_breaker: 200        # optional, show a main breaker with this rating (Leviton doesn't report it)
# rotate_180: true         # optional override — only set this if auto-detected orientation is wrong
```

If you have multiple panels, add one card per panel, each with its own `device_id`.

### Showing live CT (Grid/Solar) Watts and Amps above the panel card

The card already shows each CT clamp's live power above the door. If you'd also like those readings as their own tiles or trend graphs, add standard Home Assistant cards above the panel card using your CT clamp's own sensors. Each CT is its own device, named after its usage type (e.g. "Grid", "Solar") — find its Watts/Amps entity IDs under **Settings > Devices & Services > Devices**, click the CT device (linked under your panel), and copy them from its Sensors tab.

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

### Sub-panels

Leviton reports each load center separately; nothing in its data says that one of them is a sub-panel fed from a breaker in another. Tell the integration once and every panel card uses it, on a dashboard and on the [sidebar page](#sidebar-page) alike:

1. Open **Settings > Devices & Services > Leviton LDATA > Configure** and expand **Sub-panels**. The section is there when the integration has found two or more load centers.
2. Each load center has a field under its name. For a sub-panel, choose the breaker in the other load center that feeds it (listed as *load center · position · breaker name*). Leave the others on **Not a sub-panel**.
3. Save. The integration reloads, and the link shows without a restart.

What you get:

- A **"dumb" (non-smart) feeder breaker** has no monitoring data of its own. Linked, its label shows the sub-panel's live Watts/Amps instead, printed in blue with a "↳ sub-panel name" prefix, so it reads at a glance as "feeds another panel" rather than "just unmonitored". Clicking it opens the sub-panel.
- A **smart feeder breaker** stays a breaker, with its own readings and rocker. Its detail sheet gains a **Feeds *sub-panel*** row that opens the sub-panel.
- On a dashboard the sub-panel opens in a popup; on the sidebar page it opens the sub-panel's own tab.

A load center has one feed, a sub-panel can feed another sub-panel, and two load centers cannot feed each other.

#### Per-card extras in YAML

The card's own `sub_panels` option still works. It adds to what is set in the integration's options, and wins for the same breaker, so it is the place for the two things the integration does not ask about (a dumb breaker's rating, and a dashboard view to open instead of the popup). A card can also link a breaker that way with nothing set in the options:

```yaml
type: custom:ldata-panel-card
device_id: <main panel device id>
sub_panels:
  - breaker_position: 9                    # the dumb breaker's slot number (printed beside it on the panel)
    panel_device_id: <sub-panel device id>  # find under Settings > Devices & Services > Devices, same as device_id above
    rating: 50                             # optional — see below
```

Add one entry per breaker — a single card can link more than one, e.g. if a panel has two breakers each feeding a different sub-panel. `panel_device_id` can be left out for a breaker that is already linked in the integration's options.

Leviton's API never reports a rating for a dumb breaker (it's not a smart device, so there's no data on it at all) — if you know the breaker's own max amp rating (e.g. it's a 50A double-pole feeding the sub-panel), add `rating` and it shows on the label the same way a smart breaker's does.

Clicking the linked breaker opens that sub-panel's own full breaker layout right there in a popup — a live, independent `ldata-panel-card` for the sub-panel's `device_id`, with nothing more to configure than what's already in the entry above. Close it with ✕, Escape, or by clicking outside it.

If you'd rather leave this card entirely and jump to a real dashboard view instead — say the sub-panel already has its own `ldata-panel-card` on some other dashboard — add `view_path` with the URL path to it (open that dashboard/view in your browser and copy the path after the domain, e.g. `/lovelace/DASHBOARD_NAME`) and it replaces the popup with a normal page navigation:

```yaml
sub_panels:
  - breaker_position: 9
    panel_device_id: <sub-panel device id>
    view_path: /lovelace/DASHBOARD_NAME   # optional override — see above
```

There's no registry mapping a device id to "the dashboard view showing its card" — a device can appear on any number of dashboards or none — so this can't be auto-detected; the popup is the default precisely because it needs nothing beyond `panel_device_id`, and `view_path` only takes effect once you set it explicitly.

## Sidebar page

The integration can add a **Load Center** item to Home Assistant's sidebar. It opens a full page with the panel card of your load center. With more than one load center, each has its own tab at the top of the page, so every panel gets the full width. There is no dashboard to create and nothing to configure on the card.

It is **off by default**. Turn it on with **Show the load center in the sidebar**, either when you first set the integration up or later under **Settings > Devices & Services > Leviton LDATA > Configure**. The item appears (or disappears) as soon as you save; no restart is needed.

- The tabs are in name order, with a sub-panel right after the load center that feeds it (see [Sub-panels](#sub-panels)). Breakers are switched, and their details opened, exactly as on the dashboard card.
- Clicking a breaker that feeds a sub-panel opens that sub-panel's tab, and the sub-panel's page has a **Fed from** link back. Each tab has its own address (`/ldata/<device id>`), so the browser's back button works and a wall tablet can be left on one load center.
- If you have more than one LDATA entry (one per residence), there is still a single sidebar item. It shows the load centers of every entry that has the option turned on.
- The item is there as soon as Home Assistant starts and stays while the integration reloads or cannot reach Leviton, so a wall tablet left on the page stays on it. Until the integration has data, the breakers show as unavailable.
- The page uses the card's defaults. For the card's options (a main breaker, lighting, and so on), add the card to a dashboard instead; both can be used at the same time.
- The item's name in the sidebar is in the language Home Assistant itself is set to (**Settings > System > General**). Home Assistant shows one name to all users, so it does not follow each user's own language the way the page does. You can hide or move the item like any other by editing the sidebar.

## Languages

The panel card, the sidebar page, the setup and options dialogs, and the integration's two actions are translated into:

Chinese (Simplified and Traditional), Czech, Danish, Dutch, English, Finnish, French, German, Hungarian, Italian, Norwegian Bokmål, Polish, Portuguese (Portugal and Brazil), Romanian, Russian, Spanish (Spain and Latin America), Swedish and Ukrainian.

These are the languages of the countries where Home Assistant is used most, covering roughly 94% of installations that report to [Home Assistant Analytics](https://analytics.home-assistant.io/). Everything follows the language in your Home Assistant profile; any other language gets English.

Entity names (for example "Kitchen Watts") stay in English. The panel card finds each breaker's entities by those names, so translating them would break existing dashboards and automations.

To add or correct a language, copy `custom_components/ldata/translations/en.json` to `<language code>.json` (Home Assistant's own code, such as `ja` or `pt-BR`), translate the values and leave the keys and the `{placeholders}` as they are. Add the code to `LANGUAGES` in `tests/test_translations.py`; `python3 -m pytest tests/test_translations.py` then checks the file.

## Decora Smart Wi-Fi Support

Optional support for Leviton's **Decora Smart Wi-Fi** product line � a separate line of devices from the LDATA/WHEM breaker panels above (switches, dimmers, fans, outlets, GFCI outlets, and Wi-Fi bridges), fetched from the same Leviton cloud account via a different API. Off by default � most LDATA users don't have any of these, and leaving it off avoids extra API calls on every update.

### Enabling it

Turn on **Enable Decora Smart Wi-Fi devices** � either during initial setup, or later via **Settings > Devices & Services > Leviton LDATA > Configure**. Home Assistant will discover every supported Decora device on your account automatically; no device IDs or manual entity setup required.

### What gets created

Each Decora device becomes its own HA device, with entities depending on its type:

- **Lights & dimmers** � a `light` entity (on/off, plus brightness if the device supports dimming).
- **Fans** � a `fan` entity (on/off, plus speed if supported).
- **Switches, outlets, and GFCI outlets** � a `switch` entity.
- **GFCI outlets specifically** � an additional fault-status `binary_sensor` and `sensor` (Protected/Fault/Test), plus a buzzer enable/disable `switch` and a silence-alert `button`.
- **Every device** � a Wi-Fi signal strength `sensor`, a connectivity `binary_sensor`, and an identify `button` (blinks the device's LED so you can find it physically).
- **Dimmable/motion-capable devices** � config `select` entities for things like auto-shutoff time, status LED behavior, fade rate, and motion sensor timing/mode, where the device reports support for them.

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

## Firmware Update Notifications

Your panel and any Decora devices each get a firmware `update` entity (Settings > Devices & Services > your device) that reports when Leviton has a newer firmware version available — installing it still happens in the My Leviton app, this is detection only.

To get notified when one becomes available, import this blueprint and create an automation from it — it automatically covers every current and future LDATA `update.*` entity, no per-device setup required:

[![Open your Home Assistant instance and show the blueprint import dialog with a specific blueprint pre-filled.](https://my.home-assistant.io/badges/blueprint_import.svg)](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fraw.githubusercontent.com%2Frwoldberg%2Fldata-ha%2Fmain%2Fblueprints%2Fautomation%2Fldata_firmware_notify.yaml)

By default it creates a persistent notification inside Home Assistant. To get a mobile push instead, set the blueprint's "Notification action" input to your device's notify action (e.g. `notify.mobile_app_your_phone`, found under Settings > Devices & Services > Mobile App > your phone).

## Options

Addon is auto reloading on submit.
- HA Inform Rate (Seconds)
  - How often to update sensors in Home Assistant (2-600 seconds). Lower values = more responsive but higher system load and DB writes.
 
  - The older 1.x you could adjust the "polling rate" or how often to ask Leviton for new data, with Websocket you ask once and it turns on a fuacet of data, as any value changes it's past back to you (@ .5-1 sec rate) so the 'HA infrom rate' listens to the stream but only passes values to HA for DB writing at the rate you set.

- 120/208V Network Service (Apartment/Condo) (default off)
  - Enable this ONLY if you live in an apartment or building with a 120/208V Network setup. This correctly calculates 2-pole breaker voltages using 208V math instead of 240V. Do not enable this for a standard residential house.

- Allow Breaker Control (default off)
  - HA will not create Switch entities for breaker control (Breakers are only treated as Sensors)

- Allow Identify (default off)
  - HA will not create the per-breaker Blink LED switch used to physically locate a breaker. Independent of Allow Breaker Control � a config with breaker control off can still enable this (or vice versa) if you just want the ability to blink a breaker's LED without granting power control.

- Enable Decora Smart Wi-Fi devices (default off)
  - Discovers and creates entities for Decora Smart Wi-Fi switches, dimmers, fans, outlets, and GFCIs on your account (a separate Leviton product line from the LDATA/WHEM breaker panels). Leave off if you don't have any � it avoids extra API calls on every update. Can be set at initial setup or toggled later here.

- Show the load center in the sidebar (default off)
  - Adds a sidebar item that opens a full-page, interactive view of your load center(s). See [Sidebar page](#sidebar-page).

- Sub-panels (shown with two or more load centers)
  - For a load center that is fed from a breaker in another one, the breaker that feeds it. See [Sub-panels](#sub-panels).

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
