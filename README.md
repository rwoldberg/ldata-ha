![GitHub Release](https://img.shields.io/github/v/release/rwoldberg/ldata-ha) ![GitHub Downloads (all assets, latest release)](https://img.shields.io/github/downloads/rwoldberg/ldata-ha/latest/total)  ![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/rwoldberg/ldata-ha/total?label=Total%20Downloads&color=blue)


# ldata-ha
# leviton LDATA and LWHEM integration for Home Assistant (https://my.leviton.com/)

# **-Starting with v2 this integration now uses Websockets!-**

This is a home assistant integration for the LDATA and LWHEM hubs for levitons smart breakers.

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


## Options

Addon is auto reloading on submit.
- HA Inform Rate (Seconds)
  - How often to update sensors in Home Assistant (2-600 seconds). Lower values = more responsive but higher system load and DB writes.
 
  - The older 1.x you could adjust the "polling rate" or how often to ask Leviton for new data, with Websocket you ask once and it turns on a fuacet of data, as any value changes it's past back to you (@ .5-1 sec rate) so the 'HA infrom rate' listens to the stream but only passes values to HA for DB writing at the rate you set.

- 120/208V Network Service (Apartment/Condo) (default off)
  - Enable this ONLY if you live in an apartment or building with a 120/208V Network setup. This correctly calculates 2-pole breaker voltages using 208V math instead of 240V. Do not enable this for a standard residential house.

- Allow Breaker Control (default off)
  - HA will not create Switch entities for breaker control (Breakers are only treated as Sensors)

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

- CT clamp and Breaker lifetime values are only available via triggering a Poll request then WS gets a update
- BLErssi on 2-pole breakers always 0 due to not reporting from Leviton

<br>
<br>
<br>
This is a DIY integration and is not supported or affiliated with Leviton in any way.

