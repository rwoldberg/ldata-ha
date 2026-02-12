# ldata-ha
# leviton LDATA and LWHEM integration for Home Assistant (https://my.leviton.com/)

# **-Starting with v2 this integration now uses Websockets!-**

This is a home assistant integration for the LDATA and LWHEM hubs for levitons smart breakers.

<br>

If this integration has been useful to you, please consider chipping in and buying me a coffee!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/RWoldberg)

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

- Three phase (default off)
  - For Three phase setups

- Allow Breaker Control (default off)
  - HA will not create Switch entities for breaker control (Breakers are only treated as Sensors)

- Log General Integration Errors
  - Integration crashes or web errors

- Log Data Validation Warning (Spikes/Resets)
  - Outputs Warnings of Data inconsistancies from Leviton to log
  
- Log Full WebSocket Data
  - Outputs all data provided

- Enable Specific Field Logging
  - Outputs any specified field to log (field names can be seen by breifly enabling and looking at "Log Full WebSocket Data")

<img width="586" height="873" alt="image" src="https://github.com/user-attachments/assets/3c563e92-ca67-432b-a7c1-01ec247001cf" />

<br>
<br>
<br>
This is a DIY integration and is not supported or affiliated with Leviton in any way.

