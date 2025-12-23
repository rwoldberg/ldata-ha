# ldata-ha
# leviton LDATA and LWHEM integration for Home Assistant (https://my.leviton.com/)

This is a home assistant integration for the LDATA and LWHEM hubs for levitons smart breakers.

If this integration has been useful to you, please consider chipping in and buying me a coffee!

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/RWoldberg)

## Install

Use HACS and add as a custom repo. Once the integration is installed go to your integrations and follow the configuration options to specify the below:

- Username (my.leviton.com Username)
- Password (my.leviton.com Password)

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

You can set the update interval that the integration polls the cloud server (in seconds). The default is 60 seconds and the minimum is 30. Addon is reloading on submit.

- Three phase
  - For Three phase setups

- Read only
  - HA can not trip/reset breakers

- Log General Errors
  - App crashes or polling errors

- Log Data Validation Warning (Spikes/Resets)
  - Outpots Warnings of Data inconsistancies from Leviton to log
  
- Log All Raw API Data
  - Outputs all data pulled via the API to log

- Enable Specific Field Logging
  - Outputs any specified field to log (field names can be seen by breifly enabling and looking at "og All Raw API Data")

<img width="595" height="851" alt="image" src="https://github.com/user-attachments/assets/8133a0b1-4f45-4475-8129-2d5cde834de6" />





This is a diy integration and is not supported or affiliated with Leviton in any way.

