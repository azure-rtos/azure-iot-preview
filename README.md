![cortex_m4](https://github.com/azure-rtos/azure-iot-preview/workflows/cortex_m4/badge.svg)
![cortex_m7](https://github.com/azure-rtos/azure-iot-preview/workflows/cortex_m7/badge.svg)

# Azure RTOS SDK for Azure IoT

This repository contains SDK for Azure IoT services. SDK uses [ThreadX](https://github.com/azure-rtos/threadx) and [NetXDuo](https://github.com/azure-rtos/netxduo) to connect to Azure IoT.

## Documentation

Documentation for this library can be found here: [Link](docs/azure_rtos_iot_sdk_api.md)

## Key Features

:heavy_check_mark: feature available  :heavy_check_mark:* feature partially available (see Description for details)  :heavy_multiplication_x: feature planned but not supported

Feature | Azure RTOS SDK for Azure IoT services  | Description
---------|----------|---------------------
 [Send device-to-cloud message](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messages-d2c) | :heavy_check_mark: | Send device-to-cloud messages to IoT Hub with the option to add custom message properties. 
 [Receive cloud-to-device messages](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-messages-c2d) | :heavy_check_mark: | Receive cloud-to-device messages and associated properties from IoT Hub.   
 [Device Twins](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-device-twins) | :heavy_check_mark: | IoT Hub persists a device twin for each device that you connect to IoT Hub.  The device can perform operations like get twin document, subscribe to desired property updates.
 [Direct Methods](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-direct-methods) | :heavy_check_mark: | IoT Hub gives you the ability to invoke direct methods on devices from the cloud.  
 [DPS - Device Provisioning Service](https://docs.microsoft.com/azure/iot-dps/) | :heavy_check_mark: | This SDK supports connecting your device to the Device Provisioning Service via, for example, [individual enrollment](https://docs.microsoft.com/azure/iot-dps/concepts-service#enrollment) using an [X.509 leaf certificate](https://docs.microsoft.com/azure/iot-dps/concepts-security#leaf-certificate).  
 Protocol | MQTT | The Azure RTOS SDK for Azure IoT services supports only MQTT.
 [Plug and Play](https://docs.microsoft.com/azure/iot-pnp/overview-iot-plug-and-play) | :heavy_check_mark: | IoT Plug and Play Preview enables solution developers to integrate devices with their solutions without writing any embedded code. 
 [ASC for IoT](https://docs.microsoft.com/azure/asc-for-iot/) | :heavy_check_mark: | The Azure Security Center for IoT security module provides a comprehensive security solution for Azure RTOS devices. 

# Building and using the library

## Prerequisites

Install the following tools:

* [CMake](https://cmake.org/download/) version 3.13.0 or later
* [GCC compilers for arm-none-eabi](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads)
* [Ninja](https://ninja-build.org/)

## Cloning the repo

```bash
$ git clone https://github.com/azure-rtos/azure-iot-preview.git
$ git submodule update --init
```

## Building Sample

```bash
$ cd samples
$ cmake -GNinja -Bbuild -DCMAKE_TOOLCHAIN_FILE=./cmake/cortex_m4.cmake .
$ cmake --build ./build
```

# Repository Structure and Usage

## Branches & Releases

The master branch has the most recent code with all new features and bug fixes. It does not represent the latest General Availability (GA) release of the library.

## Releases

Each official release (preview or GA) will be tagged to mark the commit and published to the Github releases tab, e.g. `v6.0_beta1`.

## Directory layout

```
- azure_iot
- docs
- nx_cloud
- samples
  - cmake
  - lib
    - netxduo
    - threadx
  - ports/cortex_m4/gnu
  - ports/cortex_m7/gnu
  - sample_azure_iot_embedded_sdk
```

# Sample projects

Sample projects ZIP files can be downloaded from the [Release](https://github.com/azure-rtos/azure-iot-preview/releases) associated with this repository.

NOTE: These zip files are completely self-contained and include appropriate
code from the other Azure RTOS repositories. Please refer to the LICENSE.txt file
in each ZIP file for licensing requirements.

# Security

Azure RTOS provides OEMs with components to secure communication and to create code and data isolation using underlying MCU/MPU hardware protection mechanisms. It is ultimately the responsibility of the device builder to ensure the device fully meets the evolving security requirements associated with its specific use case. In the meanwhile, with built-in support of [Azure Security Center for IoT](https://docs.microsoft.com/azure/asc-for-iot/iot-security-azure-rtos), you can detect malicious network activities and create baseline with the predefined customer alert rules.

# Licensing

License terms for using Azure RTOS are defined in the LICENSE.txt file of this repo. Please refer to this file for all definitive licensing information. No additional license fees are required for deploying Azure RTOS on hardware defined in the LICENSED-HARDWARE.txt file. If you are using hardware not defined in the LICENSED-HARDWARE.txt file or have licensing questions in general, please contact Microsoft directly at https://azure-rtos.ms-iot-contact.com/

# Contribution, feedback, issues, and professional support

If you encounter any bugs, have suggestions for new features, or if you would like to become an active contributor to this project, please follow the instructions provided in the contribution guideline for the corresponding repo.

For basic support, click Issues in the command bar or post a question to Stack Overflow using the `threadx` and `azure-rtos` tags.

Professional support plans (https://azure.microsoft.com/en-us/support/options/) are available from Microsoft.

# Additional Resources

The following are references to additional Azure RTOS and Azure IoT in general:
|   |   |
|---|---|
| Azure RTOS Website: | https://azure.microsoft.com/en-us/services/rtos/ |
| Azure RTOS Sales Questions: | https://azure-rtos.ms-iot-contact.com/ |
| Microsoft Q/A for Azure IoT: | https://docs.microsoft.com/en-us/answers/products/azure?product=iot |
| Internet of Things Show: | aka.ms/iotshow |
| IoT Tech Community: | aka.ms/iottechcommunity |
