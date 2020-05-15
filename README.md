![Samples Build CI](https://github.com/azurertos/samples/workflows/Samples%20Build%20CI/badge.svg)

# Samples

This is a sample project that shows how to use threadX in your own MCU project.

This sample targets a Cortex-M4 MCU, using the ARM GCC toolchain to build.

# Usage

## Prerequisites

Before using this project, the following tools should be available on your development
environment:

* CMake 3.13+
* arm-none-eabi-gcc tools (download from from ARM)

## Building

1. git clone https://github.com/azurertos/samples.git
2. cd samples/threadx_simple
3. cmake -Bbuild -DCMAKE_TOOLCHAIN_FILE=./cmake/cortex_m4.cmake .
4. cmake --build ./build

# Resolving the git submodules

## Authentication method

Currently the submodules in this project are defined using SSH connection
strings instead of HTTPS connection strings. If you don't use SSH with git,
you will need to edit the .gitmodules file, replacing the lines that look like this

> git@github.com:azurertos/threadx.git

with lines like this

> https://github.com/azurertos/threadx.git

Then you can proceed with the next steps

## Pulling the submodules

1. git submodule init
2. git submodule update

# Customizing your build

Before you can build and flash this sample to a real device, you may  need to make a few changes:

1. Choose the correct linker script for your board. A few different Cortex-M4 starter scripts are provided in ports/cortex_m4/gnu. You will need to update the CMakeLists file in that directory as required for your hardware.

2. Update the vector table as required. The vector table, which in this sample lives in the assembly language file ports/cortex_m4/gnu/tx_vector_table.S, contains the various entry points and interrupt handlers used by your app.