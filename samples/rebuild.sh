#!/bin/bash
# A simple shell script for building the demo app
# Written by Peter Provost <peter.provost@microsoft.com>
# 
# Usage:
#    ./rebuild.sh [target_arch]
#
# Notes:
#    - target_arch must match the name of the appropriate file in the
#      cmake/ directory. Do not include the .cmake extension. 
#      Default is "cortex_m4".

# Use paths relative to this script's location
SCRIPT=$(readlink -f "$0")
BASEDIR=$(dirname "$SCRIPT")
BUILDDIR="$BASEDIR/build"

[ -z "$1" ] && TOOLCHAIN_NAME="cortex_m4" || TOOLCHAIN_NAME=$1
TOOLCHAIN_FILE=$BASEDIR/cmake/${TOOLCHAIN_NAME}.cmake

echo "Using CMake toolchain ${TOOLCHAIN_FILE}"

# If you want to build into a different directory, change this variable

# Create our build folder if required and clear it
mkdir -p $BUILDDIR
rm -rf $BUILDDIR/*

# Generate the build system using Ninja
cmake -B"$BUILDDIR" -GNinja -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE $BASEDIR
# Generate the build system using the system default
# cmake -B"$BUILDDIR" -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE $BASEDIR

# And then do the build
cmake --build $BUILDDIR
