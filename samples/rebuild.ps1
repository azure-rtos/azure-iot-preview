# A simple powershell script for building the demo app
# Written by Peter Provost <peter.provost@microsoft.com>
# 
# Usage:
#    ./rebuild.ps1 [target_arch]
#
# Notes:
#    - target_arch must match the name of the appropriate file in the
#      cmake/ directory. Do not include the .cmake extension. 
#      Default is "cortex_m4".

param([string] $TOOLCHAIN_NAME="cortex_m4")

# Use paths relative to this script's location
$BASEDIR = $PSScriptRoot
$BUILDDIR = "$BASEDIR/build"

$TOOLCHAIN_FILE = Join-Path $BASEDIR "cmake/$TOOLCHAIN_NAME.cmake"

Write-Output "Using CMake toolchain $TOOLCHAIN_FILE"

# If you want to build into a different directory, change this variable

# Create our build folder if required and clear it
New-Item -ItemType Directory -Force -Path $BUILDDIR
Remove-Item -Recurse -Force "$BUILDDIR\*.*" 

# Generate the build system using Ninja
# cmake -B"$BUILDDIR" -GNinja -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" "$BASEDIR"

# set(WIN32_FLAGS "-DTX_WIN32_DEBUG_ENABLE -DNDEBUG -D_CONSOLE -D_LIB")
# # set(LD_FLAGS "-lpthread -lrt")

# set(CMAKE_C_FLAGS   "${WIN32_FLAGS} " CACHE INTERNAL "c compiler flags")
# set(CMAKE_CXX_FLAGS "${WIN32_FLAGS} -fno-rtti -fno-exceptions" CACHE INTERNAL "cxx compiler flags")
# set(CMAKE_ASM_FLAGS "${WIN32_FLAGS} -x assembler-with-cpp" CACHE INTERNAL "asm compiler flags")
# set(CMAKE_EXE_LINKER_FLAGS "${WIN32_FLAGS} ${LD_FLAGS} -Wl,--gc-sections" CACHE INTERNAL "exe link flags")

$Win32Flags = "-DTX_WIN32_DEBUG_ENABLE -DNDEBUG -D_CONSOLE -D_LIB"
cmake -B"$BUILDDIR" -GNinja -DTHREADX_ARCH="win32" -DTHREADX_TOOLCHAIN="gnu" -DCMAKE_C_FLAGS="$win32Flags" -DCMAKE_ASM_FLAGS="$win32Flags" -DCMAKE_EXE_LINKER_FLAGS="$win32Flags" "$BASEDIR"

# Generate the build system using the system default
# cmake -B"$BUILDDIR" -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_FILE $BASEDIR

# And then do the build
cmake --build $BUILDDIR
