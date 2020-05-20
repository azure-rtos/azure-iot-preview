cmake_minimum_required(VERSION 3.13.0 FATAL_ERROR)

# See https://cmake.org/cmake/help/latest/policy/CMP0079.html for more info
cmake_policy(SET CMP0079 NEW)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Project name, version and languages
project(sample_azure_iot_embedded_sdk
    VERSION 6.0.0
    LANGUAGES C ASM
)

# Include helper modules
include(utilities)

# Provide custom *_user.h files for configuration overrides
# set(TX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk/tx_user.h")
set(NX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk/nx_user.h")
# set(FX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk/fx_user.h")
# set(UX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk/ux_user.h")
# set(GX_USER_FILE "${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk/gx_user.h")

# Define this target as an executable
add_executable(${PROJECT_NAME})

# Pick up the port specific directories before the sample_azure_iot_embedded_sdk
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../nx_cloud nx_cloud)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../azure_iot azure_iot)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ports/${THREADX_ARCH}/${THREADX_TOOLCHAIN})
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk)

# Pick up the required Azure RTOS components
set(NXD_ENABLE_FILE_SERVERS OFF CACHE BOOL "Disable fileX dependency by netxduo.")
add_azrtos_component_dir(threadx)
add_azrtos_component_dir(netxduo)
# add_azrtos_component_dir(filex)
# add_azrtos_component_dir(usbx)

# For non-Windows configurations, the linker output should be .elf so we can keep track of it
if(NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".elf")
endif()

# Apply the linker scripts to the sample_azure_iot_embedded_sdk target
if(EXISTS ${LINKER_SCRIPT})
    message(STATUS "Using linker script: ${LINKER_SCRIPT}")
    target_link_options(${PROJECT_NAME} INTERFACE -T ${LINKER_SCRIPT})
endif()

# Must use the PUBLIC section for the sample_azure_iot_embedded_sdk target since the dependencies are
# just pushing source to us
target_link_libraries(${PROJECT_NAME} PUBLIC ${azrtos_targets} azrtos::azure_iot)
target_link_libraries(netxduo PRIVATE azrtos::nx_cloud)

# If not Linux or Windows, create the BIN and HEX files for flashing
if( (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Linux") AND
    (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "Windows") )
    # Custom command to copy the output file into a .BIN file
    add_custom_command( TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary ${PROJECT_NAME}.elf ${PROJECT_NAME}.bin
        COMMAND ${CMAKE_OBJCOPY} -I binary -O ihex ${PROJECT_NAME}.bin ${PROJECT_NAME}.hex
        COMMENT "Building .hex and .bin file"
    )
endif()
