cmake_minimum_required(VERSION 3.13.0 FATAL_ERROR)

# See https://cmake.org/cmake/help/latest/policy/CMP0079.html for more info
cmake_policy(SET CMP0079 NEW)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Project name, version and languages
project(azure_iot
    VERSION 6.0.0
    LANGUAGES C ASM
)

# Define our target library and an alias for consumers
add_library(${PROJECT_NAME})
add_library("azrtos::${PROJECT_NAME}" ALIAS ${PROJECT_NAME})

target_sources(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_hub_client.c
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_hub_client.h
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_provisioning_client.c
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_provisioning_client.h
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot.c
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot.h
    
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/common/src/az_iot_common.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/src/az_iot_hub_client.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/src/az_iot_hub_client_c2d.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/src/az_iot_hub_client_methods.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/src/az_iot_hub_client_sas.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/src/az_iot_hub_client_telemetry.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/src/az_iot_hub_client_twin.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/provisioning/src/az_iot_provisioning_client.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/provisioning/src/az_iot_provisioning_client_sas.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_precondition.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/platform/noplatform/src/az_noplatform.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_json_parser.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_json_pointer.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_json_string.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_json_token.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_log.c
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/src/az_span.c
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/inc
    # TODO: this internal include is only use for compiling azure embedded sdk lib
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/core/core/internal
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/common/inc
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/hub/inc
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/iot/provisioning/inc
    ${CMAKE_CURRENT_LIST_DIR}/azure-sdk-for-c/sdk/platform/noplatform/inc
)

target_compile_definitions(${PROJECT_NAME} PUBLIC "AZ_NO_PRECONDITION_CHECKING")

# Define any required dependencies between this library and others
target_link_libraries(${PROJECT_NAME} PUBLIC "azrtos::nx_cloud")