cmake_minimum_required(VERSION 3.13.0 FATAL_ERROR)

# See https://cmake.org/cmake/help/latest/policy/CMP0079.html for more info
cmake_policy(SET CMP0079 NEW)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(NX_AZURE_DISABLE_IOT_SECURITY_MODULE ON CACHE BOOL "Disable Azure IoT Security Module (default is ON)")

# Project name, version and languages
project(azure_iot
    VERSION 6.0.0
    LANGUAGES C ASM
)

set(ENV{AZ_SDK_C_NO_SAMPLES} TRUE)
add_subdirectory(azure-sdk-for-c)

if(${NX_AZURE_DISABLE_IOT_SECURITY_MODULE})
    add_definitions(
        -DNX_AZURE_DISABLE_IOT_SECURITY_MODULE
    )
else()
    add_subdirectory(azure_iot_security_module)
endif()

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
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
        $<$<NOT:$<BOOL:${NX_AZURE_DISABLE_IOT_SECURITY_MODULE}>>:${CMAKE_CURRENT_LIST_DIR}/azure_iot_security_module>
)

target_compile_definitions(${PROJECT_NAME} PUBLIC "AZ_NO_PRECONDITION_CHECKING")

# Define any required dependencies between this library and others
target_link_libraries(${PROJECT_NAME}
    PUBLIC
        "azrtos::nx_cloud"
        az_iot_hub
        az_iot_provisioning
        $<$<NOT:$<BOOL:${NX_AZURE_DISABLE_IOT_SECURITY_MODULE}>>:iot_security_module>
)