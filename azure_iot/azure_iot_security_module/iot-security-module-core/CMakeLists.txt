cmake_minimum_required(VERSION 3.13.0 FATAL_ERROR)

set(TARGET_NAME "asc_security_core")
project(${TARGET_NAME})

# collector options
set(collector_heartbeat_enabled ON CACHE BOOL "Enable the heartbeat collector")
set(collector_network_activity_enabled OFF CACHE BOOL "Enable the network activity collector")
set(collector_system_information_enabled OFF CACHE BOOL "Enable the system information collector")
set(build_as_32 OFF CACHE BOOL "build as 32 bit")

# reslove logger log level
set(LOG_LEVELS NOTSET DEBUG INFO WARNING ERROR FATAL)
set(log_level NOTSET CACHE STRING "log_level: ${log_level} (default is NOTSET)")
set_property(CACHE log_level PROPERTY STRINGS NOTSET DEBUG INFO WARNING ERROR FATAL)
list(FIND LOG_LEVELS ${log_level} log_level_index)
if(log_level_index EQUAL -1)
    message(FATAL_ERROR "log_level must be one of ${LOG_LEVELS}")
endif()

add_library(${TARGET_NAME} STATIC
    # componets
    $<$<BOOL:${collector_heartbeat_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/collectors/collector_heartbeat.c>
    $<$<BOOL:${collector_heartbeat_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/serializer/heartbeat.c>
    $<$<BOOL:${collector_listening_ports_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/serializer/listening_ports.c>
    $<$<BOOL:${collector_network_activity_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/serializer/network_activity.c>
    $<$<BOOL:${collector_system_information_enabled}>:${CMAKE_CURRENT_LIST_DIR}/src/serializer/system_information.c>

    ${CMAKE_CURRENT_LIST_DIR}/src/serializer/extensions/custom_builder_allocator.c
    ${CMAKE_CURRENT_LIST_DIR}/src/serializer/extensions/page_allocator.c

    ${CMAKE_CURRENT_LIST_DIR}/src/collector_collection_factory.c
    ${CMAKE_CURRENT_LIST_DIR}/src/collector_collection_internal.c
    ${CMAKE_CURRENT_LIST_DIR}/src/collector_collection.c
    ${CMAKE_CURRENT_LIST_DIR}/src/collectors_info.c
    ${CMAKE_CURRENT_LIST_DIR}/src/core.c
    ${CMAKE_CURRENT_LIST_DIR}/src/logger.c
    ${CMAKE_CURRENT_LIST_DIR}/src/model/collector.c
    ${CMAKE_CURRENT_LIST_DIR}/src/model/security_message.c
    ${CMAKE_CURRENT_LIST_DIR}/src/serializer/serializer_private.c
    ${CMAKE_CURRENT_LIST_DIR}/src/serializer/serializer.c
    ${CMAKE_CURRENT_LIST_DIR}/src/utils/notifier.c
    ${CMAKE_CURRENT_LIST_DIR}/src/utils/string_utils.c
)

target_compile_definitions(${TARGET_NAME} PUBLIC
    LOG_LEVEL=${log_level_index}

    ASC_SERIALIZER_USE_CUSTOM_ALLOCATOR

    $<$<BOOL:${collector_heartbeat_enabled}>:COLLECTOR_HEARTBEAT_ENABLED>
    $<$<BOOL:${collector_network_activity_enabled}>:COLLECTOR_NETWORK_ACTIVITY_ENABLED>
    $<$<BOOL:${collector_system_information_enabled}>:COLLECTOR_SYSTEM_INFORMATION_ENABLED>
    $<$<BOOL:${collector_listening_ports_enabled}>:COLLECTOR_LISTENING_PORTS_ENABLED>
)

target_include_directories(${TARGET_NAME}
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/inc
)

set(serializer_custom_allocator ON)
add_subdirectory(deps)
target_link_libraries(${TARGET_NAME} PRIVATE
    flatccrt
)

# serializer custom allocator
target_link_libraries(flatccrt PRIVATE asc_security_core)
target_sources(flatccrt PRIVATE src/serializer/extensions/custom_emitter.c)
target_include_directories(flatccrt PRIVATE deps/flatcc/src/runtime)
