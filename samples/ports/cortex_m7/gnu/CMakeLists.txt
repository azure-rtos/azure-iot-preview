# This file sets arch and tool specific variables that get passed up to the
# parent CMakeLists via the PARENT_SCOPE argument passed to set()

# Linker script
# Note: You will need to change this file to match your specific MCU's memory layout
set(LINKER_SCRIPT 
    "${CMAKE_CURRENT_SOURCE_DIR}/STM32F723IEKx_FLASH.ld"
    PARENT_SCOPE
)

target_sources(${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/tx_vector_table.S
    ${CMAKE_CURRENT_LIST_DIR}/tx_initialize_low_level.S
)
