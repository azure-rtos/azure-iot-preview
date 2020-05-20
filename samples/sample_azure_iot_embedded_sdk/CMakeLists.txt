target_sources(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/main.c
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_cert.c
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_cert.h
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_ciphersuites.c
    ${CMAKE_CURRENT_LIST_DIR}/nx_azure_iot_ciphersuites.h
    ${CMAKE_CURRENT_LIST_DIR}/sample_azure_iot_embedded_sdk.c
    ${CMAKE_CURRENT_LIST_DIR}/sample_config.h
)

target_include_directories(${PROJECT_NAME}
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
)