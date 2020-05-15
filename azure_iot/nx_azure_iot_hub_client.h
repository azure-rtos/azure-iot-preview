/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

/**
 * @file nx_azure_iot_hub_client.h
 *
 * @brief Definition for the Azure IoT Hub client.
 * @remark The IoT Hub MQTT protocol is described at
 * https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-mqtt-support.
 *
 */

#ifndef NX_AZURE_IOT_HUB_CLIENT_H
#define NX_AZURE_IOT_HUB_CLIENT_H

#ifdef __cplusplus
extern   "C" {
#endif

#include "az_iot_hub_client.h"
#include "nx_azure_iot.h"
#include "nx_api.h"
#include "nx_cloud.h"
#include "nxd_dns.h"
#include "nxd_mqtt_client.h"

#define NX_AZURE_IOT_HUB_NONE                                       0x00000000 /**< Value denoting a message is of "None" type */
#define NX_AZURE_IOT_HUB_ALL_MESSAGE                                0xFFFFFFFF /**< Value denoting a message is of "all" type */
#define NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE                    0x00000001 /**< Value denoting a message is a cloud-to-device message */
#define NX_AZURE_IOT_HUB_DIRECT_METHOD                              0x00000002 /**< Value denoting a message is a direct method */
#define NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES                     0x00000004 /**< Value denoting a message is a device twin message */
#define NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES             0x00000008 /**< Value denoting a message is a device twin desired properties message */
#define NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE   0x00000010 /**< Value denoting a message is a device reported properties response */

/* Set the default timeout for DNS query.  */
#ifndef NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT
#define NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT             (5 * NX_IP_PERIODIC_RATE)
#endif /* NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT */

/* Set the default token expiry in secs.  */
#ifndef NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY
#define NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY            (3600)
#endif /* NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY */

/* Define AZ IoT Hub Client state.  */
#define NX_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED    0 /**< The client is not connected */
#define NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING       1 /**< The client is connecting */
#define NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED        2 /**< The client is connected */


typedef struct NX_AZURE_IOT_THREAD_STRUCT
{
    TX_THREAD                              *thread_ptr;
    struct NX_AZURE_IOT_THREAD_STRUCT      *thread_next;
    UINT                                    thread_message_type;
    UINT                                    thread_expected_id;     /* Used by device twin. */
    UINT                                    thread_response_status; /* Used by device twin. */
    NX_PACKET                              *thread_received_message;
} NX_AZURE_IOT_THREAD;

/* Forward declration*/
struct NX_AZURE_IOT_HUB_CLIENT_STRUCT;

typedef struct NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE_STRUCT
{
    NX_PACKET                              *message_head;
    NX_PACKET                              *message_tail;
    VOID                                  (*message_callback)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, VOID *args);
    VOID                                   *message_callback_args;
    UINT                                  (*message_process)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, NX_PACKET *packet_ptr,
                                                             ULONG topic_offset, USHORT topic_length);
} NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE;

/**
 * @brief Azure IoT Hub Client struct
 *
 */
typedef struct NX_AZURE_IOT_HUB_CLIENT_STRUCT
{
    NX_AZURE_IOT                           *nx_azure_iot_ptr;

    UINT                                    nx_azure_iot_hub_client_state;
    NX_AZURE_IOT_THREAD                    *nx_azure_iot_hub_client_thread_suspended;
    NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE nx_azure_iot_hub_client_c2d_message;
    NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE nx_azure_iot_hub_client_device_twin_message;
    NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE nx_azure_iot_hub_client_device_twin_desired_properties_message;
    NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE nx_azure_iot_hub_client_direct_method_message;
    VOID                                  (*nx_azure_iot_hub_client_report_properties_response_callback)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr,
                                                                                                         UINT request_id,
                                                                                                         UINT response_status,
                                                                                                         VOID *args);
    VOID                                   *nx_azure_iot_hub_client_report_properties_response_callback_args;

    VOID                                  (*nx_azure_iot_hub_client_connection_status_callback)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, UINT status);
    UINT                                  (*nx_azure_iot_hub_client_token_refresh)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr,
                                                                                   ULONG expiry_time_secs, UCHAR *key, UINT key_len,
                                                                                   UCHAR *sas_buffer, UINT sas_buffer_len, UINT *sas_length);

    UINT                                    nx_azure_iot_hub_client_request_id;
    UCHAR                                  *nx_azure_iot_hub_client_symmetric_key;
    UINT                                    nx_azure_iot_hub_client_symmetric_key_length;
    NX_AZURE_IOT_RESOURCE                   nx_azure_iot_hub_client_resource;

    az_iot_hub_client                       iot_hub_client_core;
} NX_AZURE_IOT_HUB_CLIENT;


/**
 * @brief Initialize Azure IoT hub instance
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] nx_azure_iot_ptr A pointer to a #NX_AZURE_IOT.
 * @param[in] host_name A `UCHAR` pointer to IoTHub hostname. Must be `NULL` terminated.
 * @param[in] host_name_length Length of `host_name`. Does not include the `NULL` terminator.
 * @param[in] device_id A `UCHAR` pointer to the device ID.
 * @param[in] device_id_length Length of the `device_id`. Does not include the `NULL` terminator.
 * @param[in] module_id A `UCHAR` pointer to the module ID.
 * @param[in] module_id_length Length of the `module_id`. Does not include the `NULL` terminator.
 * @param[in] crypto_array A pointer to an array of `NX_CRYPTO_METHOD`.
 * @param[in] crypto_array_size Size of `crypto_array`.
 * @param[in] cipher_map A pointer to an array of `NX_CRYPTO_CIPHERSUITE`.
 * @param[in] cipher_map_size Size of `cipher_map`.
 * @param[in] metadata_memory A `UCHAR` pointer to metadata memory buffer.
 * @param[in] memory_size Size of `metadata_memory`.
 * @param[in] trusted_certificate A pointer to `NX_SECURE_X509_CERT`, which are the server side certs.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully initialized the Azure IoT hub client.
 */
UINT nx_azure_iot_hub_client_initialize(NX_AZURE_IOT_HUB_CLIENT* hub_client_ptr,
                                        NX_AZURE_IOT *nx_azure_iot_ptr,
                                        UCHAR *host_name, UINT host_name_length,
                                        UCHAR *device_id, UINT device_id_length,
                                        UCHAR *module_id, UINT module_id_length,
                                        const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                        const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                        UCHAR *metadata_memory, UINT memory_size,
                                        NX_SECURE_X509_CERT *trusted_certificate);

/**
 * @brief Deinitialize the Azure IoT Hub instance.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully de-initialized the Azure IoT hub client.
 */
UINT nx_azure_iot_hub_client_deinitialize(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Set the client certificate in the IoT Hub client.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] device_certificate A pointer to a `NX_SECURE_X509_CERT`, which is the device certificate.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully added device certificate to AZ IoT Hub Instance.
 */
UINT nx_azure_iot_hub_client_device_cert_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate);

/**
 * @brief Set symmetric key in the IoT Hub client.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] symmetric_key A pointer to a symmetric key.
 * @param[in] symmetric_key_length Length of `symmetric_key`.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successfully set symmetric key to IoTHub client.
 */
UINT nx_azure_iot_hub_client_symmetric_key_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                               UCHAR *symmetric_key, UINT symmetric_key_length);

/**
 * @brief Connect to IoT Hub.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] clean_session Can be set to `0` to re-use current session, or `1` to start new session
 * @param[in] wait_option Number of ticks to wait for internal resources to be available.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if connected to Azure IoT Hub.
 */
UINT nx_azure_iot_hub_client_connect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                     UINT clean_session, UINT wait_option);

/**
 * @brief Disconnect from IoT Hub.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if client disconnects.
 */
UINT nx_azure_iot_hub_client_disconnect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Sets connection status callback function
 * @details This routine sets the connection status callback. This callback function is
 *          invoked when IoT Hub status is changed, such as when the client is connected to IoT Hub.
 *          The different statuses include:
 *
 *          - #NX_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED
 *          - #NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING
 *          - #NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED
 *
 *          Setting the callback function to `NULL` disables the callback function.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] connection_status_cb Pointer to a callback function invoked on connection status is changed.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if connection status callback is set.
 */
UINT nx_azure_iot_hub_client_connection_status_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            VOID (*connection_status_cb)(struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *hub_client_ptr, UINT status));

/**
 * @brief Sets receive callback function
 * @details This routine sets the IoT Hub receive callback function. This callback
 *          function is invoked when a message is received from Azure IoT hub. Setting the
 *          callback function to `NULL` disables the callback function. Message types can be:
 *
 *          - #NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE
 *          - #NX_AZURE_IOT_HUB_DIRECT_METHOD
 *          - #NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES
 *          - #NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] message_type Message type of callback function.
 * @param[in] callback_ptr Pointer to a callback function invoked if the specified message type is received.
 * @param[in] callback_args Pointer to an argument passed to callback function.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS if callback function is set successfully.
 */
UINT nx_azure_iot_hub_client_receive_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        VOID *args),
                                                  VOID *callback_args);

/**
 * @brief Creates telemetry message.
 * @details This routine prepares a packet for sending telemetry data. After the packet is properly created,
 *          application can add additional user-defined properties before sending out.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[out] packet_pptr Returned allocated `NX_PACKET` on success.
 * @param[in] wait_option Ticks to wait if no packet is available.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if a packet is allocated.
 */
UINT nx_azure_iot_hub_client_telemetry_message_create(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      NX_PACKET **packet_pptr,
                                                      UINT wait_option);

/**
 * @brief Deletes telemetry message
 *
 * @param[in] packet_ptr The `NX_PACKET` to release.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if a packet is deallocated.
 */
UINT nx_azure_iot_hub_client_telemetry_message_delete(NX_PACKET *packet_ptr);

/**
 * @brief Add property to telemetry message
 * @details This routine allows an application to add user-defined properties to a telemetry message
 *          before it is being sent. This routine can be called multiple times to add all the properties to
 *          the message. The properties are stored in the sequence which the routine is being called.
 *          The property must be added after a telemetry packet is created, and before the telemetry
 *          message is being sent.
 *
 * @param[in] packet_ptr A pointer to telemetry property packet.
 * @param[in] property_name Pointer to property name.
 * @param[in] property_name_length Length of property name.
 * @param[in] property_value Pointer to property value.
 * @param[in] property_value_length Length of property value.
 * @param[in] wait_option Ticks to wait if packet needs to be expanded.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if property is added.
 */
UINT nx_azure_iot_hub_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    UCHAR *property_name, USHORT property_name_length,
                                                    UCHAR *property_value, USHORT property_value_length,
                                                    UINT wait_option);

/**
 * @brief Sends telemetry message to IoTHub.
 * @details This routine sends telemetry to IoTHub, with `packet_ptr` containing all the properties.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] packet_ptr A pointer to telemetry property packet.
 * @param[in] telemetry_data Pointer to telemetry data.
 * @param[in] data_size Size of telemetry data.
 * @param[in] wait_option Ticks to wait for message to be sent.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if telemetry message is sent out.
 */
UINT nx_azure_iot_hub_client_telemetry_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, NX_PACKET *packet_ptr,
                                            UCHAR *telemetry_data, UINT data_size, UINT wait_option);

/**
 * @brief Enable receiving C2D message from IoTHub.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if C2D message receiving is enabled.
 */
UINT nx_azure_iot_hub_client_cloud_message_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Disables receiving C2D message from IoTHub
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if C2D message receiving is disabled.
 */
UINT nx_azure_iot_hub_client_cloud_message_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Receives C2D message from IoTHub
 * @details This routine receives C2D message from IoT Hub. If there are no messages in the receive
 *          queue, this routine can block.The amount of time it waits for a message is determined
 *          by the `wait_option` parameter.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[out] packet_pptr Return a `NX_PACKET` pointer with C2D message on success.
 * @param[in] wait_option Ticks to wait for message to arrive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if C2D message is received.
 */
UINT nx_azure_iot_hub_client_cloud_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, NX_PACKET **packet_pptr, UINT wait_option);

/**
 * @brief Retrieve the property with given property name in the C2D message.
 *
 * @param[in] hub_client_ptr A pointer to a NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] packet_ptr Pointer to NX_PACKET containing C2D message.
 * @param[in] property_name A `UCHAR` pointer to property name.
 * @param[in] property_name_length Length of `property_name`.
 * @param[out] property_value Pointer to `UCHAR` array that contains property values.
 * @param[out] property_value_length A `USHORT` pointer to size of `property_value`.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if property is found and copied successfully into user buffer.
 *   @retval #NX_AZURE_IOT_NOT_FOUND If property is not found.
 */
UINT nx_azure_iot_hub_client_cloud_message_property_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, NX_PACKET *packet_ptr,
                                                        UCHAR *property_name, USHORT property_name_length,
                                                        UCHAR **property_value, USHORT *property_value_length);

/**
 * @brief Enables device twin feature
 * @details This routine enables device twin feature.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if device twin feature is enabled.
 */
UINT nx_azure_iot_hub_client_device_twin_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Disables device twin feature
 * @details This routine disables device twin feature.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if device twin feature is disabled.
 */
UINT nx_azure_iot_hub_client_device_twin_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Sets reported properties response callback function
 * @details This routine sets the reponse receive callback function for repoerted properties. This callback
 *          function is invoked when a response is received from Azure IoT hub for reported properties and no
 *          thread is waiting for response. Setting the callback function to `NULL` disables the callback
 *          function.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] callback_ptr Pointer to a callback function invoked.
 * @param[in] callback_args Pointer to an argument passed to callback function.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if callback function is set successfully.
 */
UINT nx_azure_iot_hub_client_report_properties_response_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status,
                                                                           VOID *args),
                                                                     VOID *callback_args);

/**
 * @brief Send device twin reported properties to IoT Hub
 * @details This routine sends device twin reported properties to IoT Hub.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] message_buffer JSON document containing the reported properties.
 * @param[in] message_length Length of JSON document.
 * @param[out] request_id_ptr Request Id assigned to the request.
 * @param[out] response_status_ptr Status return for successful send of reported properties.
 * @param[in] wait_option Ticks to wait for message to send.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if device twin reported properties is sent successfully.
 */
UINT nx_azure_iot_hub_client_device_twin_reported_propetries_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                  UCHAR *message_buffer, UINT message_length,
                                                                  UINT *request_id_ptr, UINT *response_status_ptr,
                                                                  UINT wait_option);

/**
 * @brief Request complete device twin properties
 * @details This routine requests complete device twin properties.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT
 * @param[in] wait_option Ticks to wait for sending request.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if device twin properties is requested successfully.
 */
UINT nx_azure_iot_hub_client_device_twin_properties_request(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT wait_option);

/**
 * @brief Receive complete device twin properties
 * @details This routine receives complete device twin properties.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT
 * @param[out] packet_pptr Pointer to #NX_PACKET* that contains complete twin document.
 * @param[in] wait_option Ticks to wait for message to receive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if device twin properties is received successfully.
 */
UINT nx_azure_iot_hub_client_device_twin_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            NX_PACKET **packet_pptr, UINT wait_option);

/**
 * @brief Receive desired properties form IoTHub
 * @details This routine receives desired properties from IoTHub.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[out] packet_pptr Pointer to #NX_PACKET* that contains complete twin document.
 * @param[in] wait_option Ticks to wait for message to receive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if desired properties is received successfully.
 */
UINT nx_azure_iot_hub_client_device_twin_desired_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                    NX_PACKET **packet_pptr, UINT wait_option);

/**
 * @brief Enables receiving direct method messages from IoTHub
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @return
 *   @retval #NX_AZURE_IOT_SUCCESS Successful if direct method message receiving is enabled.
 */
UINT nx_azure_iot_hub_client_direct_method_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Disables receiving direct method messages from IoTHub
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if direct method message receiving is disabled.
 */
UINT nx_azure_iot_hub_client_direct_method_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

/**
 * @brief Receives direct method message from IoTHub
 * @details This routine receives direct method message from IoT Hub. If there are no
 *          messages in the receive queue, this routine can block. The amount of time it waits for a
 *          message is determined by the `wait_option` parameter.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[out] method_name_pptr Return a pointer to method name on success.
 * @param[out] method_name_length_ptr Return length of `method_name_pptr` on success.
 * @param[out] context_pptr Return a pointer to the context pointer on success.
 * @param[out] context_length_ptr Return length of `context` on success.
 * @param[out] packet_pptr Return `NX_PACKET` containing the method payload on success.
 * @param[in] wait_option Ticks to wait for message to arrive.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if direct method message is received.
 */
UINT nx_azure_iot_hub_client_direct_method_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                           UCHAR **method_name_pptr, USHORT *method_name_length_ptr,
                                                           VOID **context_pptr, USHORT *context_length_ptr,
                                                           NX_PACKET **packet_pptr, UINT wait_option);

/**
 * @brief Return response to direct method message from IoTHub
 * @details This routine returns response to the direct method message from IoT Hub.
 * @note request_id ties the correlation between direct method receive and response.
 *
 * @param[in] hub_client_ptr A pointer to a #NX_AZURE_IOT_HUB_CLIENT.
 * @param[in] status_code Status code for direct method.
 * @param[in] context_ptr Pointer to context return from nx_azure_iot_hub_client_direct_method_message_receive().
 * @param[in] context_length Length of context.
 * @param[in] payload  Pointer to `UCHAR` containing the payload for the direct method response. Payload is in JSON format.
 * @param[in] payload_length Length of `payload`
 * @param[in] wait_option Ticks to wait for message to send.
 * @return A `UINT` with the result of the API.
 *   @retval #NX_AZURE_IOT_SUCCESS  Successful if direct method response is send.
 */
UINT nx_azure_iot_hub_client_direct_method_message_response(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT status_code, VOID *context_ptr, USHORT context_length,
                                                            UCHAR *payload, UINT payload_length, UINT wait_option);
#ifdef __cplusplus
}
#endif
#endif /* NX_AZURE_IOT_HUB_CLIENT_H */
