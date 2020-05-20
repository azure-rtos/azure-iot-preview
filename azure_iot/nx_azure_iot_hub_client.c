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

/* Version: 6.0 Preview */

#include "nx_azure_iot_hub_client.h"

#include "az_version.h"

#define NX_AZURE_IOT_HUB_CLIENT_EMPTY_JSON      "{}"

#ifndef NX_AZURE_IOT_HUB_CLIENT_USER_AGENT

/* useragent e.g: DeviceClientType=c%2F1.0.0-preview.1%20%28nx%206.0%3Bazrtos%206.0%29 */
#define NX_AZURE_IOT_HUB_CLIENT_STR(C)          #C
#define NX_AZURE_IOT_HUB_CLIENT_TO_STR(x)       NX_AZURE_IOT_HUB_CLIENT_STR(x)
#define NX_AZURE_IOT_HUB_CLIENT_USER_AGENT      "DeviceClientType=c%2F" AZ_SDK_VERSION_STRING "%20%28nx%20" \
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(NETXDUO_MAJOR_VERSION) "." \
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(NETXDUO_MINOR_VERSION) "%3Bazrtos%20"\
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(THREADX_MAJOR_VERSION) "." \
                                                NX_AZURE_IOT_HUB_CLIENT_TO_STR(THREADX_MINOR_VERSION) "%29"
#endif /* NX_AZURE_IOT_HUB_CLIENT_USER_AGENT */

static VOID nx_azure_iot_hub_client_received_message_cleanup(NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE *message);
static UINT nx_azure_iot_hub_client_cloud_message_sub_unsub(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT is_subscribe);
static UINT nx_azure_iot_hub_client_process_publish_packet(UCHAR *start_ptr,
                                                           ULONG *topic_offset_ptr,
                                                           USHORT *topic_length_ptr);
static VOID nx_azure_iot_hub_client_mqtt_receive_callback(NXD_MQTT_CLIENT* client_ptr,
                                                          UINT number_of_messages);
static UINT nx_azure_iot_hub_client_c2d_process(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                NX_PACKET *packet_ptr,
                                                ULONG topic_offset,
                                                USHORT topic_length);
static UINT nx_azure_iot_hub_client_device_twin_process(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        NX_PACKET *packet_ptr,
                                                        ULONG topic_offset,
                                                        USHORT topic_length);
extern UINT _nxd_mqtt_process_publish_packet(NX_PACKET *packet_ptr, ULONG *topic_offset_ptr,
                                             USHORT *topic_length_ptr, ULONG *message_offset_ptr,
                                             ULONG *message_length_ptr);
static VOID nx_azure_iot_hub_client_mqtt_connect_notify(struct NXD_MQTT_CLIENT_STRUCT *client_ptr,
                                                        UINT status, VOID *context);
static VOID nx_azure_iot_hub_client_mqtt_disconnect_notify(NXD_MQTT_CLIENT *client_ptr);
VOID nx_azure_iot_hub_client_event_process(NX_AZURE_IOT *nx_azure_iot_ptr,
                                           ULONG common_events, ULONG module_own_events);
static VOID nx_azure_iot_hub_client_thread_dequeue(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   NX_AZURE_IOT_THREAD *thread_list_ptr);
static UINT nx_azure_iot_hub_client_sas_token_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  ULONG expiry_time_secs, UCHAR *key, UINT key_len,
                                                  UCHAR *sas_buffer, UINT sas_buffer_len, UINT *sas_length);

UINT nx_azure_iot_hub_client_initialize(NX_AZURE_IOT_HUB_CLIENT* hub_client_ptr,
                                        NX_AZURE_IOT *nx_azure_iot_ptr,
                                        UCHAR *host_name, UINT host_name_length,
                                        UCHAR *device_id, UINT device_id_length,
                                        UCHAR *module_id, UINT module_id_length,
                                        const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                        const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                        UCHAR * metadata_memory, UINT memory_size,
                                        NX_SECURE_X509_CERT *trusted_certificate)
{

UINT status;
NX_AZURE_IOT_RESOURCE *resource_ptr;
az_span hostname_span = az_span_init(host_name, (INT)host_name_length);
az_span device_id_span = az_span_init(device_id, (INT)device_id_length);
az_iot_hub_client_options options;
az_result core_result;

    if ((nx_azure_iot_ptr == NX_NULL) || (hub_client_ptr == NX_NULL) || (host_name == NX_NULL) ||
        (device_id == NX_NULL))
    {
        LogError("IoTHub client create fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    memset(hub_client_ptr, 0, sizeof(NX_AZURE_IOT_HUB_CLIENT));

    hub_client_ptr -> nx_azure_iot_ptr = nx_azure_iot_ptr;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_crypto_array = crypto_array;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_crypto_array_size = crypto_array_size;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_cipher_map = cipher_map;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_cipher_map_size = cipher_map_size;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_metadata_ptr = metadata_memory;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_metadata_size = memory_size;
    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_trusted_certificate = trusted_certificate;
    options.module_id = az_span_init(module_id, (INT)module_id_length);
    options.user_agent = AZ_SPAN_FROM_STR(NX_AZURE_IOT_HUB_CLIENT_USER_AGENT);

    core_result = az_iot_hub_client_init(&hub_client_ptr -> iot_hub_client_core,
                                         hostname_span, device_id_span, &options);
    if (az_failed(core_result))
    {
        LogError("IoTHub client failed initialization with error : 0x%08x", core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    /* Set resource pointer.  */
    resource_ptr = &(hub_client_ptr -> nx_azure_iot_hub_client_resource);

    /* Create MQTT client.  */
    status = _nxd_mqtt_client_cloud_create(&(resource_ptr -> resource_mqtt),
                                           (CHAR *)nx_azure_iot_ptr -> nx_azure_iot_name,
                                           "", 0,
                                           nx_azure_iot_ptr -> nx_azure_iot_ip_ptr,
                                           nx_azure_iot_ptr -> nx_azure_iot_pool_ptr,
                                           &nx_azure_iot_ptr -> nx_azure_iot_cloud);
    if (status)
    {
        LogError("IoTHub client create fail: MQTT CLIENT CREATE FAIL: 0x%02x", status);
        return(status);
    }

    /* Set mqtt receive notify.  */
    status = nxd_mqtt_client_receive_notify_set(&(resource_ptr -> resource_mqtt),
                                                nx_azure_iot_hub_client_mqtt_receive_callback);
    if (status)
    {
        LogError("IoTHub client set message callback: 0x%02x", status);
        nxd_mqtt_client_delete(&(resource_ptr -> resource_mqtt));
        return(status);
    }

    /* Obtain the mutex.   */
    tx_mutex_get(nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Link the resource. */
    resource_ptr -> resource_data_ptr = (VOID *)hub_client_ptr;
    resource_ptr -> resource_type = NX_AZURE_IOT_RESOURCE_IOT_HUB;
    nx_azure_iot_resource_add(nx_azure_iot_ptr, resource_ptr);

    /* Release the mutex.  */
    tx_mutex_put(nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_connection_status_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            VOID (*connection_status_cb)(
                                                                  struct NX_AZURE_IOT_HUB_CLIENT_STRUCT *client_ptr,
                                                                  UINT status))
{

    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NX_NULL) || (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError("IoTHub client connect fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Set callback function for disconnection. */
    nxd_mqtt_client_disconnect_notify_set(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                          nx_azure_iot_hub_client_mqtt_disconnect_notify);

    /* Obtain the mutex.   */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Set connection status callback.  */
    hub_client_ptr -> nx_azure_iot_hub_client_connection_status_callback = connection_status_cb;

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    /* Return success.  */
    return(NX_AZURE_IOT_SUCCESS);

}

UINT nx_azure_iot_hub_client_connect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                     UINT clean_session, UINT wait_option)
{

UINT            status;
NXD_ADDRESS     server_address;
NX_AZURE_IOT_RESOURCE *resource_ptr;
NXD_MQTT_CLIENT *mqtt_client_ptr;
UCHAR           *buffer_ptr;
UINT            buffer_size;
VOID            *buffer_context;
UINT            buffer_length;
UINT            dns_timeout = wait_option;
ULONG           expiry_time_secs;
az_result       core_result;

    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NX_NULL) || (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError("IoTHub client connect fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Check for status.  */
    if (hub_client_ptr -> nx_azure_iot_hub_client_state == NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED)
    {
        LogError("IoTHub client already connected");
        return(NX_AZURE_IOT_ALREADY_CONNECTED);
    }
    else if (hub_client_ptr -> nx_azure_iot_hub_client_state == NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING)
    {
        LogError("IoTHub client is connecting");
        return(NX_AZURE_IOT_CONNECTING);
    }

    /* Set the DNS timeout as NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT for non-blocking mode.*/
    if (dns_timeout == 0)
    {
        dns_timeout = NX_AZURE_IOT_HUB_CLIENT_DNS_TIMEOUT;
    }

    /* Resolve the host name.  */
    status = nxd_dns_host_by_name_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_dns_ptr,
                                      az_span_ptr(hub_client_ptr -> iot_hub_client_core._internal.iot_hub_hostname),
                                      &server_address, dns_timeout, NX_IP_VERSION_V4);
    if (status)
    {
        LogError("IoTHub client connect fail: DNS RESOLVE FAIL: 0x%02x", status);
        return(status);
    }

    /* Allocate buffer for client id, username and sas token.  */
    status = nx_azure_iot_buffer_allocate(hub_client_ptr -> nx_azure_iot_ptr,
                                          &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client failed initialization: BUFFER ALLOCATE FAIL");
        return(status);
    }

    /* Obtain the mutex.   */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Set resource pointer and buffer context.  */
    resource_ptr = &(hub_client_ptr -> nx_azure_iot_hub_client_resource);

    /* Build client id.  */
    buffer_length = buffer_size;
    core_result = az_iot_hub_client_get_client_id(&hub_client_ptr -> iot_hub_client_core,
                                                  (CHAR *)buffer_ptr, buffer_length, &buffer_length);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        nx_azure_iot_buffer_free(buffer_context);
        LogError("IoTHub client failed to get clientId with error : 0x%08x", core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }
    resource_ptr -> resource_mqtt_client_id = buffer_ptr;
    resource_ptr -> resource_mqtt_client_id_length = buffer_length;

    /* Update buffer for user name.  */
    buffer_ptr += resource_ptr -> resource_mqtt_client_id_length;
    buffer_size -= resource_ptr -> resource_mqtt_client_id_length;

    /* Build user name.  */
    buffer_length = buffer_size;
    core_result = az_iot_hub_client_get_user_name(&hub_client_ptr -> iot_hub_client_core,
                                                  (CHAR *)buffer_ptr, buffer_length, &buffer_length);
    if (az_failed(core_result))
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        nx_azure_iot_buffer_free(buffer_context);
        LogError("IoTHub client connect fail, with error 0x%08x", core_result);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }
    resource_ptr -> resource_mqtt_user_name = buffer_ptr;
    resource_ptr -> resource_mqtt_user_name_length = buffer_length;

    /* Build sas token.  */
    resource_ptr -> resource_mqtt_sas_token = buffer_ptr + buffer_length;
    resource_ptr -> resource_mqtt_sas_token_length = buffer_size - buffer_length;

    /* Check if token refersh is setup */
    if (hub_client_ptr -> nx_azure_iot_hub_client_token_refresh)
    {
        status = nx_azure_iot_unix_time_get(hub_client_ptr -> nx_azure_iot_ptr, &expiry_time_secs);
        if (status)
        {

            /* Release the mutex.  */
            tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            nx_azure_iot_buffer_free(buffer_context);
            LogError("IoTHub client connect fail: unixtime get failed: 0x%02x", status);
            return(status);
        }

        expiry_time_secs += NX_AZURE_IOT_HUB_CLIENT_TOKEN_EXPIRY;
        status = hub_client_ptr -> nx_azure_iot_hub_client_token_refresh(hub_client_ptr,
                                                                         expiry_time_secs,
                                                                         hub_client_ptr -> nx_azure_iot_hub_client_symmetric_key,
                                                                         hub_client_ptr -> nx_azure_iot_hub_client_symmetric_key_length,
                                                                         resource_ptr -> resource_mqtt_sas_token,
                                                                         resource_ptr -> resource_mqtt_sas_token_length,
                                                                         &(resource_ptr -> resource_mqtt_sas_token_length));
        if (status)
        {

            /* Release the mutex.  */
            tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
            nx_azure_iot_buffer_free(buffer_context);
            LogError("IoTHub client connect fail: Token generation failed: 0x%02x", status);
            return(status);
        }
    }
    else
    {
        resource_ptr ->  resource_mqtt_sas_token_length = 0;
    }

    /* Set azure IoT and MQTT client.  */
    mqtt_client_ptr = &(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt);

    /* Update client id.  */
    mqtt_client_ptr -> nxd_mqtt_client_id = (CHAR *)resource_ptr -> resource_mqtt_client_id;
    mqtt_client_ptr -> nxd_mqtt_client_id_length = resource_ptr -> resource_mqtt_client_id_length;

    /* Set login info.  */
    status = nxd_mqtt_client_login_set(&(resource_ptr -> resource_mqtt),
                                       (CHAR *)resource_ptr -> resource_mqtt_user_name,
                                       resource_ptr -> resource_mqtt_user_name_length,
                                       (CHAR *)resource_ptr -> resource_mqtt_sas_token,
                                       resource_ptr -> resource_mqtt_sas_token_length);
    if (status)
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        nx_azure_iot_buffer_free(buffer_context);
        LogError("IoTHub client connect fail: MQTT CLIENT LOGIN SET FAIL: 0x%02x", status);
        return(status);
    }

    /* Set connect notify for non-blocking mode.  */
    if (wait_option == 0)
    {
        mqtt_client_ptr -> nxd_mqtt_connect_notify = nx_azure_iot_hub_client_mqtt_connect_notify;
        mqtt_client_ptr -> nxd_mqtt_connect_context = hub_client_ptr;
    }

    /* Save the resource buffer.  */
    resource_ptr -> resource_mqtt_buffer_context = buffer_context;
    resource_ptr -> resource_mqtt_buffer_size = buffer_size;

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    /* Start MQTT connection.  */
    status = nxd_mqtt_client_secure_connect(mqtt_client_ptr, &server_address, NXD_MQTT_TLS_PORT,
                                            nx_azure_iot_mqtt_tls_setup, NX_AZURE_IOT_MQTT_KEEP_ALIVE,
                                            clean_session, wait_option);

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Check status for non-blocking mode.  */
    if ((wait_option == 0) && (status == NX_IN_PROGRESS))
    {
        hub_client_ptr -> nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTING;

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        /* Return in-progress completion status.  */
        return(NX_AZURE_IOT_CONNECTING);
    }

    /* Release the mqtt connection resource.  */
    if (resource_ptr -> resource_mqtt_buffer_context)
    {
        nx_azure_iot_buffer_free(resource_ptr -> resource_mqtt_buffer_context);
        resource_ptr -> resource_mqtt_buffer_context = NX_NULL;
    }

    /* Check status.  */
    if (status != NX_AZURE_IOT_SUCCESS)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED;
        LogError("IoTHub client connect fail: MQTT CONNECT FAIL: 0x%02x", status);
    }
    else
    {

        /* Connected to IoT Hub.  */
        hub_client_ptr -> nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED;
    }

    /* Call connection notify if it is set.  */
    if (hub_client_ptr -> nx_azure_iot_hub_client_connection_status_callback)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_connection_status_callback(hub_client_ptr, status);
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(status);
}

static VOID nx_azure_iot_hub_client_mqtt_connect_notify(struct NXD_MQTT_CLIENT_STRUCT *client_ptr,
                                                        UINT status, VOID *context)
{

NX_AZURE_IOT_HUB_CLIENT *iot_hub_client = (NX_AZURE_IOT_HUB_CLIENT*)context;


    NX_PARAMETER_NOT_USED(client_ptr);

    /* Obtain the mutex.  */
    tx_mutex_get(iot_hub_client -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Release the mqtt connection resource.  */
    if (iot_hub_client -> nx_azure_iot_hub_client_resource.resource_mqtt_buffer_context)
    {
        nx_azure_iot_buffer_free(iot_hub_client -> nx_azure_iot_hub_client_resource.resource_mqtt_buffer_context);
        iot_hub_client -> nx_azure_iot_hub_client_resource.resource_mqtt_buffer_context = NX_NULL;
    }

    /* Update hub client status.  */
    if (status == NXD_MQTT_SUCCESS)
    {
        iot_hub_client -> nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED;
    }
    else
    {
        iot_hub_client -> nx_azure_iot_hub_client_state = NX_AZURE_IOT_HUB_CLIENT_STATUS_NOT_CONNECTED;
    }

    /* Call connection notify if it is set.  */
    if (iot_hub_client -> nx_azure_iot_hub_client_connection_status_callback)
    {
        iot_hub_client -> nx_azure_iot_hub_client_connection_status_callback(iot_hub_client, status);
    }

    /* Release the mutex.  */
    tx_mutex_put(iot_hub_client -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
}

static VOID nx_azure_iot_hub_client_mqtt_disconnect_notify(NXD_MQTT_CLIENT *client_ptr)
{
NX_AZURE_IOT_RESOURCE *resource = nx_azure_iot_resource_search(client_ptr);
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = NX_NULL;

    /* This function is protected by MQTT mutex. */

    if (resource && (resource -> resource_type == NX_AZURE_IOT_RESOURCE_IOT_HUB))
    {
        hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)resource -> resource_data_ptr;
    }

    /* Call connection notify if it is set.  */
    if (hub_client_ptr && hub_client_ptr -> nx_azure_iot_hub_client_connection_status_callback)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_connection_status_callback(hub_client_ptr,
                                                                             NX_AZURE_IOT_DISCONNECTED);
    }
}

VOID nx_azure_iot_hub_client_event_process(NX_AZURE_IOT *nx_azure_iot_ptr,
                                           ULONG common_events, ULONG module_own_events)
{

    NX_PARAMETER_NOT_USED(nx_azure_iot_ptr);

    /* Process common events.  */
    NX_PARAMETER_NOT_USED(common_events);

    /* Process module own events.  */
    NX_PARAMETER_NOT_USED(module_own_events);
}

UINT nx_azure_iot_hub_client_disconnect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;
NX_AZURE_IOT_THREAD *thread_list_ptr;


    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NX_NULL) || (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError("IoTHub client disconnect fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Disconnect.  */
    status = nxd_mqtt_client_disconnect(&hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt);
    if (status)
    {
        LogError("IoTHub client disconnect fail: 0x%02x", status);
        return(status);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Release the mqtt connection resource.  */
    if (hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt_buffer_context)
    {
        nx_azure_iot_buffer_free(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt_buffer_context);
        hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt_buffer_context = NX_NULL;
    }

    /* Wakeup all suspend threads.  */
    for (thread_list_ptr = hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> thread_next)
    {
        tx_thread_wait_abort(thread_list_ptr -> thread_ptr);
    }

    /* Cleanup received messages. */
    nx_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> nx_azure_iot_hub_client_c2d_message));
    nx_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message));
    nx_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message));
    nx_azure_iot_hub_client_received_message_cleanup(&(hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message));

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

static VOID nx_azure_iot_hub_client_received_message_cleanup(NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE *message)
{
NX_PACKET *current_ptr;
NX_PACKET *next_ptr;

    for (current_ptr = message -> message_head; current_ptr; current_ptr = next_ptr)
    {

        /* Get next packet in queue. */
        next_ptr = current_ptr -> nx_packet_queue_next;

        /* Release current packet. */
        current_ptr -> nx_packet_queue_next = NX_NULL;
        nx_packet_release(current_ptr);
    }

    /* Reset received messages. */
    message -> message_head = NX_NULL;
    message -> message_tail = NX_NULL;
}

UINT nx_azure_iot_hub_client_deinitialize(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;


    /* Check for invalid input pointers.  */
    if ((hub_client_ptr == NX_NULL) || (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError("IoTHub client deinitialize fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    nx_azure_iot_hub_client_disconnect(hub_client_ptr);

    status = nxd_mqtt_client_delete(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt));
    if (status)
    {
        LogError("IoTHub client delete fail: 0x%02x", status);
        return(status);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Remove resource from list.  */
    status = nx_azure_iot_resource_remove(hub_client_ptr -> nx_azure_iot_ptr,
                                          &(hub_client_ptr -> nx_azure_iot_hub_client_resource));
    if (status)
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError("IoTHub client handle not found");
        return(status);
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_cert_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate)
{

    if ((hub_client_ptr == NX_NULL) ||
        (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (device_certificate == NX_NULL))
    {
        LogError("IoTHub device certificate set fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_device_certificate = device_certificate;

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_symmetric_key_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                               UCHAR *symmetric_key, UINT symmetric_key_length)
{
    if ((hub_client_ptr == NX_NULL)  || (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (symmetric_key == NX_NULL) || (symmetric_key_length == 0))
    {
        LogError("IoTHub client symmetric key fail: Invalid argument");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    hub_client_ptr -> nx_azure_iot_hub_client_symmetric_key = symmetric_key;
    hub_client_ptr -> nx_azure_iot_hub_client_symmetric_key_length = symmetric_key_length;

    hub_client_ptr -> nx_azure_iot_hub_client_token_refresh = nx_azure_iot_hub_client_sas_token_get;

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_telemetry_message_create(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      NX_PACKET **packet_pptr, UINT wait_option)
{
NX_PACKET *packet_ptr;
UINT topic_length;
UINT status;
az_result core_result;

    if ((hub_client_ptr == NX_NULL) ||
        (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError("IoTHub telemetry message create fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_publish_packet_get(hub_client_ptr -> nx_azure_iot_ptr,
                                             &(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                             &packet_ptr, wait_option);
    if (status)
    {
        LogError("Create telemetry data fail");
        return(status);
    }

    topic_length = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    core_result = az_iot_hub_client_telemetry_get_publish_topic(&hub_client_ptr -> iot_hub_client_core,
                                                                NULL, (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                topic_length, &topic_length);
    if (az_failed(core_result))
    {
        LogError("IoTHub client telemetry message create fail with error 0x%08x", core_result);
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;
    *packet_pptr = packet_ptr;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_telemetry_message_delete(NX_PACKET *packet_ptr)
{
    return(nx_packet_release(packet_ptr));
}

UINT nx_azure_iot_hub_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    UCHAR *property_name, USHORT property_name_length,
                                                    UCHAR *property_value, USHORT property_value_length,
                                                    UINT wait_option)
{
UINT status;

    if ((packet_ptr == NX_NULL) ||
        (property_name == NX_NULL) ||
        (property_value == NX_NULL))
    {
        LogError("IoTHub telemetry property add fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if (*(packet_ptr -> nx_packet_append_ptr - 1) != '/')
    {
        status = nx_packet_data_append(packet_ptr, "&", 1,
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError("Telemetry data append fail");
            return(status);
        }
    }

    status = nx_packet_data_append(packet_ptr, property_name, (UINT)property_name_length,
                                   packet_ptr -> nx_packet_pool_owner, wait_option);
    if (status)
    {
        LogError("Telemetry data append fail");
        return(status);
    }

    status = nx_packet_data_append(packet_ptr, "=", 1,
                                   packet_ptr -> nx_packet_pool_owner,
                                   wait_option);
    if (status)
    {
        LogError("Telemetry data append fail");
        return(status);
    }

    status = nx_packet_data_append(packet_ptr, property_value, (UINT)property_value_length,
                                   packet_ptr -> nx_packet_pool_owner, wait_option);
    if (status)
    {
        LogError("Telemetry data append fail");
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_telemetry_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                            NX_PACKET *packet_ptr, UCHAR *telemetry_data,
                                            UINT data_size, UINT wait_option)
{
UINT status;
UINT topic_len;
UCHAR packet_id[2];

    if ((hub_client_ptr == NX_NULL) || (packet_ptr == NX_NULL))
    {
        LogError("IoTHub telemetry send fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    topic_len = packet_ptr -> nx_packet_length;

    status = nx_azure_iot_mqtt_packet_id_get(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                             packet_id, wait_option);
    if (status)
    {
        LogError("Failed to get packet id");
        return(status);
    }

    /* Append packet identifier */
    status = nx_packet_data_append(packet_ptr, packet_id, sizeof(packet_id),
                                   packet_ptr -> nx_packet_pool_owner,
                                   wait_option);
    if (status)
    {
        LogError("Telemetry append fail");
        return(status);
    }

    if (telemetry_data && (data_size != 0))
    {

        /* Append payload. */
        status = nx_packet_data_append(packet_ptr, telemetry_data, data_size,
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError("Telemetry data append fail");
            return(status);
        }
    }

    status = nx_azure_iot_publish_mqtt_packet(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                              packet_ptr, topic_len, packet_id, NX_AZURE_IOT_MQTT_QOS_1, wait_option);
    if (status)
    {
        LogError("IoTHub client send fail: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_receive_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        VOID *args),
                                                  VOID *callback_args)
{
    if ((hub_client_ptr == NX_NULL) || (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL))
    {
        LogError("IoTHub receive callback set fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    if (message_type == NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_c2d_message.message_callback = callback_ptr;
        hub_client_ptr -> nx_azure_iot_hub_client_c2d_message.message_callback_args = callback_args;
    }
    else if (message_type == NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_callback = callback_ptr;
        hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_callback_args = callback_args;
    }
    else if (message_type == NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message.message_callback = callback_ptr;
        hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message.message_callback_args = callback_args;
    }
    else if (message_type == NX_AZURE_IOT_HUB_DIRECT_METHOD)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message.message_callback = callback_ptr;
        hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message.message_callback_args = callback_args;
    }
    else
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        return(NX_AZURE_IOT_NOT_SUPPORTED);
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_cloud_message_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    return(nx_azure_iot_hub_client_cloud_message_sub_unsub(hub_client_ptr, NX_TRUE));
}

UINT nx_azure_iot_hub_client_cloud_message_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
    return(nx_azure_iot_hub_client_cloud_message_sub_unsub(hub_client_ptr, NX_FALSE));
}

static UINT nx_azure_iot_hub_client_process_publish_packet(UCHAR *start_ptr,
                                                           ULONG *topic_offset_ptr,
                                                           USHORT *topic_length_ptr)
{
UCHAR *byte = start_ptr;
UINT byte_count = 0;
UINT multiplier = 1;
UINT remaining_length = 0;
UINT topic_length;

    /* validate packet start contains fixed header */
    do
    {
        if (byte_count >= 4)
        {
            LogError("Invalid mqtt packet start position");
            return(NX_AZURE_IOT_INVALID_PACKET);
        }

        byte++;
        remaining_length += (((*byte) & 0x7F) * multiplier);
        multiplier = multiplier << 7;
        byte_count++;
    } while ((*byte) & 0x80);

    if (remaining_length < 2)
    {
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    /* retrieve topic length */
    byte++;
    topic_length = (UINT)(*(byte) << 8) | (*(byte + 1));

    if (topic_length > remaining_length - 2u)
    {
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    *topic_offset_ptr = (ULONG)((byte + 2) - start_ptr);
    *topic_length_ptr = (USHORT)topic_length;

    /* Return */
    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_hub_client_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT message_type,
                                                    NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE *receive_message,
                                                    NX_PACKET **packet_pptr, UINT wait_option)
{
NX_PACKET *packet_ptr = NX_NULL;
UINT old_threshold;
NX_AZURE_IOT_THREAD thread_list;

    if ((hub_client_ptr == NX_NULL) ||
        (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError("IoTHub message receive fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if (receive_message -> message_process == NX_NULL)
    {
        LogError("IoTHub message receive fail: NOT ENABLED");
        return(NX_AZURE_IOT_NOT_ENABLED);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    if (receive_message -> message_head)
    {
        packet_ptr = receive_message -> message_head;
        if (receive_message -> message_tail == packet_ptr)
        {
            receive_message -> message_tail = NX_NULL;
        }
        receive_message -> message_head = packet_ptr -> nx_packet_queue_next;
    }
    else if (wait_option)
    {
        thread_list.thread_message_type = message_type;
        thread_list.thread_ptr = tx_thread_identify();
        thread_list.thread_received_message = NX_NULL;
        thread_list.thread_expected_id = 0;
        thread_list.thread_next = hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended;
        hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended = &thread_list;

        /* Disable preemption. */
        tx_thread_preemption_change(tx_thread_identify(), 0, &old_threshold);

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        tx_thread_sleep(wait_option);

        /* Obtain the mutex.  */
        tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

        nx_azure_iot_hub_client_thread_dequeue(hub_client_ptr, &thread_list);

        /* Restore preemption. */
        tx_thread_preemption_change(tx_thread_identify(), old_threshold, &old_threshold);
        packet_ptr = thread_list.thread_received_message;
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    if (packet_ptr == NX_NULL)
    {
        return(NX_AZURE_IOT_NO_PACKET);
    }

    *packet_pptr = packet_ptr;

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_hub_client_adjust_payload(NX_PACKET *packet_ptr)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
ULONG message_offset;
ULONG message_length;

    status = _nxd_mqtt_process_publish_packet(packet_ptr, &topic_offset,
                                              &topic_length, &message_offset,
                                              &message_length);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    packet_ptr -> nx_packet_length = message_length;

    /* Adjust packet to pointer to message payload. */
    while (packet_ptr)
    {
        if ((ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) > message_offset)
        {

            /* This packet contains message payload. */
            packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_prepend_ptr + message_offset;
            break;
        }

        message_offset -= (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

        /* Set current packet to empty. */
        packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_append_ptr;

        /* Move to next packet. */
        packet_ptr = packet_ptr -> nx_packet_next;
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_cloud_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;

    status = nx_azure_iot_hub_client_message_receive(hub_client_ptr, NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                     &(hub_client_ptr -> nx_azure_iot_hub_client_c2d_message),
                                                     packet_pptr, wait_option);
    if (status)
    {
        return(status);
    }

    return(nx_azure_iot_hub_client_adjust_payload(*packet_pptr));
}

UINT nx_azure_iot_hub_client_cloud_message_property_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        NX_PACKET *packet_ptr, UCHAR *property_name,
                                                        USHORT property_name_length, UCHAR **property_value,
                                                        USHORT *property_value_length)
{
USHORT topic_size;
UINT status;
ULONG topic_offset;
UCHAR *topic_name;
az_iot_hub_client_c2d_request request;
az_span receive_topic;
az_result core_result;
az_span span;

    if (packet_ptr == NX_NULL ||
        property_name == NX_NULL ||
        property_value == NX_NULL ||
        property_value_length == NX_NULL)
    {
        LogError("IoTHub cloud message get property fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_client_process_publish_packet(packet_ptr -> nx_packet_data_start,
                                                            &topic_offset, &topic_size);
    if (status)
    {
        return(status);
    }

    topic_name = packet_ptr -> nx_packet_data_start + topic_offset;

    /* NOTE: Current implementation does not support topic to span multiple packets */
    if ((ULONG)(packet_ptr -> nx_packet_append_ptr - topic_name) < (ULONG)topic_size)
    {
        LogError("IoTHub cloud message get property fail: topic out of boundaries of single packet");
        return(NX_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_init(topic_name, (INT)topic_size);
    core_result = az_iot_hub_client_c2d_parse_received_topic(&hub_client_ptr -> iot_hub_client_core,
                                                             receive_topic, &request);
    if (az_failed(core_result))
    {
        LogError("IoTHub cloud message get property fail: parsing error");
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    span = az_span_init(property_name, property_name_length);
    core_result = az_iot_hub_client_properties_find(&request.properties, span, &span);
    if (az_failed(core_result))
    {
        if (core_result == AZ_ERROR_ITEM_NOT_FOUND)
        {
            status = NX_AZURE_IOT_NOT_FOUND;
        }
        else
        {
            LogError("IoTHub cloud message get property fail: property find");
            status = NX_AZURE_IOT_SDK_CORE_ERROR;
        }

        return(status);
    }

    *property_value = (UCHAR *)az_span_ptr(span);
    *property_value_length = (USHORT)az_span_size(span);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client device twin subscribe fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nxd_mqtt_client_subscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                       AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC,
                                       sizeof(AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC) - 1,
                                       NX_AZURE_IOT_MQTT_QOS_0);
    if (status)
    {
        LogError("IoTHub client device twin subscribe fail: 0x%02x", status);
        return(status);
    }

    status = nxd_mqtt_client_subscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                       AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC,
                                       sizeof(AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC) - 1,
                                       NX_AZURE_IOT_MQTT_QOS_0);
    if (status)
    {
        LogError("IoTHub client device twin subscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_process =
                      nx_azure_iot_hub_client_device_twin_process;
    hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message.message_process =
                      nx_azure_iot_hub_client_device_twin_process;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client device twin unsubscribe fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nxd_mqtt_client_unsubscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                         AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC,
                                         sizeof(AZ_IOT_HUB_CLIENT_TWIN_RESPONSE_SUBSCRIBE_TOPIC) - 1);
    if (status)
    {
        LogError("IoTHub client device twin unsubscribe fail: 0x%02x", status);
        return(status);
    }

    status = nxd_mqtt_client_unsubscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                         AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC,
                                         sizeof(AZ_IOT_HUB_CLIENT_TWIN_PATCH_SUBSCRIBE_TOPIC) - 1);
    if (status)
    {
        LogError("IoTHub client device twin unsubscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_process = NX_NULL;
    hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message.message_process = NX_NULL;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_report_properties_response_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status,
                                                                           VOID *args),
                                                                     VOID *callback_args)
{
    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client device twin set callback fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    hub_client_ptr -> nx_azure_iot_hub_client_report_properties_response_callback = callback_ptr;
    hub_client_ptr -> nx_azure_iot_hub_client_report_properties_response_callback_args = callback_args;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_reported_properties_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                  UCHAR *message_buffer, UINT message_length,
                                                                  UINT *request_id_ptr, UINT *response_status_ptr,
                                                                  UINT wait_option)
{
UINT status;
UCHAR *buffer_ptr;
UINT buffer_size;
VOID *buffer_context;
NX_PACKET *packet_ptr;
az_span topic_span;
UINT topic_length;
UINT request_id;
az_span request_id_span;
NX_AZURE_IOT_THREAD thread_list;
az_result core_result;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client device twin receive fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/PATCH/properties/reported/?$rid={request id}"
     * 2. Wait for the response if required.
     * 3. Return result if present.
     * */
    if (hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_process == NX_NULL)
    {
        LogError("IoTHub client device twin receive fail: NOT ENABLED");
        return(NX_AZURE_IOT_NOT_ENABLED);
    }

    status = nx_azure_iot_buffer_allocate(hub_client_ptr -> nx_azure_iot_ptr, &buffer_ptr,
                                          &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client device twin fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Generate odd request id for reported properties send */
    if ((hub_client_ptr -> nx_azure_iot_hub_client_request_id & 0x1))
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id += 2;
    }
    else
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id += 1;
    }

    request_id = hub_client_ptr -> nx_azure_iot_hub_client_request_id;
    topic_span = az_span_init(buffer_ptr, (INT)buffer_size);
    core_result = az_span_u32toa(topic_span, request_id, &topic_span);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError("IoTHub client device failed to u32toa");
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    request_id_span = az_span_init(buffer_ptr, (INT)(buffer_size - (UINT)az_span_size(topic_span)));
    core_result = az_iot_hub_client_twin_patch_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 request_id_span, (CHAR *)az_span_ptr(topic_span),
                                                                 (UINT)az_span_size(topic_span), &topic_length);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError("IoTHub client device twin subscribe fail: NX_AZURE_IOT_HUB_CLIENT_TOPIC_SIZE is too small.");
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    thread_list.thread_message_type = NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE;
    thread_list.thread_ptr = tx_thread_identify();
    thread_list.thread_expected_id = request_id;
    thread_list.thread_received_message = NX_NULL;
    thread_list.thread_response_status = 0;
    thread_list.thread_next = hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended;
    hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended = &thread_list;

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    status = nxd_mqtt_client_publish(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                     (CHAR *)az_span_ptr(topic_span), topic_length,
                                     (CHAR *)message_buffer, message_length, 0,
                                     NX_AZURE_IOT_MQTT_QOS_0, wait_option);
    nx_azure_iot_buffer_free(buffer_context);

    if (status)
    {
        /* remove thread from waiting suspend queue.  */
        tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);
        nx_azure_iot_hub_client_thread_dequeue(hub_client_ptr, &thread_list);
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

        LogError("IoTHub client reported state send: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }
    LogDebug("[%s]request_id: %u", __func__, request_id);

    if ((thread_list.thread_received_message) == NX_NULL && wait_option)
    {
        tx_thread_sleep(wait_option);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    nx_azure_iot_hub_client_thread_dequeue(hub_client_ptr, &thread_list);
    packet_ptr = thread_list.thread_received_message;

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    if (packet_ptr == NX_NULL)
    {
        LogError("IoTHub client reported state not responded");
        return(NX_AZURE_IOT_NO_PACKET);
    }

    if (request_id_ptr)
    {
        *request_id_ptr = request_id;
    }

    if (response_status_ptr)
    {
        *response_status_ptr = thread_list.thread_response_status;
    }

    /* Release message block. */
    nx_packet_release(packet_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_properties_request(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT wait_option)
{
UINT status;
UINT topic_length;
UCHAR *buffer_ptr;
UINT buffer_size;
VOID *buffer_context;
az_span request_id_span;
az_span topic_span;
az_result core_result;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client device twin publish fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Publish message to topic "$iothub/twin/GET/?$rid={request id}"
     * */
    status = nx_azure_iot_buffer_allocate(hub_client_ptr -> nx_azure_iot_ptr, &buffer_ptr,
                                          &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client device twin publish fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    /* Obtain the mutex.  */
    tx_mutex_get(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr, TX_WAIT_FOREVER);

    /* Generate even request id for twin properties request */
    if ((hub_client_ptr -> nx_azure_iot_hub_client_request_id & 0x1) == 0)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id += 2;
    }
    else
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id += 1;
    }

    if (hub_client_ptr -> nx_azure_iot_hub_client_request_id == 0)
    {
        hub_client_ptr -> nx_azure_iot_hub_client_request_id = 2;
    }

    topic_span = az_span_init(buffer_ptr, (INT)buffer_size);
    core_result = az_span_u32toa(topic_span, hub_client_ptr -> nx_azure_iot_hub_client_request_id, &topic_span);
    if (az_failed(core_result))
    {

        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError("IoTHub client device failed to u32toa");
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    request_id_span = az_span_init(buffer_ptr, (INT)(buffer_size - (UINT)az_span_size(topic_span)));
    core_result = az_iot_hub_client_twin_document_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                    request_id_span, (CHAR *)az_span_ptr(topic_span),
                                                                    (UINT)az_span_size(topic_span), &topic_length);
    if (az_failed(core_result))
    {
        /* Release the mutex.  */
        tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);
        LogError("IoTHub client device twin get topic fail.");
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* Release the mutex.  */
    tx_mutex_put(hub_client_ptr -> nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr);

    status = nxd_mqtt_client_publish(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                     (CHAR *)az_span_ptr(topic_span),
                                     topic_length, NX_NULL, 0, 0,
                                     NX_AZURE_IOT_MQTT_QOS_0, wait_option);
    nx_azure_iot_buffer_free(buffer_context);
    if (status)
    {
        LogError("IoTHub client device twin: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_device_twin_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
az_result core_result;
az_span topic_span;
az_iot_hub_client_twin_response out_twin_response;
NX_PACKET *packet_ptr;

    if (hub_client_ptr == NX_NULL || packet_pptr == NX_NULL)
    {
        LogError("IoTHub client device twin receive failed: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the twin document is available to receive from linklist.
     * 2. If present check the response.
     * 3. Return the payload of the response.
     * */
    status = nx_azure_iot_hub_client_message_receive(hub_client_ptr, NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES,
                                                     &(hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message),
                                                     &packet_ptr, wait_option);
    if (status)
    {
        LogError("IoTHub client device twin receive failed: 0x%02x", status);
        return(status);
    }

    if (nx_azure_iot_hub_client_process_publish_packet(packet_ptr -> nx_packet_prepend_ptr, &topic_offset,
                                                       &topic_length))
    {

        /* Message not supported. It will be released. */
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    topic_span = az_span_init(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), (INT)topic_length);
    core_result = az_iot_hub_client_twin_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                              topic_span, &out_twin_response);
    if (az_failed(core_result))
    {
        /* Topic name does not match device twin format. */
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    if ((out_twin_response.status < 200) || (out_twin_response.status >= 300))
    {
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SERVER_RESPONSE_ERROR);
    }

    *packet_pptr = packet_ptr;

    return(nx_azure_iot_hub_client_adjust_payload(*packet_pptr));
}

UINT nx_azure_iot_hub_client_device_twin_desired_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                    NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;

    if (hub_client_ptr == NX_NULL || packet_pptr == NX_NULL)
    {
        LogError("IoTHub client device twin receive properties failed: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Steps.
     * 1. Check if the desired properties document is available to receive from linklist.
     * 2. Return result if present.
     * */
    status = nx_azure_iot_hub_client_message_receive(hub_client_ptr, NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES,
                                                     &(hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message),
                                                     packet_pptr, wait_option);
    if (status)
    {
        return(status);
    }

    return(nx_azure_iot_hub_client_adjust_payload(*packet_pptr));
}

static UINT nx_azure_iot_hub_client_cloud_message_sub_unsub(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, UINT is_subscribe)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub cloud message subscribe fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if (is_subscribe)
    {
        status = nxd_mqtt_client_subscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                           AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, sizeof(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC) - 1,
                                           NX_AZURE_IOT_MQTT_QOS_1);
        if (status)
        {
            LogError("IoTHub cloud message subscribe fail: 0x%02x", status);
            return(status);
        }

        hub_client_ptr -> nx_azure_iot_hub_client_c2d_message.message_process = nx_azure_iot_hub_client_c2d_process;
    }
    else
    {
        status = nxd_mqtt_client_unsubscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                             AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC, sizeof(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC) - 1);
        if (status)
        {
            LogError("IoTHub cloud message subscribe fail: 0x%02x", status);
            return(status);
        }

        hub_client_ptr -> nx_azure_iot_hub_client_c2d_message.message_process = NX_NULL;
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static VOID nx_azure_iot_hub_client_mqtt_receive_callback(NXD_MQTT_CLIENT* client_ptr,
                                                          UINT number_of_messages)
{
NX_AZURE_IOT_RESOURCE *resource = nx_azure_iot_resource_search(client_ptr);
NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr = NX_NULL;
NX_PACKET *packet_ptr;
NX_PACKET *packet_next_ptr;
ULONG topic_offset;
USHORT topic_length;

    /* This function is protected by MQTT mutex. */

    NX_PARAMETER_NOT_USED(number_of_messages);

    if (resource && (resource -> resource_type == NX_AZURE_IOT_RESOURCE_IOT_HUB))
    {
        hub_client_ptr = (NX_AZURE_IOT_HUB_CLIENT *)resource -> resource_data_ptr;
    }

    if (hub_client_ptr)
    {
        for (packet_ptr = client_ptr -> message_receive_queue_head;
             packet_ptr;
             packet_ptr = packet_next_ptr)
        {

            /* Store next packet in case current packet is consumed. */
            packet_next_ptr = packet_ptr -> nx_packet_queue_next;

            /* Adjust packet to simply process logic. */
            nx_azure_iot_mqtt_packet_adjust(packet_ptr);

            if (nx_azure_iot_hub_client_process_publish_packet(packet_ptr -> nx_packet_prepend_ptr, &topic_offset,
                                                               &topic_length))
            {

                /* Message not supported. It will be released. */
                nx_packet_release(packet_ptr);
                continue;
            }

            if ((topic_offset + topic_length) >
                (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr))
            {

                /* Only process topic in the first packet since the fixed topic is short enough to fit into one packet. */
                topic_length = (USHORT)(((ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) -
                                         topic_offset) & 0xFFFF);
            }

            if (hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message.message_process &&
                (hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message.message_process(hub_client_ptr, packet_ptr,
                                                                                                 topic_offset,
                                                                                                 topic_length) == NX_AZURE_IOT_SUCCESS))
            {

                /* Direct method message is processed. */
                continue;
            }

            if (hub_client_ptr -> nx_azure_iot_hub_client_c2d_message.message_process &&
                (hub_client_ptr -> nx_azure_iot_hub_client_c2d_message.message_process(hub_client_ptr, packet_ptr,
                                                                                       topic_offset,
                                                                                       topic_length) == NX_AZURE_IOT_SUCCESS))
            {

                /* Could to Device message is processed. */
                continue;
            }

            if ((hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_process) &&
                (hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message.message_process(hub_client_ptr,
                                                                                               packet_ptr, topic_offset,
                                                                                               topic_length) == NX_AZURE_IOT_SUCCESS))
            {

                /* Device Twin message is processed. */
                continue;
            }

            /* Message not supported. It will be released. */
            nx_packet_release(packet_ptr);
        }

        /* Clear all message from MQTT receive queue. */
        client_ptr -> message_receive_queue_head = NX_NULL;
        client_ptr -> message_receive_queue_tail = NX_NULL;
        client_ptr -> message_receive_queue_depth = 0;
    }
}

static VOID nx_azure_iot_hub_client_message_notify(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   NX_AZURE_IOT_HUB_CLIENT_RECEIVE_MESSAGE *receive_message,
                                                   NX_PACKET *packet_ptr)
{
    if (receive_message -> message_tail)
    {
        receive_message -> message_tail -> nx_packet_queue_next = packet_ptr;
    }
    else
    {
        receive_message -> message_head = packet_ptr;
    }
    receive_message -> message_tail = packet_ptr;

    /* Check for user callback function. */
    if (receive_message -> message_callback)
    {
        receive_message -> message_callback(hub_client_ptr, receive_message -> message_callback_args);
    }
}

static UINT nx_azure_iot_hub_client_receive_thread_find(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        NX_PACKET *packet_ptr, UINT message_type,
                                                        UINT request_id, NX_AZURE_IOT_THREAD **thread_list_pptr)
{
NX_AZURE_IOT_THREAD *thread_list_prev = NX_NULL;
NX_AZURE_IOT_THREAD *thread_list_ptr;

    /* Search thread waiting for message type. */
    for (thread_list_ptr = hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended;
         thread_list_ptr;
         thread_list_ptr = thread_list_ptr -> thread_next)
    {
        if ((thread_list_ptr -> thread_message_type == message_type) &&
            (request_id == thread_list_ptr -> thread_expected_id))
        {

            /* Found a thread waiting for message type. */
            if (thread_list_prev == NX_NULL)
            {
                hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended = thread_list_ptr -> thread_next;
            }
            else
            {
                thread_list_prev -> thread_next = thread_list_ptr -> thread_next;
            }
            thread_list_ptr -> thread_received_message = packet_ptr;
            *thread_list_pptr =  thread_list_ptr;
            return(NX_AZURE_IOT_SUCCESS);
        }

        thread_list_prev = thread_list_ptr;
    }

    return(NX_AZURE_IOT_NOT_FOUND);
}

static UINT nx_azure_iot_hub_client_c2d_process(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                NX_PACKET *packet_ptr,
                                                ULONG topic_offset,
                                                USHORT topic_length)
{
UCHAR *topic_name;
az_iot_hub_client_c2d_request request;
az_span receive_topic;
az_result core_result;
UINT status;
NX_AZURE_IOT_THREAD *thread_list_ptr;

    /* This function is protected by MQTT mutex. */

    /* Check message type first. */
    topic_name = &(packet_ptr -> nx_packet_prepend_ptr[topic_offset]);

    /* NOTE: Current implementation does not support topic to span multiple packets */
    if ((ULONG)(packet_ptr -> nx_packet_append_ptr - topic_name) < topic_length)
    {
        LogError("topic out of boundaries of single packet");
        return(NX_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_init(topic_name, topic_length);
    core_result = az_iot_hub_client_c2d_parse_received_topic(&hub_client_ptr -> iot_hub_client_core,
                                                             receive_topic, &request);
    if (az_failed(core_result))
    {

        /* Topic name does not match C2D format. */
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    status = nx_azure_iot_hub_client_receive_thread_find(hub_client_ptr,
                                                         packet_ptr,
                                                         NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE,
                                                         0, &thread_list_ptr);
    if (status == NX_AZURE_IOT_SUCCESS)
    {
        tx_thread_wait_abort(thread_list_ptr -> thread_ptr);
        return(NX_AZURE_IOT_SUCCESS);
    }

    /* No thread is waiting for C2D message yet. */
    nx_azure_iot_hub_client_message_notify(hub_client_ptr,
                                           &(hub_client_ptr -> nx_azure_iot_hub_client_c2d_message),
                                           packet_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_hub_client_direct_method_process(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                          NX_PACKET *packet_ptr,
                                                          ULONG topic_offset,
                                                          USHORT topic_length)
{
UCHAR *topic_name;
az_iot_hub_client_method_request request;
az_span receive_topic;
az_result core_result;
UINT status;
NX_AZURE_IOT_THREAD *thread_list_ptr;

    /* This function is protected by MQTT mutex. */

    /* Check message type first. */
    topic_name = &(packet_ptr -> nx_packet_prepend_ptr[topic_offset]);

    /* NOTE: Current implementation does not support topic to span multiple packets */
    if ((ULONG)(packet_ptr -> nx_packet_append_ptr - topic_name) < topic_length)
    {
        LogError("topic out of boundaries of single packet");
        return(NX_AZURE_IOT_TOPIC_TOO_LONG);
    }

    receive_topic = az_span_init(topic_name, topic_length);
    core_result = az_iot_hub_client_methods_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 receive_topic, &request);
    if (az_failed(core_result))
    {

        /* Topic name does not match direct method format. */
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    status = nx_azure_iot_hub_client_receive_thread_find(hub_client_ptr,
                                                         packet_ptr,
                                                         NX_AZURE_IOT_HUB_DIRECT_METHOD,
                                                         0, &thread_list_ptr);
    if (status == NX_AZURE_IOT_SUCCESS)
    {
        tx_thread_wait_abort(thread_list_ptr -> thread_ptr);
        return(NX_AZURE_IOT_SUCCESS);
    }

    /* No thread is waiting for direct method message yet. */
    nx_azure_iot_hub_client_message_notify(hub_client_ptr,
                                           &(hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message),
                                           packet_ptr);
    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_hub_client_device_twin_message_type_get(az_iot_hub_client_twin_response *out_twin_response_ptr,
                                                                 UINT request_id)
{
UINT mesg_type;

    switch (out_twin_response_ptr -> response_type)
    {
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_GET :
        /* fall through */
        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_REPORTED_PROPERTIES :
        {
            /* odd requests are of reported properties and even of twin properties*/
            mesg_type = request_id % 2 == 0 ? NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES :
                        NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE;
        }
        break;

        case AZ_IOT_CLIENT_TWIN_RESPONSE_TYPE_DESIRED_PROPERTIES :
        {
            mesg_type = NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES;
        }
        break;

        default :
        {
            mesg_type = NX_AZURE_IOT_HUB_NONE;
        }
    }

    return mesg_type;
}

static UINT nx_azure_iot_hub_client_device_twin_process(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                        NX_PACKET *packet_ptr,
                                                        ULONG topic_offset,
                                                        USHORT topic_length)
{
NX_AZURE_IOT_THREAD *thread_list_ptr;
UINT message_type;
uint32_t request_id;
UINT correlation_id;
UINT status;
az_result core_result;
az_span topic_span;
az_iot_hub_client_twin_response out_twin_response;

    /* This function is protected by MQTT mutex. */

    /* Check message type first. */
    topic_span = az_span_init(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), (INT)topic_length);
    core_result = az_iot_hub_client_twin_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                              topic_span, &out_twin_response);
    if (az_failed(core_result))
    {
        /* Topic name does not match device twin format. */
            return(NX_AZURE_IOT_NOT_FOUND);
    }

    core_result = az_span_atou32(out_twin_response.request_id, &request_id);
    if (az_failed(core_result))
    {
        /* Topic name does not match device twin format. */
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    message_type = nx_azure_iot_hub_client_device_twin_message_type_get(&out_twin_response, request_id);
    if (message_type == NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE)
    {
        /* only requested thread should be woken*/
        correlation_id = request_id;
    }
    else
    {
        /* any thread can be woken*/
        correlation_id = 0;
    }

    status = nx_azure_iot_hub_client_receive_thread_find(hub_client_ptr,
                                                         packet_ptr,
                                                         message_type,
                                                         correlation_id, &thread_list_ptr);
    if (status == NX_AZURE_IOT_SUCCESS)
    {
        thread_list_ptr -> thread_response_status = (UINT)out_twin_response.status;
        tx_thread_wait_abort(thread_list_ptr -> thread_ptr);
        return(NX_AZURE_IOT_SUCCESS);
    }

    switch(message_type)
    {
        case NX_AZURE_IOT_HUB_DEVICE_TWIN_REPORTED_PROPERTIES_RESPONSE :
        {
            if (hub_client_ptr -> nx_azure_iot_hub_client_report_properties_response_callback)
            {
                hub_client_ptr -> nx_azure_iot_hub_client_report_properties_response_callback(hub_client_ptr,
                                                                                              request_id,
                                                                                              out_twin_response.status,
                                                                                              hub_client_ptr -> nx_azure_iot_hub_client_report_properties_response_callback_args);
            }

            nx_packet_release(packet_ptr);
        }
        break;

        case NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES :
        {

            /* No thread is waiting for device twin message yet. */
            nx_azure_iot_hub_client_message_notify(hub_client_ptr,
                                                   &(hub_client_ptr -> nx_azure_iot_hub_client_device_twin_message),
                                                   packet_ptr);
        }
        break;

        case NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES :
        {
            /* No thread is waiting for device twin message yet. */
            nx_azure_iot_hub_client_message_notify(hub_client_ptr,
                                                   &(hub_client_ptr -> nx_azure_iot_hub_client_device_twin_desired_properties_message),
                                                   packet_ptr);
        }
        break;

        default :
            nx_packet_release(packet_ptr);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

static VOID nx_azure_iot_hub_client_thread_dequeue(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   NX_AZURE_IOT_THREAD *thread_list_ptr)
{
NX_AZURE_IOT_THREAD *thread_list_prev = NX_NULL;
NX_AZURE_IOT_THREAD *thread_list_current;

    for (thread_list_current = hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended;
         thread_list_current;
         thread_list_current = thread_list_current -> thread_next)
    {
        if (thread_list_current == thread_list_ptr)
        {

            /* Found the thread to dequeue. */
            if (thread_list_prev == NX_NULL)
            {
                hub_client_ptr -> nx_azure_iot_hub_client_thread_suspended = thread_list_current -> thread_next;
            }
            else
            {
                thread_list_prev -> thread_next = thread_list_current -> thread_next;
            }
            break;
        }

        thread_list_prev = thread_list_current;
    }
}

static UINT nx_azure_iot_hub_client_sas_token_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  ULONG expiry_time_secs, UCHAR *key, UINT key_len,
                                                  UCHAR *sas_buffer, UINT sas_buffer_len, UINT *sas_length)
{
UCHAR *buffer_ptr;
UINT buffer_size;
VOID *buffer_context;
az_span span = az_span_init(sas_buffer, (INT)sas_buffer_len);
az_span buffer_span;
UINT status;
UCHAR *output_ptr;
UINT output_len;
az_result core_result;

    status = nx_azure_iot_buffer_allocate(hub_client_ptr -> nx_azure_iot_ptr, &buffer_ptr, &buffer_size, &buffer_context);
    if (status)
    {
        LogError("IoTHub client connect fail: BUFFER ALLOCATE FAIL");
        return(status);
    }

    core_result = az_iot_hub_client_sas_get_signature(&(hub_client_ptr -> iot_hub_client_core),
                                                      expiry_time_secs, span, &span);
    if (az_failed(core_result))
    {
        LogError("IoTHub failed failed to get signature with error : 0x%08x", core_result);
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    status = nx_azure_iot_url_encoded_hmac_sha256_calculate(&(hub_client_ptr -> nx_azure_iot_hub_client_resource),
                                                            key, key_len, az_span_ptr(span), (UINT)az_span_size(span),
                                                            buffer_ptr, buffer_size, &output_ptr, &output_len);
    if (status)
    {
        LogError("IoTHub failed to encoded hash");
        nx_azure_iot_buffer_free(buffer_context);
        return(status);
    }

    buffer_span = az_span_init(output_ptr, (INT)output_len);
    core_result= az_iot_hub_client_sas_get_password(&(hub_client_ptr -> iot_hub_client_core),
                                                    buffer_span, expiry_time_secs, AZ_SPAN_NULL,
                                                    (CHAR *)sas_buffer, sas_buffer_len, &sas_buffer_len);
    if (az_failed(core_result))
    {
        LogError("IoTHub failed to generate token with error : 0x%08x", core_result);
        nx_azure_iot_buffer_free(buffer_context);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *sas_length = sas_buffer_len;
    nx_azure_iot_buffer_free(buffer_context);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_direct_method_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client direct method subscribe fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nxd_mqtt_client_subscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                       AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC,
                                       sizeof(AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC) - 1,
                                       NX_AZURE_IOT_MQTT_QOS_0);
    if (status)
    {
        LogError("IoTHub client direct method subscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message.message_process = nx_azure_iot_hub_client_direct_method_process;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_direct_method_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr)
{
UINT status;

    if (hub_client_ptr == NX_NULL)
    {
        LogError("IoTHub client direct method unsubscribe fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nxd_mqtt_client_unsubscribe(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                         AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC,
                                         sizeof(AZ_IOT_HUB_CLIENT_METHODS_SUBSCRIBE_TOPIC) - 1);
    if (status)
    {
        LogError("IoTHub client direct method unsubscribe fail: 0x%02x", status);
        return(status);
    }

    hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message.message_process = NX_NULL;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_direct_method_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                           UCHAR **method_name_pptr, USHORT *method_name_length_ptr,
                                                           VOID **context_pptr, USHORT *context_length_ptr,
                                                           NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;
ULONG topic_offset;
USHORT topic_length;
az_span topic_span;
ULONG message_offset;
ULONG message_length;
NX_PACKET *packet_ptr;
az_result core_result;
az_iot_hub_client_method_request request;

    if ((hub_client_ptr == NX_NULL) ||
        (method_name_pptr == NX_NULL) ||
        (method_name_length_ptr == NX_NULL) ||
        (context_pptr == NX_NULL) ||
        (context_length_ptr == NX_NULL) ||
        (packet_pptr == NX_NULL))
    {
        LogError("IoTHub client direct method receive fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    status = nx_azure_iot_hub_client_message_receive(hub_client_ptr, NX_AZURE_IOT_HUB_DIRECT_METHOD,
                                                     &(hub_client_ptr -> nx_azure_iot_hub_client_direct_method_message),
                                                     packet_pptr, wait_option);
    if (status)
    {
        return(status);
    }

    packet_ptr = *packet_pptr;
    status = _nxd_mqtt_process_publish_packet(packet_ptr, &topic_offset, &topic_length, &message_offset, &message_length);
    if (status)
    {
        nx_packet_release(packet_ptr);
        return(status);
    }

    topic_span = az_span_init(&(packet_ptr -> nx_packet_prepend_ptr[topic_offset]), topic_length);
    core_result = az_iot_hub_client_methods_parse_received_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                 topic_span, &request);
    if (az_failed(core_result))
    {
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }

    *packet_pptr = packet_ptr;
    packet_ptr -> nx_packet_length = message_length;

    /* Adjust packet to pointer to message payload. */
    while (packet_ptr)
    {
        if ((ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) > message_offset)
        {

            /* This packet contains message payload. */
            packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_prepend_ptr + message_offset;
            break;
        }

        message_offset -= (ULONG)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);

        /* Set current packet to empty. */
        packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_append_ptr;

        /* Move to next packet. */
        packet_ptr = packet_ptr -> nx_packet_next;
    }

    *method_name_pptr = az_span_ptr(request.name);
    *method_name_length_ptr = (USHORT)az_span_size(request.name);
    *context_pptr = (VOID*)az_span_ptr(request.request_id);
    *context_length_ptr =  (USHORT)az_span_size(request.request_id);

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_hub_client_direct_method_message_response(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT status_code, VOID *context_ptr,
                                                            USHORT context_length, UCHAR *payload,
                                                            UINT payload_length, UINT wait_option)
{
NX_PACKET *packet_ptr;
UINT topic_length;
az_span request_id_span;
UINT status;
az_result core_result;
UCHAR packet_id[2];

    if ((hub_client_ptr == NX_NULL) ||
        (hub_client_ptr -> nx_azure_iot_ptr == NX_NULL) ||
        (context_ptr == NX_NULL) ||
        (context_length == 0))
    {
        LogError("IoTHub telemetry message create fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* prepare response packet */
    status = nx_azure_iot_publish_packet_get(hub_client_ptr -> nx_azure_iot_ptr,
                                             &(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                             &packet_ptr, wait_option);
    if (status)
    {
        LogError("Create response data fail");
        return(status);
    }

    topic_length = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr);
    request_id_span = az_span_init((UCHAR*)context_ptr, (INT)context_length);
    core_result = az_iot_hub_client_methods_response_get_publish_topic(&(hub_client_ptr -> iot_hub_client_core),
                                                                       request_id_span, (USHORT)status_code,
                                                                       (CHAR *)packet_ptr -> nx_packet_prepend_ptr,
                                                                       topic_length, &topic_length);
    if (az_failed(core_result))
    {
        LogError("Failed to create the method response topic");
        nx_packet_release(packet_ptr);
        return(NX_AZURE_IOT_SDK_CORE_ERROR);
    }


    packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_prepend_ptr + topic_length;
    packet_ptr -> nx_packet_length = topic_length;

    if (payload && (payload_length != 0))
    {

        /* Append payload. */
        status = nx_packet_data_append(packet_ptr, payload, payload_length,
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError("Method reponse data append fail");
            nx_packet_release(packet_ptr);
            return(status);
        }
    }
    else
    {
        /* Append payload. */
        status = nx_packet_data_append(packet_ptr, NX_AZURE_IOT_HUB_CLIENT_EMPTY_JSON,
                                       sizeof(NX_AZURE_IOT_HUB_CLIENT_EMPTY_JSON) - 1,
                                       packet_ptr -> nx_packet_pool_owner,
                                       wait_option);
        if (status)
        {
            LogError("Adding empty json failed.");
            nx_packet_release(packet_ptr);
            return(status);
        }
    }

    status = nx_azure_iot_publish_mqtt_packet(&(hub_client_ptr -> nx_azure_iot_hub_client_resource.resource_mqtt),
                                              packet_ptr, topic_length, packet_id, NX_AZURE_IOT_MQTT_QOS_0,
                                              wait_option);
    if (status)
    {
        LogError("IoTHub client method response fail: PUBLISH FAIL: 0x%02x", status);
        nx_packet_release(packet_ptr);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}
