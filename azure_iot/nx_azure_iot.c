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

#include "nx_azure_iot.h"

#ifndef NX_AZURE_IOT_WAIT_OPTION
#define NX_AZURE_IOT_WAIT_OPTION NX_WAIT_FOREVER
#endif /* NX_AZURE_IOT_WAIT_OPTION */

/* Define offset of MQTT telemetry packet. */
#define NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET   7

/* Convert number to upper hex */
#define NX_AZURE_IOT_NUMBER_TO_UPPER_HEX(number)    (CHAR)(number + (number < 10 ? '0' : 'A' - 10))

/* Define the prototypes for Azure RTOS IoT.  */
NX_AZURE_IOT *_nx_azure_iot_created_ptr;

/* Define the base64 letters  */
static CHAR _nx_azure_iot_base64_array[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

extern VOID nx_azure_iot_hub_client_event_process(NX_AZURE_IOT *nx_azure_iot_ptr,
                                                  ULONG common_events, ULONG module_own_events);
extern UINT _nxd_mqtt_client_publish_packet_send(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                                 USHORT packet_id, UINT QoS, ULONG wait_option);

static UINT nx_azure_iot_url_encode(CHAR *src_ptr, UINT src_len,
                                    CHAR *dest_ptr, UINT dest_len, UINT *bytes_copied)
{
UINT dest_index;
UINT src_index;
CHAR ch;

    for (src_index = 0, dest_index = 0; src_index < src_len; src_index++)
    {
        ch = src_ptr[src_index];

        /* Check if encoding is required.
           copied from sdk-core */
        if ((('0' <= ch) && (ch <= '9')) ||
            (('a' <= (ch | 0x20)) && ((ch | 0x20) <= 'z')))
        {
            if (dest_index >= dest_len)
            {
                return NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE;
            }

            dest_ptr[dest_index++] = ch;
        }
        else
        {
            if ((dest_index + 2) >= dest_len)
            {
                return NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE;
            }

            dest_ptr[dest_index++] = '%';
            dest_ptr[dest_index++] = NX_AZURE_IOT_NUMBER_TO_UPPER_HEX((ch >> 4));
            dest_ptr[dest_index++] = NX_AZURE_IOT_NUMBER_TO_UPPER_HEX((ch & 0x0F));
        }
    }

    *bytes_copied = dest_index;

    return NX_AZURE_IOT_SUCCESS;
}

static VOID nx_azure_iot_event_process(VOID *nx_azure_iot, ULONG common_events, ULONG module_own_events)
{

NX_AZURE_IOT *nx_azure_iot_ptr = (NX_AZURE_IOT *)nx_azure_iot;

    /* Process iot hub client */
    nx_azure_iot_hub_client_event_process(nx_azure_iot, common_events, module_own_events);

    /* Process DPS events.  */
    if (nx_azure_iot_ptr -> nx_azure_iot_provisioning_client_event_process)
    {
        nx_azure_iot_ptr -> nx_azure_iot_provisioning_client_event_process(nx_azure_iot_ptr, common_events,
                                                                           module_own_events);
    }
}

static UINT nx_azure_iot_publish_packet_header_add(NX_PACKET* packet_ptr, UINT topic_len, UINT qos)
{
UCHAR *buffer_ptr;
UINT length;

    /* Check if packet has enough space to write MQTT header */
    if (NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET >
        (packet_ptr -> nx_packet_prepend_ptr - packet_ptr -> nx_packet_data_start))
    {
        return(NX_AZURE_IOT_INVALID_PACKET);
    }

    /* Start to fill MQTT header. */
    buffer_ptr = packet_ptr -> nx_packet_prepend_ptr - NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET;

    /* Set flags. */
    buffer_ptr[0] = (UCHAR)(MQTT_CONTROL_PACKET_TYPE_PUBLISH << 4);
    if (qos == NX_AZURE_IOT_MQTT_QOS_1)
    {
        buffer_ptr[0] |= MQTT_PUBLISH_QOS_LEVEL_1;
    }

    /* Set topic length. */
    buffer_ptr[5] = (UCHAR)(topic_len >> 8);
    buffer_ptr[6] = (UCHAR)(topic_len & 0xFF);

    /* Set total length.
     * 2 bytes for topic length.
     * 2 bytes for packet id.
     * data_size for payload.
     *
     * packet already contains topic length, packet id (optional) and data payload
     */
    length = packet_ptr -> nx_packet_length + 2;

    /* Total length is encoded in fixed four bytes format. */
    buffer_ptr[1] = (UCHAR)((length & 0x7F) | 0x80);
    length >>= 7;
    buffer_ptr[2] = (UCHAR)((length & 0x7F) | 0x80);
    length >>= 7;
    buffer_ptr[3] = (UCHAR)((length & 0x7F) | 0x80);
    length >>= 7;
    buffer_ptr[4] = (UCHAR)(length & 0x7F);

    /* Update packet. */
    packet_ptr -> nx_packet_prepend_ptr = buffer_ptr;
    packet_ptr -> nx_packet_length += NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET;

    return(NX_AZURE_IOT_SUCCESS);
}

NX_AZURE_IOT_RESOURCE *nx_azure_iot_resource_search(NXD_MQTT_CLIENT *client_ptr)
{
NX_AZURE_IOT_RESOURCE *resource_ptr;

    /* Check if created Azure RTOS IoT.  */
    if ((_nx_azure_iot_created_ptr == NX_NULL) || (client_ptr == NX_NULL))
    {
        return(NX_NULL);
    }

    /* Loop to find the resource associated with current MQTT client. */
    for (resource_ptr = _nx_azure_iot_created_ptr -> nx_azure_iot_resource_list_header;
         resource_ptr; resource_ptr = resource_ptr -> resource_next)
    {

        if (&(resource_ptr -> resource_mqtt) == client_ptr)
        {
            return(resource_ptr);
        }
    }

    return(NX_NULL);
}

UINT nx_azure_iot_resource_add(NX_AZURE_IOT *nx_azure_iot_ptr, NX_AZURE_IOT_RESOURCE *resource_ptr)
{

    resource_ptr -> resource_next = nx_azure_iot_ptr -> nx_azure_iot_resource_list_header;
    nx_azure_iot_ptr -> nx_azure_iot_resource_list_header = resource_ptr;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_resource_remove(NX_AZURE_IOT *nx_azure_iot_ptr, NX_AZURE_IOT_RESOURCE *resource_ptr)
{

NX_AZURE_IOT_RESOURCE   *resource_previous;

    if (nx_azure_iot_ptr -> nx_azure_iot_resource_list_header == NX_NULL)
    {
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    if (nx_azure_iot_ptr -> nx_azure_iot_resource_list_header == resource_ptr)
    {
        nx_azure_iot_ptr -> nx_azure_iot_resource_list_header = nx_azure_iot_ptr -> nx_azure_iot_resource_list_header -> resource_next;
        return(NX_AZURE_IOT_SUCCESS);
    }

    for (resource_previous = nx_azure_iot_ptr -> nx_azure_iot_resource_list_header;
         resource_previous -> resource_next;
         resource_previous = resource_previous -> resource_next)
    {
        if (resource_previous -> resource_next == resource_ptr)
        {
            resource_previous -> resource_next = resource_previous -> resource_next -> resource_next;
            return(NX_AZURE_IOT_SUCCESS);
        }
    }

    return(NX_AZURE_IOT_NOT_FOUND);
}

UINT nx_azure_iot_create(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR *name_ptr,
                         NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr,
                         VOID *stack_memory_ptr, UINT stack_memory_size,
                         UINT priority, UINT (*unix_time_callback)(ULONG *unix_time))
{
UINT status;

    if ((nx_azure_iot_ptr == NX_NULL) || (ip_ptr == NX_NULL) ||
        (pool_ptr == NX_NULL) || (dns_ptr == NX_NULL))
    {
        LogError("IoT create fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    nx_azure_iot_ptr -> nx_azure_iot_name = name_ptr;
    nx_azure_iot_ptr -> nx_azure_iot_ip_ptr = ip_ptr;
    nx_azure_iot_ptr -> nx_azure_iot_dns_ptr = dns_ptr;
    nx_azure_iot_ptr -> nx_azure_iot_pool_ptr = pool_ptr;
    nx_azure_iot_ptr -> nx_azure_iot_unix_time_get = unix_time_callback;

    status = nx_cloud_create(&nx_azure_iot_ptr -> nx_azure_iot_cloud, (CHAR *)name_ptr, stack_memory_ptr,
                             stack_memory_size, priority);
    if (status)
    {
        LogError("IoT create fail: 0x%02x", status);
        return(status);
    }

    /* Register SDK module on cloud helper.  */
    status = nx_cloud_module_register(&(nx_azure_iot_ptr -> nx_azure_iot_cloud), &(nx_azure_iot_ptr -> nx_azure_iot_cloud_module),
                                      "Azure SDK Module", NX_CLOUD_MODULE_AZURE_SDK_EVENT | NX_CLOUD_COMMON_PERIODIC_EVENT,
                                      nx_azure_iot_event_process, nx_azure_iot_ptr);
    if (status)
    {
        LogError("IoT module register fail: 0x%02x", status);
        return(status);
    }

    /* Set the mutex.  */
    nx_azure_iot_ptr -> nx_azure_iot_mutex_ptr = &(nx_azure_iot_ptr -> nx_azure_iot_cloud.nx_cloud_mutex);

    /* Set created IoT pointer.  */
    _nx_azure_iot_created_ptr = nx_azure_iot_ptr;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_delete(NX_AZURE_IOT *nx_azure_iot_ptr)
{
UINT status;

    if (nx_azure_iot_ptr == NX_NULL)
    {
        LogError("IoT delete fail: INVALID POINTER");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    if (nx_azure_iot_ptr -> nx_azure_iot_resource_list_header)
    {
        LogError("IoT delete fail: IOTHUB CLIENT NOT DELETED");
        return(NX_AZURE_IOT_NOT_FOUND);
    }

    /* Deregister SDK module on cloud helper.  */
    nx_cloud_module_deregister(&(nx_azure_iot_ptr -> nx_azure_iot_cloud), &(nx_azure_iot_ptr -> nx_azure_iot_cloud_module));

    /* Delete cloud.  */
    status = nx_cloud_delete(&nx_azure_iot_ptr -> nx_azure_iot_cloud);
    if (status)
    {
        LogError("IoT delete fail: 0x%02x", status);
        return(status);
    }

    _nx_azure_iot_created_ptr = NX_NULL;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_buffer_allocate(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR **buffer_pptr,
                                  UINT *buffer_size, VOID **buffer_context)
{
NX_PACKET *packet_ptr;
UINT status;

    status = nx_packet_allocate(nx_azure_iot_ptr -> nx_azure_iot_pool_ptr,
                                &packet_ptr, 0, NX_AZURE_IOT_WAIT_OPTION);
    if (status)
    {
        return(status);
    }

    *buffer_pptr = packet_ptr -> nx_packet_data_start;
    *buffer_size = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_data_start);
    *buffer_context = (VOID *)packet_ptr;
    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_buffer_free(VOID *buffer_context)
{
NX_PACKET *packet_ptr = (NX_PACKET *)buffer_context;

    return(nx_packet_release(packet_ptr));
}

UINT nx_azure_iot_publish_packet_get(NX_AZURE_IOT *nx_azure_iot_ptr, NXD_MQTT_CLIENT *client_ptr,
                                     NX_PACKET **packet_pptr, UINT wait_option)
{
UINT status;

    status = nx_secure_tls_packet_allocate(&(client_ptr -> nxd_mqtt_tls_session),
                                           nx_azure_iot_ptr -> nx_azure_iot_pool_ptr,
                                           packet_pptr, wait_option);
    if (status)
    {
        LogError("Create publish packet failed");
        return(status);
    }

    /* Preserve room for fixed MQTT header. */
    (*packet_pptr) -> nx_packet_prepend_ptr += NX_AZURE_IOT_PUBLISH_PACKET_START_OFFSET;

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_publish_mqtt_packet(NXD_MQTT_CLIENT *client_ptr, NX_PACKET *packet_ptr,
                                      UINT topic_len, UCHAR *packet_id, UINT qos, UINT wait_option)
{
UINT status;

    status = nx_azure_iot_publish_packet_header_add(packet_ptr, topic_len, qos);
    if (status)
    {
        LogError("failed to add mqtt header");
        return(status);
    }

    /* Note, mutex will be released by this function. */
    status = _nxd_mqtt_client_publish_packet_send(client_ptr, packet_ptr,
                                                  (USHORT)((packet_id[0] << 8) | packet_id[1]),
                                                  qos, wait_option);
    if (status)
    {
        LogError("Mqtt client send fail: PUBLISH FAIL: 0x%02x", status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_mqtt_packet_id_get(NXD_MQTT_CLIENT *client_ptr, UCHAR *packet_id, UINT wait_option)
{
UINT status;

    /* get packet id under mutex */
    status = tx_mutex_get(client_ptr -> nxd_mqtt_client_mutex_ptr, wait_option);
    if (status)
    {
        return(status);
    }

    /* Internal API assuming it to be 2 Byte buffer */
    packet_id[0] = (UCHAR)(client_ptr -> nxd_mqtt_client_packet_identifier >> 8);
    packet_id[1] = (UCHAR)(client_ptr -> nxd_mqtt_client_packet_identifier & 0xFF);

    /* Update packet id. */
    client_ptr -> nxd_mqtt_client_packet_identifier = (client_ptr -> nxd_mqtt_client_packet_identifier + 1) & 0xFFFF;

    /* Prevent packet identifier from being zero. MQTT-2.3.1-1 */
    if(client_ptr -> nxd_mqtt_client_packet_identifier == 0)
    {
        client_ptr -> nxd_mqtt_client_packet_identifier = 1;
    }

    tx_mutex_put(client_ptr -> nxd_mqtt_client_mutex_ptr);

    return(NX_AZURE_IOT_SUCCESS);
}

VOID nx_azure_iot_mqtt_packet_adjust(NX_PACKET *packet_ptr)
{
UINT size;
UINT copy_size;
NX_PACKET *current_packet_ptr;

    /* Adjust the packet to make sure,
     * 1. nx_packet_prepend_ptr does not pointer to nx_packet_data_start.
     * 2. The first packet is full if it is chained with multiple packets. */

    if (packet_ptr -> nx_packet_prepend_ptr != packet_ptr -> nx_packet_data_start)
    {

        /* Move data to the nx_packet_data_start. */
        size = (UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr);
        memmove(packet_ptr -> nx_packet_data_start, packet_ptr -> nx_packet_prepend_ptr, size);
        packet_ptr -> nx_packet_prepend_ptr = packet_ptr -> nx_packet_data_start;
        packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_data_start + size;
    }

    if (packet_ptr -> nx_packet_next == NX_NULL)
    {

        /* All data are in the first packet. */
        return;
    }

    /* Move data in the chained packet into first one until it is full. */
    for (current_packet_ptr = packet_ptr -> nx_packet_next;
         current_packet_ptr;
         current_packet_ptr = packet_ptr -> nx_packet_next)
    {

        /* Calculate remaining buffer size in the first packet. */
        size = (UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_append_ptr);

        /* Calculate copy size from current packet. */
        copy_size = (UINT)(current_packet_ptr -> nx_packet_append_ptr - current_packet_ptr -> nx_packet_prepend_ptr);

        if (size >= copy_size)
        {

            /* Copy all data from current packet. */
            memcpy((VOID *)packet_ptr -> nx_packet_append_ptr, (VOID *)current_packet_ptr -> nx_packet_prepend_ptr, copy_size);
            packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_append_ptr + copy_size;
        }
        else
        {

            /* Copy partial data from current packet. */
            memcpy(packet_ptr -> nx_packet_append_ptr, current_packet_ptr -> nx_packet_prepend_ptr, size);
            packet_ptr -> nx_packet_append_ptr = packet_ptr -> nx_packet_data_end;

            /* Move data in current packet to nx_packet_data_start. */
            memmove((VOID *)current_packet_ptr -> nx_packet_data_start,
                    (VOID *)(current_packet_ptr -> nx_packet_prepend_ptr + size),
                    (copy_size - size));
            current_packet_ptr -> nx_packet_prepend_ptr = current_packet_ptr -> nx_packet_data_start;
            current_packet_ptr -> nx_packet_append_ptr = current_packet_ptr -> nx_packet_data_start + (copy_size - size);

            /* First packet is full. */
            break;
        }

        /* Remove current packet from packet chain. */
        packet_ptr -> nx_packet_next = current_packet_ptr -> nx_packet_next;

        /* Release current packet. */
        current_packet_ptr -> nx_packet_next = NX_NULL;
        nx_packet_release(current_packet_ptr);
    }
}

UINT nx_azure_iot_mqtt_tls_setup(NXD_MQTT_CLIENT *client_ptr, NX_SECURE_TLS_SESSION *tls_session,
                                 NX_SECURE_X509_CERT *certificate,
                                 NX_SECURE_X509_CERT *trusted_certificate)
{
UINT status;
NX_AZURE_IOT_RESOURCE *resource_ptr;

    NX_PARAMETER_NOT_USED(certificate);
    NX_PARAMETER_NOT_USED(trusted_certificate);

    /* Obtain the mutex.   */
    tx_mutex_get(client_ptr -> nxd_mqtt_client_mutex_ptr, TX_WAIT_FOREVER);

    resource_ptr = nx_azure_iot_resource_search(client_ptr);

    /* Release the mutex.  */
    tx_mutex_put(client_ptr -> nxd_mqtt_client_mutex_ptr);

    if (resource_ptr == NX_NULL)
    {
        LogError("Failed to find associated resource");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    /* Create TLS session.  */
    status = _nx_secure_tls_session_create_ext(tls_session,
                                               resource_ptr -> resource_crypto_array,
                                               resource_ptr -> resource_crypto_array_size,
                                               resource_ptr -> resource_cipher_map,
                                               resource_ptr -> resource_cipher_map_size,
                                               resource_ptr -> resource_metadata_ptr,
                                               resource_ptr -> resource_metadata_size);
    if (status)
    {
        LogError("Failed to create TLS session: 0x%02x", status);
        return(status);
    }

    status = nx_secure_tls_trusted_certificate_add(tls_session, resource_ptr -> resource_trusted_certificate);
    if (status)
    {
        LogError("Failed to add trusted CA certificate to session: 0x%02x", status);
        return(status);
    }

    if (resource_ptr -> resource_device_certificate)
    {
        status = nx_secure_tls_local_certificate_add(tls_session, resource_ptr -> resource_device_certificate);
        if (status)
        {
            LogError("Failed to add device certificate to session: 0x%02x", status);
            return(status);
        }
    }

    status = nx_secure_tls_session_packet_buffer_set(tls_session,
                                                     resource_ptr -> resource_tls_packet_buffer,
                                                     sizeof(resource_ptr -> resource_tls_packet_buffer));
    if (status)
    {
        LogError("Failed to set the session packet buffer: 0x%02x", status);
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}

UINT nx_azure_iot_unix_time_get(NX_AZURE_IOT *nx_azure_iot_ptr, ULONG *unix_time)
{

    if ((nx_azure_iot_ptr == NX_NULL) ||
        (nx_azure_iot_ptr -> nx_azure_iot_unix_time_get == NX_NULL) ||
        (unix_time == NX_NULL))
    {
        LogError("Unix time callback not set");
        return(NX_AZURE_IOT_INVALID_PARAMETER);
    }

    return(nx_azure_iot_ptr -> nx_azure_iot_unix_time_get(unix_time));
}

static UINT nx_azure_iot_base64_decode(CHAR *base64name, UINT length, UCHAR *name, UINT name_size, UINT *bytes_copied)
{
UINT    i, j;
UINT    value1, value2;
UINT    step;
UINT    sourceLength = length;

    /* Adjust the length to represent the ASCII name.  */
    length =  ((length * 6) / 8);

    if (base64name[sourceLength - 1] == '=')
    {
        if (base64name[sourceLength - 2] == '=')
        {
            length --;
        }
        length--;
    }

    if (name_size < length)
    {
        LogError("Failed to find enough memory");
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* Setup index into the ASCII name.  */
    j =  0;

    /* Compute the ASCII name.  */
    step =  0;
    i =     0;
    while ((j < length) && (base64name[i]) && (base64name[i] != '='))
    {

        /* Derive values of the Base64 name.  */
        if ((base64name[i] >= 'A') && (base64name[i] <= 'Z'))
            value1 =  (UINT) (base64name[i] - 'A');
        else if ((base64name[i] >= 'a') && (base64name[i] <= 'z'))
            value1 =  (UINT) (base64name[i] - 'a') + 26;
        else if ((base64name[i] >= '0') && (base64name[i] <= '9'))
            value1 =  (UINT) (base64name[i] - '0') + 52;
        else if (base64name[i] == '+')
            value1 =  62;
        else if (base64name[i] == '/')
            value1 =  63;
        else
            value1 =  0;

        /* Derive value for the next character.  */
        if ((base64name[i+1] >= 'A') && (base64name[i+1] <= 'Z'))
            value2 =  (UINT) (base64name[i+1] - 'A');
        else if ((base64name[i+1] >= 'a') && (base64name[i+1] <= 'z'))
            value2 =  (UINT) (base64name[i+1] - 'a') + 26;
        else if ((base64name[i+1] >= '0') && (base64name[i+1] <= '9'))
            value2 =  (UINT) (base64name[i+1] - '0') + 52;
        else if (base64name[i+1] == '+')
            value2 =  62;
        else if (base64name[i+1] == '/')
            value2 =  63;
        else
            value2 =  0;

        /* Determine which step we are in.  */
        if (step == 0)
        {

            /* Use first value and first 2 bits of second value.  */
            name[j++] =    (UCHAR) (((value1 & 0x3f) << 2) | ((value2 >> 4) & 3));
            i++;
            step++;
        }
        else if (step == 1)
        {

            /* Use last 4 bits of first value and first 4 bits of next value.  */
            name[j++] =    (UCHAR) (((value1 & 0xF) << 4) | (value2 >> 2));
            i++;
            step++;
        }
        else if (step == 2)
        {

            /* Use first 2 bits and following 6 bits of next value.  */
            name[j++] =   (UCHAR) (((value1 & 3) << 6) | (value2 & 0x3f));
            i++;
            i++;
            step =  0;
        }
    }

    /* Put a NULL character in.  */
    name[j] =  NX_NULL;
    *bytes_copied = j;

    return(NX_AZURE_IOT_SUCCESS);
}

static UINT nx_azure_iot_base64_encode(UCHAR *name, UINT length, CHAR *base64name, UINT base64name_size)
{
UINT    pad;
UINT    i, j;
UINT    step;


    /* Adjust the length to represent the base64 name.  */
    length =  ((length * 8) / 6);

    /* Default padding to none.  */
    pad =  0;

    /* Determine if an extra conversion is needed.  */
    if ((length * 6) % 24)
    {
        /* Some padding is needed.  */

        /* Calculate the number of pad characters.  */
        pad =  (length * 6) % 24;
        pad =  (24 - pad) / 6;
        pad =  pad - 1;

        /* Adjust the length to pickup the character fraction.  */
        length++;
    }

    if (base64name_size <= length)
    {
        LogError("Failed to find enough memory");
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    /* Setup index into the base64name.  */
    j =  0;

    /* Compute the base64name.  */
    step =  0;
    i =     0;
    while (j < length)
    {
        /* Determine which step we are in.  */
        if (step == 0)
        {
            /* Use first 6 bits of name character for index.  */
            base64name[j++] =  (CHAR)_nx_azure_iot_base64_array[((UINT) name[i]) >> 2];
            step++;
        }
        else if (step == 1)
        {

            /* Use last 2 bits of name character and first 4 bits of next name character for index.  */
            base64name[j++] =  (CHAR)_nx_azure_iot_base64_array[((((UINT) name[i]) & 0x3) << 4) | (((UINT) name[i+1]) >> 4)];
            i++;
            step++;
        }
        else if (step == 2)
        {

            /* Use last 4 bits of name character and first 2 bits of next name character for index.  */
            base64name[j++] =  (CHAR)_nx_azure_iot_base64_array[((((UINT) name[i]) & 0xF) << 2) | (((UINT) name[i+1]) >> 6)];
            i++;
            step++;
        }
        else /* Step 3 */
        {

            /* Use last 6 bits of name character for index.  */
            base64name[j++] =  (CHAR)_nx_azure_iot_base64_array[(((UINT) name[i]) & 0x3F)];
            i++;
            step = 0;
        }
    }

    /* Determine if the index needs to be advanced.  */
    if (step != 3)
        i++;

    /* Now add the PAD characters.  */
    while ((pad--) && (j < base64name_size))
    {

        /* Pad base64name with '=' characters.  */
        base64name[j++] = '=';
    }

    /* Put a NULL character in.  */
    base64name[j] =  NX_NULL;

    return(NX_AZURE_IOT_SUCCESS);
}

/* HMAC-SHA256(master key, message ) */
static UINT nx_azure_iot_hmac_sha256_calculate(NX_AZURE_IOT_RESOURCE *resource_ptr, UCHAR *key, UINT key_size,
                                               UCHAR *message, UINT message_size, UCHAR *output)
{
UINT i;
UINT status;
VOID *handler;
UCHAR *metadata_ptr = resource_ptr -> resource_metadata_ptr;
UINT metadata_size = resource_ptr -> resource_metadata_size;
const NX_CRYPTO_METHOD *hmac_sha_256_crypto_method = NX_NULL;


    /* Find hmac sha256 crypto method.  */
    for(i = 0; i < resource_ptr -> resource_crypto_array_size; i++)
    {
        if(resource_ptr -> resource_crypto_array[i] -> nx_crypto_algorithm == NX_CRYPTO_AUTHENTICATION_HMAC_SHA2_256)
        {
            hmac_sha_256_crypto_method = resource_ptr -> resource_crypto_array[i];
            break;
        }
    }

    /* Check if find the crypto method.  */
    if (hmac_sha_256_crypto_method == NX_NULL)
    {
        return(NX_AZURE_IOT_NO_AVAILABLE_CIPHER);
    }

    /* Initialize.  */
    status = hmac_sha_256_crypto_method -> nx_crypto_init((NX_CRYPTO_METHOD *)hmac_sha_256_crypto_method,
                                                          key, (key_size << 3),
                                                          &handler,
                                                          metadata_ptr,
                                                          metadata_size);
    if (status)
    {
        return(status);
    }

    /* Authenticate.  */
    status = hmac_sha_256_crypto_method -> nx_crypto_operation(NX_CRYPTO_AUTHENTICATE,
                                                               handler,
                                                               (NX_CRYPTO_METHOD *)hmac_sha_256_crypto_method,
                                                               key,
                                                               (key_size << 3),
                                                               message,
                                                               message_size,
                                                               NX_CRYPTO_NULL,
                                                               output,
                                                               32,
                                                               metadata_ptr,
                                                               metadata_size,
                                                               NX_CRYPTO_NULL,
                                                               NX_CRYPTO_NULL);
    if (status)
    {
        return(status);
    }

    /* Cleanup.  */
    status = hmac_sha_256_crypto_method -> nx_crypto_cleanup(metadata_ptr);

    return(status);
}

UINT nx_azure_iot_url_encoded_hmac_sha256_calculate(NX_AZURE_IOT_RESOURCE *resource_ptr,
                                                    UCHAR *key_ptr, UINT key_size,
                                                    UCHAR *message_ptr, UINT message_size,
                                                    UCHAR *buffer_ptr, UINT buffer_len,
                                                    UCHAR **output_pptr, UINT *output_len)
{
UINT status;
UCHAR *hash_buf;
UINT hash_buf_size = 33;
CHAR *encoded_hash_buf;
UINT encoded_hash_buf_size = 48;
UINT binary_key_buf_size;

    binary_key_buf_size = buffer_len;
    status = nx_azure_iot_base64_decode((CHAR *)key_ptr, key_size,
                                        buffer_ptr, binary_key_buf_size, &binary_key_buf_size);
    if (status)
    {
        LogError("Failed to base64 decode");
        return(status);
    }

    buffer_len -= binary_key_buf_size;
    if ((hash_buf_size + encoded_hash_buf_size) > buffer_len)
    {
        LogError("Failed to not enough memory");
        return(NX_AZURE_IOT_INSUFFICIENT_BUFFER_SPACE);
    }

    hash_buf = buffer_ptr + binary_key_buf_size;
    status = nx_azure_iot_hmac_sha256_calculate(resource_ptr, buffer_ptr, binary_key_buf_size,
                                                message_ptr, (UINT)message_size, hash_buf);
    if (status)
    {
        LogError("Failed to get hash256");
        return(status);
    }

    buffer_len -= hash_buf_size;
    encoded_hash_buf = (CHAR *)(hash_buf + hash_buf_size);
    /* Additional space is required by encoder */
    hash_buf[hash_buf_size - 1] = 0;
    status = nx_azure_iot_base64_encode(hash_buf, hash_buf_size - 1,
                                        encoded_hash_buf, encoded_hash_buf_size);
    if (status)
    {
        LogError("Failed to base64 encode");
        return(status);
    }

    buffer_len -= encoded_hash_buf_size;
    *output_pptr = (UCHAR *)(encoded_hash_buf + encoded_hash_buf_size);
    status = nx_azure_iot_url_encode(encoded_hash_buf, strlen(encoded_hash_buf),
                                     (CHAR *)*output_pptr, buffer_len, output_len);
    if (status)
    {
        LogError("Failed to get hash256");
        return(status);
    }

    return(NX_AZURE_IOT_SUCCESS);
}
