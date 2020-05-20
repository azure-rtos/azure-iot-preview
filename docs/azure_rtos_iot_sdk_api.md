# Azure RTOS IoT SDK API

## Azure IOT

**nx_azure_iot_create**
***
<div style="text-align: right"> Create the Azure IoT subsystem</div>

**Prototype**
```c
UINT nx_azure_iot_create(NX_AZURE_IOT *nx_azure_iot_ptr, UCHAR *name_ptr,
                         NX_IP *ip_ptr, NX_PACKET_POOL *pool_ptr, NX_DNS *dns_ptr,
                         VOID *stack_memory_ptr, UINT stack_memory_size,
                         UINT priority, UINT (*unix_time_callback)(ULONG *unix_time));
```
**Description**

<p>This routine creates the Azure IoT subsystem.  An internal thread is created to manage activities related to Azure IoT services. Only one `NX_AZURE_IOT` instance is needed to manage instances for Azure IoT hub, IoT Central, Device Provisioning Services (DPS), and Azure Security Center (ASC). </p>

**Parameters**
| Name | Description |
| - |:-|
| nx_azure_iot_ptr [in]    | A pointer to a NX_AZURE_IOT |
| name_ptr [in]      | A pointer to a NULL-terminated string indicating the name of the Azure IoT instance. |
| ip_ptr [in] | A pointer to a `NX_IP`, which is the IP stack used to connect to Azure IoT Services.     |
| pool_ptr [in] | A pointer to a `NX_PACKET_POOL`, which is the packet pool used by Azure IoT Services.     |
| dns_ptr [in] | A pointer to a `NX_DNS`.     |
| stack_memory_ptr [in] | A pointer to memory to be used as a stack space for the internal thread.     |
| stack_memory_size [in] | Size of stack memory area.  |
| priority [in] | Priority of the internal thread.    |
| unix_time_callback [in] | Callback to fetch unix time from platform.  |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully created the Azure IoT instance.

**Allowed From**

Initialization, Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_delete**
***
<div style="text-align: right"> Shutdown and cleanup the Azure IoT subsystem</div>

**Prototype**
```c
UINT  nx_azure_iot_delete(NX_AZURE_IOT *nx_azure_iot_ptr);
```
**Description**

<p>This routine stops all Azure services managed by this instance, and cleans up internal resources. </p>

**Parameters**

| Name | Description |
| - |:-|
| nx_azure_iot_ptr  [in]    | A pointer to a `NX_AZURE_IOT` |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successful stopped Azure IoT services and cleaned up internal resources.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

## Azure IOT Hub Client

**nx_azure_iot_hub_client_initialize**
***
<div style="text-align: right"> Initialize Azure IoT hub instance</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_initialize(NX_AZURE_IOT_HUB_CLIENT* hub_client_ptr,
                                        NX_AZURE_IOT *nx_azure_iot_ptr,
                                        UCHAR *host_name, UINT host_name_length,
                                        UCHAR *device_id, UINT device_id_length,
                                        UCHAR *module_id, UINT module_id_length,
                                        const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                        const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                        UCHAR * metadata_memory, UINT memory_size,
                                        NX_SECURE_X509_CERT *trusted_certificate);
```  
**Description**

<p>This routine initializes the IoT Hub client.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| nx_azure_iot_ptr [in]      | A pointer to a `NX_AZURE_IOT`.|
| host_name [in] | A pointer to IoTHub hostname. Must be NULL terminated string.   |
| host_name_length [in] | Length of the IoTHub hostname.  |
| device_id [in]  | A pointer to device ID.     |
| device_id_length [in] | Length of the device ID. |
| module_id [in]  | A pointer to module ID.     |
| module_id_length [in] | Length of the module ID. |
| crypto_array [in] | A pointer to `NX_CRYPTO_METHOD`    |
| crypto_array_size [in] | Size of crypto method array   |
| cipher_map [in] | A pointer to `NX_CRYPTO_CIPHERSUITE`    |
| cipher_map_size [in] | Size of cipher map    |
| metadata_memory [in] | A pointer to metadata memory buffer. |
| memory_size [in]  | Size of metadata buffer     |
| trusted_certificate [in] | A pointer to `NX_SECURE_X509_CERT`, which is server side certs |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully initialized the Azure IoT hub.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_deinitialize**
***
<div style="text-align: right"> Cleanup the Azure IoT Hub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_deinitialize(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>The routine deinitializes the IoT Hub client</p>

**Parameters**
|               |               |
| ------------- |:-------------|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successful deinitialized the IoT Hub instance.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_cert_set**
***
<div style="text-align: right"> Set client certificate </div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_cert_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                             NX_SECURE_X509_CERT *device_certificate);
```
**Description**

<p>This routine sets the device certificate.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |
| device_certificate [in]    | A pointer to a `NX_SECURE_X509_CERT` |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully added device certificate to AZ IoT Hub Instance.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_symmetric_key_set**
***
<div style="text-align: right"> Set symmetric key </div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_symmetric_key_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                               UCHAR *symmetric_key, UINT symmetric_key_length);
```
**Description**

<p>This routine sets the symmetric key.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |
| symmetric_key [in]    | A pointer to a symmetric key. |
| symmetric_key_length [in]    | Length of symmetric key |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully set the symmetric key to the IoT Hub client.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_connect**
***
<div style="text-align: right"> Connects to IoT Hub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_connect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                     UINT clean_session, UINT wait_option);
```
**Description**

<p>This routine connects to the Azure IoT Hub.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |
| clean_session [in]    | 0 re-use current session, or 1 to start new session |
| wait_option [in]    | Number of ticks to wait for internal resources to be available. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if connected to Azure IoT Hub.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_disconnect**
***
<div style="text-align: right"> Disconnects the client</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_disconnect(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>This routine disconnects the client.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if client disconnects.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_connection_status_callback_set**
***
<div style="text-align: right"> Sets connection status callback function</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_connection_status_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            VOID (*connection_status_cb)(
                                                                 struct NX_AZURE_IOT_HUB_CLIENT_STRUCT
                                                                 *hub_client_ptr, UINT status));
```
**Description**

<p>This routine sets the connection status callback. This callback function is invoked when the IoT Hub status is changed, such as: return NX_AZURE_IOT_HUB_CLIENT_STATUS_CONNECTED status once client is connected to IoT Hub. Setting the callback function to NULL disables the callback function.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |
| connection_status_cb [in]    | Pointer to a callback function invoked once connection status is changed. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if connection status callback is set.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_receive_callback_set**
***
<div style="text-align: right"> Sets receive callback function</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_receive_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                  UINT message_type,
                                                  VOID (*callback_ptr)(
                                                        NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, VOID *args),
                                                  VOID *callback_args);
```
**Description**

<p>This routine sets the IoT Hub receive callback function. This callback function is invoked when a message is received from Azure IoT hub. Setting the callback function to NULL disables the callback function. Message types can be NX_AZURE_IOT_HUB_CLOUD_TO_DEVICE_MESSAGE, NX_AZURE_IOT_HUB_DIRECT_METHOD, NX_AZURE_IOT_HUB_DEVICE_TWIN_DESIRED_PROPERTIES and NX_AZURE_IOT_HUB_DEVICE_TWIN_PROPERTIES. </p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| message_type [in]    | Message type of callback function. |
| callback_ptr [in]    | Pointer to a callback function invoked on specified message type is received. |
| callback_args [in]    | Pointer to an argument passed to callback function. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if callback function is set.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_telemetry_message_create**
***
<div style="text-align: right"> Creates telemetry message</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_telemetry_message_create(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                      NX_PACKET **packet_pptr,
                                                      UINT wait_option);
```
**Description**

<p>This routine prepares a packet for sending telemetry data. After the packet is properly created, application can add additional user-defined properties before sending out.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| packet_pptr [out]    | Return allocated packet on success. |
| wait_option [in]    | Ticks to wait if no packet is available. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if a packet is allocated.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_telemetry_message_delete**
***
<div style="text-align: right"> Deletes telemetry message</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_telemetry_message_delete(NX_PACKET *packet_ptr);
```
**Description**

<p>This routine deletes the telemetry message.</p>

**Parameters**

| Name | Description |
| - |:-|
| packet_ptr [in]    | Release the `NX_PACKET` on success. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if a packet is deallocated.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_telemetry_property_add**
***
<div style="text-align: right"> Adds property to telemetry message</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_telemetry_property_add(NX_PACKET *packet_ptr,
                                                    UCHAR *property_name, USHORT property_name_length,
                                                    UCHAR *property_value, USHORT property_value_length,
                                                    UINT wait_option);
```
**Description**

<p>This routine allows an application to add user-defined properties to a telemetry message before it is being sent. This routine can be called multiple times to add all the properties to the message. The properties are stored in the sequence which the routine is called. The property must be added after a telemetry packet is created, and before the telemetry message is being sent.</p>

**Parameters**

| Name | Description |
| - |:-|
| packet_ptr [in]    | A pointer to telemetry property packet. |
| property_name [in]    | Pointer to property name. |
| property_name_length [in]    | Length of property name. |
| property_value [in]    | Pointer to property value. |
| property_value_length [in]    | Length of property value. |
| wait_option [in]    | Ticks to wait if packet needs to be expanded. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if property is added.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_telemetry_send**
***
<div style="text-align: right"> Sends telemetry message to IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_telemetry_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, NX_PACKET *packet_ptr,
                                            UCHAR *telemetry_data, UINT data_size, UINT wait_option);
```
**Description**

<p>This routine sends telemetry to IoTHub, with packet_ptr containing all the properties.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| packet_ptr [in]    | A pointer to telemetry property packet. |
| telemetry_data [in]    | Pointer to telemetry data. |
| data_size [in]    | Size of telemetry data. |
| wait_option [in]    | Ticks to wait for message to be sent. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if telemetry message is sent out.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_cloud_message_enable**
***
<div style="text-align: right"> Enables receiving C2D message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_cloud_message_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>This routine enables receiving C2D message from IoT Hub.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if C2D message receiving is enabled.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_cloud_message_disable**
***
<div style="text-align: right"> Disables receiving C2D message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_cloud_message_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>This routine disables receiving C2D message from IoT Hub.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if C2D message receiving is disabled.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_cloud_message_receive**
***
<div style="text-align: right"> Receives C2D message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_cloud_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                   NX_PACKET **packet_pptr,
                                                   UINT wait_option);
```
**Description**

<p>This routine receives C2D message from IoT Hub. If there are no messages in the receive queue, this routine can block. The amount of time it waits for a message is determined by the wait_option parameter.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| packet_pptr [out]    | Return a packet pointer with C2D message on success. |
| wait_option [in]    | Ticks to wait for message to arrive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if C2D message is received.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_cloud_message_property_get**
***
<div style="text-align: right"> Retrieve the property with given property name in the C2D message</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_cloud_message_property_get(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, NX_PACKET *packet_ptr,
                                                        UCHAR *property_name, USHORT property_name_length,
                                                        UCHAR **property_value, USHORT *property_value_length);
```
**Description**

<p>This routine retrieves the property with given property name in the NX_PACKET.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| packet_ptr [in]    | Pointer to `NX_PACKET` containing C2D message. |
| property_name [in]    | Pointer to property name. |
| property_name_length [in]    | Property name length. |
| property_value [out]    | Pointer to memory that contains property value |
| property_value_length [out]    | Pointer to size of property value. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if property is found and copied successfully into user buffer.
* NX_AZURE_IOT_NOT_FOUND (0x20006)  If property is not found.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_direct_method_enable**
***
<div style="text-align: right"> Enables receiving direct method messages from IoTHub </div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_direct_method_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);

```
**Description**

<p>This routine enables receiving direct method messages from IoT Hub. </p>

**Parameters**
| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT` |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successful if direct method message receiving is enabled.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_direct_method_disable**
***
<div style="text-align: right"> Disables receiving direct method messages from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_direct_method_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>This routine disables receiving direct method messages from IoT Hub.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if direct method message receiving is disabled.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_direct_method_message_receive**
***
<div style="text-align: right"> Receives direct method message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_direct_method_message_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                           UCHAR **method_name_pptr, USHORT *method_name_length_ptr,
                                                           VOID **context_pptr, USHORT *context_length_ptr,
                                                           NX_PACKET **packet_pptr, UINT wait_option);
```
**Description**

<p>This routine receives direct method message from IoT Hub. If there are no messages in the receive queue, this routine can block. The amount of time it waits for a message is determined by the wait_option parameter.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| method_name_pptr [out]    | Return a pointer to method name on success. |
| method_name_length_ptr [out]    | Return length of method name on success. |
| context_pptr [out]    | Return a pointer to context pointer on success. |
| context_length_ptr [out]    | Return length of context on success. |
| packet_pptr [out]    | Return `NX_PACKET` containing the method payload on success. |
| wait_option [in]    | Ticks to wait for message to arrive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if direct method message is received.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_direct_method_message_response**
***
<div style="text-align: right"> Return response to direct method message from IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_direct_method_message_response(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            UINT status_code, VOID *context_ptr, USHORT context_length,,
                                                            UCHAR *payload, UINT payload_length, UINT wait_option);
```
**Description**

<p>This routine returns response to the direct method message from IoT Hub. Note: request_id ties the correlation between direct method receive and response.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| status_code [in]    | Status code for direct method. |
| context_ptr [in]    | Pointer to context return from nx_azure_iot_hub_client_direct_method_message_receive. |
| context_length [in]    | Length of context. |
| payload [in]    | Pointer to `UCHAR` containing the payload for the direct method response. Payload is in JSON format. |
| payload_length [in]    | Length of the payload |
| wait_option [in]    | Ticks to wait for message to send. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if direct method response is send.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_twin_enable**
***
<div style="text-align: right">Enables device twin feature</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_twin_enable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>This routine enables device twin feature.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if device twin feature is enabled.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_twin_disable**
***
<div style="text-align: right">Disables device twin feature</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_twin_disable(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr);
```
**Description**

<p>This routine disables device twin feature.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if device twin feature is disabled.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_report_properties_response_callback_set**
***
<div style="text-align: right">Sets reported properties response callback function</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_report_properties_response_callback_set(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                     VOID (*callback_ptr)(
                                                                           NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                           UINT request_id,
                                                                           UINT response_status, 
                                                                           VOID *args),
                                                                     VOID *callback_args);
```
**Description**

<p>This routine sets the response receive callback function for reported properties. This callback function is invoked when a response is received from Azure IoT hub for reported properties and no  thread is waiting for response. Setting the callback function to NULL disables the callback function.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| callback_ptr [in]    | Pointer to a callback function invoked. |
| callback_args [in]    | Pointer to an argument passed to callback function. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if callback function is set successfully.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_twin_reported_properties_send**
***
<div style="text-align: right">Send device twin reported properties to IoT Hub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_twin_reported_properties_send(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                  UCHAR *message_buffer, UINT message_length,
                                                                  UINT *request_id_ptr, UINT *response_status_ptr, 
                                                                  UINT wait_option);
```
**Description**

<p>This routine sends device twin reported properties to IoT Hub.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| message_buffer [in]    | JSON document containing the reported properties. |
| message_length [in]    | Length of JSON document. |
| request_id_ptr [out]    |  Request Id assigned to the request. |
| response_status_ptr [out]    | Status return for successful send of reported properties.|
| wait_option [in]    | Ticks to wait for message to send. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if device twin reported properties is sent successfully.

**Allowed From**

Threads

**Example**

**See Also**


<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_twin_properties_request**
***
<div style="text-align: right">Request complete device twin properties</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_twin_properties_request(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr, 
                                                            UINT wait_option);
```
**Description**

<p>This routine requests complete device twin properties.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| wait_option [in]    | Ticks to wait for to wait for sending request. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if device twin properties is requested successfully.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_twin_properties_receive**
***
<div style="text-align: right">Receive complete device twin properties</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_twin_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                            NX_PACKET **packet_pptr, UINT wait_option);
```
**Description**

<p>This routine receives complete device twin properties.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| packet_pptr [out]    | Pointer to `NX_PACKET*` that contains complete device twin properties. |
| wait_option [in]    | Ticks to wait for message to receive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if device twin properties is received successfully.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_hub_client_device_twin_desired_properties_receive**
***
<div style="text-align: right">Receive desired properties form IoTHub</div>

**Prototype**
```c
UINT nx_azure_iot_hub_client_device_twin_desired_properties_receive(NX_AZURE_IOT_HUB_CLIENT *hub_client_ptr,
                                                                    NX_PACKET **packet_pptr, UINT wait_option);
```
**Description**

<p>This routine receives desired properties from IoTHub.</p>

**Parameters**

| Name | Description |
| - |:-|
| hub_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_HUB_CLIENT`. |
| packet_pptr [out]    | Pointer to `NX_PACKET*` that contains complete twin document. |
| wait_option [in]    | Ticks to wait for message to receive. |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0)  Successful if desired properties are received successfully.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>


## Azure IOT Provisioning Client

**nx_azure_iot_provisioning_client_initialize**
***
<div style="text-align: right"> Initialize Azure IoT Provisioning instance</div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_initialize(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                 NX_AZURE_IOT *nx_azure_iot_ptr,
                                                 UCHAR *endpoint, UINT endpoint_length,
                                                 UCHAR *id_scope, UINT id_scope_length,
                                                 UCHAR *registration_id, UINT registration_id_length,
                                                 const NX_CRYPTO_METHOD **crypto_array, UINT crypto_array_size,
                                                 const NX_CRYPTO_CIPHERSUITE **cipher_map, UINT cipher_map_size,
                                                 UCHAR *metadata_memory, UINT memory_size,
                                                 NX_SECURE_X509_CERT *trusted_certificate);
```
**Description**

<p>This routine initializes the device to the IoT provisioning service.</p>

**Parameters**

| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT`. |
| nx_azure_iot_ptr [in]      | A pointer to a `NX_AZURE_IOT`.|
| endpoint [in] | A pointer to IoT Provisioning endpoint. Must be NULL terminated string.   |
| endpoint_length [in] | Length of the IoT Provisioning endpoint.  |
| id_scope [in]  | A pointer to ID Scope.     |
| id_scope_length [in] | Length of the ID Scope. |
| registration_id [in]  | A pointer to registration ID.     |
| registration_id_length [in] | Length of the registration ID. |
| crypto_array [in] | A pointer to `NX_CRYPTO_METHOD`    |
| crypto_array_size [in] | Size of crypto method array   |
| cipher_map [in] | A pointer to `NX_CRYPTO_CIPHERSUITE`    |
| cipher_map_size [in] | Size of cipher map    |
| metadata_memory [in] | A pointer to metadata memory buffer. |
| memory_size [in]  | Size of metadata buffer     |
| trusted_certificate [in] | A pointer to `NX_SECURE_X509_CERT`, which is server side certs |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully initialized to Azure IoT Provisioning Client.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_provisioning_client_deinitialize**
***
<div style="text-align: right"> Cleanup the Azure IoT Provisioning Client</div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_deinitialize(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr);
```
**Description**

<p>This routine de-initializes AZ IoT Provisioning Client. </p>

**Parameters**
| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT` |


**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully cleaned up AZ IoT Provisioning Client Instance.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_provisioning_client_device_cert_set**
***
<div style="text-align: right"> Set client certificate </div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_device_cert_set(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                      NX_SECURE_X509_CERT *client_x509_cert);
```
**Description**

<p>This routine sets device certificate.</p>

**Parameters**
| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT` |
| client_x509_cert [in]    | A pointer to a `NX_SECURE_X509_CERT`, client cert. |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully added device certs to AZ IoT Provisioning Client Instance.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_provisioning_client_symmetric_key_set**
***
<div style="text-align: right"> Set symmetric key </div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_symmetric_key_set(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                        UCHAR *symmetric_key, UINT symmetric_key_length);
```
**Description**

<p>This routine sets symmetric key.</p>

**Parameters**

| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT` |
| symmetric_key [in]    | A pointer to a symmetric key. |
| symmetric_key_length [in]    | Length of symmetric key |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully set symmetric key to IoT Provisioning client.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_provisioning_client_register**
***
<div style="text-align: right"> Register device to Azure IoT Provisioning service </div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_register(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr, UINT wait_option);

```
**Description**

<p>This routine registers device to Azure IoT Provisioning service.</p>

**Parameters**
| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT` |
| wait_option [in]    | Number of ticks to block for device registration. |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully register device to AZ IoT Provisioning.
* NX_AZURE_IOT_PENDING (0x2000D) Successfully started registration of device but not yet completed.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>


**nx_azure_iot_provisioning_client_completion_callback_set**
***
<div style="text-align: right"> Set registration completion callback </div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_completion_callback_set(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                              VOID (*on_complete_callback)(struct NX_AZURE_IOT_PROVISIONING_CLIENT_STRUCT *prov_client_ptr, UINT status));

```
**Description**

<p>This routine sets the callback for registration completion </p>

**Parameters**
| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT` |
| on_complete_callback [in]    | Registration completion callback. |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully register completion callback.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

**nx_azure_iot_provisioning_client_iothub_device_info_get**
***
<div style="text-align: right"> Get IoTHub device info into user supplied buffer </div>

**Prototype**
```c
UINT nx_azure_iot_provisioning_client_iothub_device_info_get(NX_AZURE_IOT_PROVISIONING_CLIENT *prov_client_ptr,
                                                             UCHAR *iothub_hostname, UINT *iothub_hostname_len,
                                                             UCHAR *device_id, UINT *device_id_len);

```
**Description**

<p>This routine gets IoTHub device info into user supplied buffer </p>

**Parameters**
| Name | Description |
| - |:-|
| prov_client_ptr [in]    | A pointer to a `NX_AZURE_IOT_PROVISIONING_CLIENT` |
| iothub_hostname [out]    | Buffer pointer that will contain IoTHub hostname. |
| iothub_hostname_len [inout]    | Pointer to UINT that contains size of buffer supplied, once successfully return it contains bytes copied to buffer |
| device_id [out]    | Buffer pointer that will contain IoTHub deviceId. |
| device_id_len [inout]    | Pointer to UINT that contains size of buffer supplied, once successfully return it contains bytes copied to buffer  |

**Return Values**
* NX_AZURE_IOT_SUCCESS (0x0) Successfully retrieved IoT Hub device info to user supplied buffers.

**Allowed From**

Threads

**Example**

**See Also**

<div style="page-break-after: always;"></div>

