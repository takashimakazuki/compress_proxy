
#ifndef UCX_CORE_H_
#define UCX_CORE_H_

#include <stdbool.h>

#include <ucp/api/ucp.h>

/* @NOTE: am = active message */

struct compress_proxy_ucx_context;
struct compress_proxy_ucx_connection;
struct compress_proxy_ucx_request;
struct compress_proxy_ucx_am_desc;

/*
 * Function pointer type of general "compress_proxy_ucx" callback to be called after a communication operation has endded
 */
typedef doca_error_t (*compress_proxy_ucx_callback)(void *arg, ucs_status_t status);
/*
 * Function pointer type of general Active Message callback to be called after an AM communication operation has endded
 */
typedef doca_error_t (*compress_proxy_ucx_am_callback)(struct compress_proxy_ucx_am_desc *am_desc);

/***** Requests Processing *****/

/*
 * Waits until an "compress_proxy_ucx" action is finished
 *
 * @ret [in]: The return value from the "compress_proxy_ucx_<operation>" function
 * @request [in]: The UCX request handle returned from the "compress_proxy_ucx_<operation>" function, can be NULL to ignore
 * @return: 0 on success and negative value otherwise
 */
int compress_proxy_ucx_request_wait(int ret, struct compress_proxy_ucx_request *request);

/*
 * Releases an UCX request handle
 *
 * @request [in]: The handle to free
 */
void compress_proxy_ucx_request_release(struct compress_proxy_ucx_request *request);

/***** Active Message send operation *****/

/*
 * Sends a message with a specific Active Message ID to the connection
 *
 * @connection [in]: Connection to send the data to
 * @am_id [in]: Active Message ID to associate the message with
 * @header [in]: Message header
 * @header_length [in]: Size of header in bytes
 * @buffer [in]: Buffer to send, can be GPU memory
 * @length [in]: Size of the buffer in bytes
 * @callback [in]: Callback to invoke once the send operation has completed
 * @arg [in]: Additional argument to pass the callback
 * @request_p [out]: Pointer to store UCX request handle, useful to track progress of the operation. Use NULL to ignore
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t compress_proxy_ucx_am_send(struct compress_proxy_ucx_connection *connection, unsigned int am_id, const void *header,
			  size_t header_length, const void *buffer, size_t length, compress_proxy_ucx_callback callback,
			  void *arg, struct compress_proxy_ucx_request **request_p);

/***** Active Message receive operation *****/

/*
 * Receive the message according to the Active Message descriptor
 *
 * @am_desc [in]: Pointer to a descriptor of the incoming message
 * @buffer [in]: Buffer to hold the incoming message
 * @length [in]: Size of the buffer in bytes
 * @callback [in]: Callback to invoke once the receive operation has completed
 * @arg [in]: Additional argument to pass the callback
 * @request_p [out]: Pointer to store UCX request handle, useful to track progress of the operation. Use NULL to ignore
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t compress_proxy_ucx_am_recv(struct compress_proxy_ucx_am_desc *am_desc, void *buffer, size_t length,
			  compress_proxy_ucx_callback callback, void *arg, struct compress_proxy_ucx_request **request_p);

/*
 * Query an Active Message message descriptor for some data on the incoming message it represents
 *
 * @am_desc [in]: Pointer to a descriptor of the incoming message
 * @connection [out]: The connection on which the incoming message will arrive or has arrived from
 * @header [out]: The incoming message header
 * @header_length [out]: The size of the header in bytes
 * @length [out]: The size of the incoming message
 */
void compress_proxy_ucx_am_desc_query(struct compress_proxy_ucx_am_desc *am_desc, struct compress_proxy_ucx_connection **connection,
				 const void **header, size_t *header_length, size_t *length);

/*
 * Sets a callback to be invoked with an Active Message descriptor once an incoming message arrives with the given ID
 *
 * @context [in]: UCX context to configure with the callback
 * @am_id [in]: Active Message ID to associate with the callback
 * @callback [in]: Callback to use for incoming messages with the given ID
 */
void compress_proxy_ucx_am_set_recv_handler(struct compress_proxy_ucx_context *context, unsigned int am_id,
				       compress_proxy_ucx_am_callback callback);

/***** Connection establishment *****/

/*
 * Connect to a remote node
 *
 * @context [in]: UCX context to use for the new connection
 * @dest_ip_str [in]: The remote node IP
 * @dest_port [in]: The remote node port
 * @connection_p [out]: The established connection
 * @return: 0 on success and negative value otherwise
 */
int compress_proxy_ucx_connect(struct compress_proxy_ucx_context *context, const char *dest_ip_str, uint16_t dest_port,
			  struct compress_proxy_ucx_connection **connection_p);

/*
 * Disconnect a present connection
 *
 * @connection [in]: connection to tear down
 */
void compress_proxy_ucx_disconnect(struct compress_proxy_ucx_connection *connection);

/***** Main UCX operations *****/

/*
 * Create UCX related resources
 *
 * @max_am_id [in]: A value bigger by 1 then the maximum Active Message ID that will be used
 * @context_p [out]: The create UCX context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t compress_proxy_ucx_init(unsigned int max_am_id, struct compress_proxy_ucx_context **context_p);

/*
 * Cleanup and teardown an existing UCX context
 *
 * @context [in]: UCX context to teardown
 */
void compress_proxy_ucx_destroy(struct compress_proxy_ucx_context *context);

/*
 * Create a UCX listener for incoming connection requests on the given port
 *
 * @context [in]: UCX context to use for the listener
 * @port [in]: Port number to use for the listener
 * @return: 0 on success and negative value otherwise
 */
int compress_proxy_ucx_listen(struct compress_proxy_ucx_context *context, uint16_t port);

/*
 * Progress the UCX communication - lets the UCX engine to process ingress and egress operations
 *
 * @context [in]: UCX context to progress
 * @return: DOCA_SUCCESS on success of all progress actions and callbacks and DOCA_ERROR otherwise
 */
doca_error_t compress_proxy_ucx_progress(struct compress_proxy_ucx_context *context);

#endif /** UCX_CORE_H_ */
