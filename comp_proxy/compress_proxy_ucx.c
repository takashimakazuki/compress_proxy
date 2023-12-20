#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif


#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <string.h>
#include <assert.h>

#include <doca_log.h>

#include "compress_proxy_ucx.h"

/***** Main UCX operations *****/

doca_error_t
compress_proxy_ucx_init(unsigned int max_am_id, struct compress_proxy_ucx_context **context_p)
{
	ucp_params_t context_params = {
		/* Features, request initialize callback and request size are specified */
		.field_mask = UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_REQUEST_INIT | UCP_PARAM_FIELD_REQUEST_SIZE,
		/* Request support for Active messages (AM) in a UCP context */
		.features = UCP_FEATURE_AM,
		/* Function which will be invoked to fill UCP request upon allocation */
		.request_init = request_init,
		/* Size of UCP request */
		.request_size = sizeof(struct compress_proxy_ucx_request)
	};
	ucp_worker_params_t worker_params = {
		/* Thread mode is specified */
		.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE,
		/* UCP worker progress and all send/receive operations must be called from a single thread at the same
		 * time
		 */
		.thread_mode = UCS_THREAD_MODE_SINGLE
	};
	ucs_status_t status;
	struct compress_proxy_ucx_context *context;

	context = malloc(sizeof(*context));
	if (context == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory for UCX context");
		return DOCA_ERROR_NO_MEMORY;
	}

	context->am_callback_infos = NULL;
	context->listener = NULL;

	/* Save maximum AM ID which will be specified by the user */
	context->max_am_id = max_am_id;

	/* Allocate hash to hold all connections created by user or accepted from a peer */
	context->ep_to_connections_hash =
		g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, destroy_connection_callback);
	if (context->ep_to_connections_hash == NULL) {
		free(context);
		return DOCA_ERROR_NO_MEMORY;
	}
	active_connections_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
	if (active_connections_hash == NULL) {
		g_hash_table_destroy(context->ep_to_connections_hash);
		free(context);
		return DOCA_ERROR_NO_MEMORY;
	}

	/* UCP has default config that is set by env vars, we don't need to change it, so using NULL */
	status = ucp_init(&context_params, NULL, &context->context);
	if (status != UCS_OK) {
		DOCA_LOG_ERR("Failed to create UCP context: %s", ucs_status_string(status));
		g_hash_table_destroy(active_connections_hash);
		g_hash_table_destroy(context->ep_to_connections_hash);
		free(context);
		return DOCA_ERROR_INITIALIZATION;
	}

	/* Create UCP worker */
	status = ucp_worker_create(context->context, &worker_params, &context->worker);
	if (status != UCS_OK) {
		DOCA_LOG_ERR("Failed to create UCP worker: %s", ucs_status_string(status));
		ucp_cleanup(context->context);
		g_hash_table_destroy(active_connections_hash);
		g_hash_table_destroy(context->ep_to_connections_hash);
		free(context);
		return DOCA_ERROR_INITIALIZATION;
	}

	/* Use 'max_am_id + 1' to set AM callback to receive connection check message */
	am_set_recv_handler_common(context->worker, context->max_am_id + 1, am_connection_check_recv_callback, NULL);

	*context_p = context;

	return DOCA_SUCCESS;
}

void
compress_proxy_ucx_destroy(struct compress_proxy_ucx_context *context)
{
	/* Destroy all created connections inside hash destroy operation */
	g_hash_table_destroy(context->ep_to_connections_hash);
	/* Destroy this table after the above because cleanup method for values in the above table uses both tables */
	g_hash_table_destroy(active_connections_hash);

	if (context->listener != NULL) {
		/* Destroy UCP listener if it was created by a user */
		ucp_listener_destroy(context->listener);
	}

	/* Destroy UCP worker */
	ucp_worker_destroy(context->worker);
	/* Destroy UCP context */
	ucp_cleanup(context->context);

	free(context->am_callback_infos);
	free(context);
}

int
compress_proxy_ucx_listen(struct compress_proxy_ucx_context *context, uint16_t port)
{
	/* Listen on any IPv4 address and the user-specified port */
	const struct sockaddr_in listen_addr = {
		/* Set IPv4 address family */
		.sin_family = AF_INET,
		.sin_addr = {
			/* Set any address */
			.s_addr = INADDR_ANY
		},
		/* Set port from the user */
		.sin_port = htons(port)
	};
	ucp_listener_params_t listener_params = {
		/* Socket address and conenction handler are specified */
		.field_mask = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR | UCP_LISTENER_PARAM_FIELD_CONN_HANDLER,
		/* Listen address */
		.sockaddr.addr = (const struct sockaddr *)&listen_addr,
		/* Size of listen address */
		.sockaddr.addrlen = sizeof(listen_addr),
		/* Incoming connection handler */
		.conn_handler.cb = connect_callback,
		/* UCX context which is owner of the connection */
		.conn_handler.arg = context
	};
	ucs_status_t status;

	/* Create UCP listener to accept incoming connections */
	status = ucp_listener_create(context->worker, &listener_params, &context->listener);
	if (status != UCS_OK) {
		DOCA_LOG_ERR("Failed to create UCP listener: %s", ucs_status_string(status));
		return -1;
	}

	return 0;
}

doca_error_t
compress_proxy_ucx_progress(struct compress_proxy_ucx_context *context)
{
	/* Progress send and receive operations on UCP worker */
	ucp_worker_progress(context->worker);
	return callback_errno;
}
