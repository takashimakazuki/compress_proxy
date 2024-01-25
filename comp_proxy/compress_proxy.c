/*
 * UCP client - server example utility
 * -----------------------------------------------
 * Server side:
 *    ./compress_proxy
 * Client side:
 *    ./compress_proxy -a <server-ip>
 * 
 * - default send type: CLIENT_SERVER_SEND_RECV_DEFAULT (stream)
 * - send_recv_tag/send_recv_am is not implemented.
 */

#include "ucs_util.h"
#include "ucp_util.h"
#include "common.h"
#include "compress_proxy.h"
#include "mpi_dpuoffload.h"

#include <ucp/api/ucp.h>

#include <doca_error.h>
#include <doca_argp.h>
#include <doca_log.h>
#include <doca_comm_channel.h>

#include <string.h>    /* memset */
#include <arpa/inet.h> /* inet_addr */
#include <unistd.h>    /* getopt */
#include <stdlib.h>    /* atoi */
#include <bits/getopt_core.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>


// UCX Communication
#define DEFAULT_PORT           13337
#define IP_STRING_LEN          50
#define PORT_STRING_LEN        8
#define TAG                    0xCAFE
#define COMM_TYPE_DEFAULT      "STREAM"
#define PRINT_INTERVAL         2000
#define TEST_AM_ID             0

// #define DEBUG_TIMER_ENABLED    true

#define GET_TIME(_timespec_val) {\
    clock_gettime(CLOCK_MONOTONIC, &(_timespec_val));\
}
#define PRINT_TIME(_ts, _te) {\
    double _f = ((double)(_te).tv_sec*1e9 + (_te).tv_nsec) - ((double)(_ts).tv_sec*1e9 + (_ts).tv_nsec);\
    printf("time %f us\n", _f/1000);\
}

DOCA_LOG_REGISTER(COMPRESS_PROXY);

static uint16_t server_port    = DEFAULT_PORT;
static sa_family_t ai_family   = AF_INET;
static int connection_closed   = 1;

static bool quit_app;		/* Shared variable to allow for a proper shutdown */

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM || signum == SIGKILL) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		quit_app = true;
	}
}

static void common_cb(void *user_data, const char *type_str)
{
    test_req_t *ctx;

    if (user_data == NULL) {
        fprintf(stderr, "user_data passed to %s mustn't be NULL\n", type_str);
        return;
    }

    ctx           = user_data;
    ctx->complete = 1;
}

/**
 * The callback on the receiving side, which is invoked upon receiving the
 * stream message.
 */
static void stream_recv_cb(void *request, ucs_status_t status, size_t length,
                           void *user_data)
{
    common_cb(user_data, "stream_recv_cb");
}

/**
 * The callback on the sending side, which is invoked after finishing sending
 * the message.
 */
static void send_cb(void *request, ucs_status_t status, void *user_data)
{
    common_cb(user_data, "send_cb");
}

/**
 * Error handling callback.
 */
static void err_cb(void *arg, ucp_ep_h ep, ucs_status_t status)
{
    DOCA_LOG_ERR("error handling callback was invoked with status %d (%s)", status, ucs_status_string(status));
    connection_closed = 1;
}

/**
 * Set an address for the server to listen on - INADDR_ANY on a well known port.
 */
void set_sock_addr(const char *address_str, struct sockaddr_storage *saddr)
{
    struct sockaddr_in *sa_in;

    /* The server will listen on INADDR_ANY */
    memset(saddr, 0, sizeof(*saddr));

    switch (ai_family) {
    case AF_INET:
        sa_in = (struct sockaddr_in*)saddr;
        if (address_str != NULL) {
            inet_pton(AF_INET, address_str, &sa_in->sin_addr);
        } else {
            sa_in->sin_addr.s_addr = INADDR_ANY;
        }
        sa_in->sin_family = AF_INET;
        sa_in->sin_port   = htons(server_port);
        break;
    default:
        fprintf(stderr, "Invalid address family");
        break;
    }
}

/**
 * Initialize the client side. Create an endpoint from the client side to be
 * connected to the remote server (to the given IP).
 */
static ucs_status_t start_client(ucp_worker_h ucp_worker,
                                 const char *address_str, ucp_ep_h *client_ep)
{
    ucp_ep_params_t ep_params;
    struct sockaddr_storage connect_addr;
    ucs_status_t status;

    set_sock_addr(address_str, &connect_addr);

    /*
     * Endpoint field mask bits:
     * UCP_EP_PARAM_FIELD_FLAGS             - Use the value of the 'flags' field.
     * UCP_EP_PARAM_FIELD_SOCK_ADDR         - Use a remote sockaddr to connect
     *                                        to the remote peer.
     * UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE - Error handling mode - this flag
     *                                        is temporarily required since the
     *                                        endpoint will be closed with
     *                                        UCP_EP_CLOSE_MODE_FORCE which
     *                                        requires this mode.
     *                                        Once UCP_EP_CLOSE_MODE_FORCE is
     *                                        removed, the error handling mode
     *                                        will be removed.
     */
    ep_params.field_mask       = UCP_EP_PARAM_FIELD_FLAGS       |
                                 UCP_EP_PARAM_FIELD_SOCK_ADDR   |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                 UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
    ep_params.err_mode         = UCP_ERR_HANDLING_MODE_PEER;
    ep_params.err_handler.cb   = err_cb;
    ep_params.err_handler.arg  = NULL;
    ep_params.flags            = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER;
    ep_params.sockaddr.addr    = (struct sockaddr*)&connect_addr;
    ep_params.sockaddr.addrlen = sizeof(connect_addr);

    status = ucp_ep_create(ucp_worker, &ep_params, client_ep);
    if (status != UCS_OK) {
        DOCA_LOG_ERR("failed to connect to %s (%s)", address_str, ucs_status_string(status));
    }

    return status;
}

static inline int request_finalize(ucp_worker_h ucp_worker, test_req_t *request,
                            test_req_t *ctx, int is_receiver, ucp_dt_iov_t *iov)
{
    int ret = 0;
    ucs_status_t status;

#ifdef DEBUG_TIMER_ENABLED
    struct timespec tstart, tend;
    GET_TIME(tstart);
#endif

    if (request == NULL) {
        status = UCS_OK;
        goto check_request_status;
    }
    if (UCS_PTR_IS_ERR(request)) {
        status = UCS_PTR_STATUS(request);
        goto check_request_status;
    }

    /* Progress the request until it completes. */
    while (ctx->complete == 0) {
        if (quit_app) break;
        ucp_worker_progress(ucp_worker);
    }
    status = ucp_request_check_status(request);
    ucp_request_free(request);

check_request_status:
    if (status != UCS_OK) {
        fprintf(stderr, "unable to %s UCX message (%s)\n",
                is_receiver ? "receive": "send", ucs_status_string(status));
        return -1;
    }

#ifdef DEBUG_TIMER_ENABLED
    GET_TIME(tend);
    printf("request_finalize: ");
    PRINT_TIME(tstart, tend);
#endif
    // print_result(is_receiver, iov);
    return ret;
}

/**
 * Send and receive a message using the Stream API.
 * The client sends a message to the server and waits until the send it completed.
 * The server receives a message from the client and waits for its completion.
 */
static inline int send_recv_stream(
    ucp_worker_h ucp_worker, ucp_ep_h ep, 
    int is_receiver, void *buf, size_t *buf_len)
{
    ucp_request_param_t param;
    test_req_t *request;
    test_req_t ctx;
    int is_sender = !is_receiver;


    /* Set send/recv shared params */
    ctx.complete       = 0;
    param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK |
                          UCP_OP_ATTR_FIELD_DATATYPE |
                          UCP_OP_ATTR_FIELD_USER_DATA;
    param.datatype     = ucp_dt_make_contig(1);
    param.user_data    = &ctx;


    if (is_sender) {
        /* Client sends a message to the server using the stream API */
        param.cb.send = send_cb;
        request       = ucp_stream_send_nbx(ep, buf, *buf_len, &param);
    } else {
        /* Server receives a message from the client using the stream API */
        param.op_attr_mask  |= UCP_OP_ATTR_FIELD_FLAGS;
        param.flags          = UCP_STREAM_RECV_FLAG_WAITALL;
        param.cb.recv_stream = stream_recv_cb;
        request              = ucp_stream_recv_nbx(ep, buf, *buf_len, buf_len, &param);
    }

    return request_finalize(ucp_worker, request, &ctx, is_receiver, NULL);
}

static char* sockaddr_get_ip_str(const struct sockaddr_storage *sock_addr,
                                 char *ip_str, size_t max_size)
{
    struct sockaddr_in  addr_in;

    switch (sock_addr->ss_family) {
    case AF_INET:
        memcpy(&addr_in, sock_addr, sizeof(struct sockaddr_in));
        inet_ntop(AF_INET, &addr_in.sin_addr, ip_str, max_size);
        return ip_str;
    default:
        return "Invalid address family";
    }
}

static char* sockaddr_get_port_str(const struct sockaddr_storage *sock_addr,
                                   char *port_str, size_t max_size)
{
    struct sockaddr_in  addr_in;

    switch (sock_addr->ss_family) {
    case AF_INET:
        memcpy(&addr_in, sock_addr, sizeof(struct sockaddr_in));
        snprintf(port_str, max_size, "%d", ntohs(addr_in.sin_port));
        return port_str;
    default:
        return "Invalid address family";
    }
}

/**
 * Create a ucp worker on the given ucp context.
 */
static int init_worker(ucp_context_h ucp_context, ucp_worker_h *ucp_worker)
{
    ucp_worker_params_t worker_params;
    ucs_status_t status;
    int ret = 0;

    memset(&worker_params, 0, sizeof(worker_params));

    worker_params.field_mask  = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    status = ucp_worker_create(ucp_context, &worker_params, ucp_worker);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_worker_create (%s)\n", ucs_status_string(status));
        ret = -1;
    }

    return ret;
}

/**
 * The callback on the server side which is invoked upon receiving a connection
 * request from the client.
 */
static void server_conn_handle_cb(ucp_conn_request_h conn_request, void *arg)
{
    ucx_server_ctx_t *context = arg;
    ucp_conn_request_attr_t attr;
    char ip_str[IP_STRING_LEN];
    char port_str[PORT_STRING_LEN];
    ucs_status_t status;

    attr.field_mask = UCP_CONN_REQUEST_ATTR_FIELD_CLIENT_ADDR;
    status = ucp_conn_request_query(conn_request, &attr);
    if (status == UCS_OK) {
        printf("Server received a connection request from client at address %s:%s\n",
               sockaddr_get_ip_str(&attr.client_address, ip_str, sizeof(ip_str)),
               sockaddr_get_port_str(&attr.client_address, port_str, sizeof(port_str)));
    } else if (status != UCS_ERR_UNSUPPORTED) {
        fprintf(stderr, "failed to query the connection request (%s)\n",
                ucs_status_string(status));
    }

    if (context->conn_request == NULL) {
        context->conn_request = conn_request;
    } else {
        /* The server is already handling a connection request from a client,
         * reject this new one */
        printf("Rejecting a connection request. "
               "Only one client at a time is supported.\n");
        status = ucp_listener_reject(context->listener, conn_request);
        if (status != UCS_OK) {
            fprintf(stderr, "server failed to reject a connection request: (%s)\n",
                    ucs_status_string(status));
        }
    }
}

static ucs_status_t server_create_ep(ucp_worker_h data_worker,
                                     ucp_conn_request_h conn_request,
                                     ucp_ep_h *server_ep)
{
    ucp_ep_params_t ep_params;
    ucs_status_t    status;

    /* Server creates an ep to the client on the data worker.
     * This is not the worker the listener was created on.
     * The client side should have initiated the connection, leading
     * to this ep's creation */
    ep_params.field_mask      = UCP_EP_PARAM_FIELD_ERR_HANDLER |
                                UCP_EP_PARAM_FIELD_CONN_REQUEST;
    ep_params.conn_request    = conn_request;
    ep_params.err_handler.cb  = err_cb;
    ep_params.err_handler.arg = NULL;

    status = ucp_ep_create(data_worker, &ep_params, server_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to create an endpoint on the server: (%s)\n",
                ucs_status_string(status));
    }

    return status;
}

/**
 * Initialize the server side. The server starts listening on the set address.
 */
static ucs_status_t
start_server(ucp_worker_h ucp_worker, ucx_server_ctx_t *context,
             ucp_listener_h *listener_p, const char *address_str)
{
    struct sockaddr_storage listen_addr;
    ucp_listener_params_t params;
    ucp_listener_attr_t attr;
    ucs_status_t status;
    char ip_str[IP_STRING_LEN];
    char port_str[PORT_STRING_LEN];

    set_sock_addr(address_str, &listen_addr);

    params.field_mask         = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR |
                                UCP_LISTENER_PARAM_FIELD_CONN_HANDLER;
    params.sockaddr.addr      = (const struct sockaddr*)&listen_addr;
    params.sockaddr.addrlen   = sizeof(listen_addr);
    params.conn_handler.cb    = server_conn_handle_cb;
    params.conn_handler.arg   = context;

    /* Create a listener on the server side to listen on the given address.*/
    status = ucp_listener_create(ucp_worker, &params, listener_p);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to listen (%s)\n", ucs_status_string(status));
        goto out;
    }

    /* Query the created listener to get the port it is listening on. */
    attr.field_mask = UCP_LISTENER_ATTR_FIELD_SOCKADDR;
    status = ucp_listener_query(*listener_p, &attr);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to query the listener (%s)\n",
                ucs_status_string(status));
        ucp_listener_destroy(*listener_p);
        goto out;
    }

    fprintf(stderr, "server is listening on IP %s port %s\n",
            sockaddr_get_ip_str(&attr.sockaddr, ip_str, IP_STRING_LEN),
            sockaddr_get_port_str(&attr.sockaddr, port_str, PORT_STRING_LEN));

    printf("Waiting for connection...\n");

out:
    return status;
}

static int proxy_progress(ucp_worker_h ucp_worker,
                    ucp_ep_h ucp_ep,
                    send_recv_type_t send_recv_type, 
                    struct cpxy_cc_objects *cc_objects) {
    doca_error_t result;
    int ret = 0;

    // Receive buffer for data from Comm Channel
    struct mpi_dpuo_message msg_from_host;
    size_t msg_from_host_len = sizeof(struct mpi_dpuo_message);
    memset(&msg_from_host, 0, msg_from_host_len);

    DOCA_LOG_INFO("CC_Recv waiting...");

    while ((result = doca_comm_channel_ep_recvfrom(cc_objects->cc_ep, &msg_from_host, &msg_from_host_len, DOCA_CC_MSG_FLAG_NONE,
                            &cc_objects->cc_peer_addr)) == DOCA_ERROR_AGAIN) {
        if (quit_app) {
            result = DOCA_ERROR_UNEXPECTED;
            return ret;
        }
        msg_from_host_len = sizeof(struct mpi_dpuo_message);
    }
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Message was not received: %s", doca_error_get_descr(result));
        return ret;
    }
    DOCA_LOG_INFO("Received message from host through CC type: %d", msg_from_host.type);
    DOCA_LOG_INFO("Received message from host through CC buffer: '%s'", msg_from_host.buffer);
    DOCA_LOG_INFO("Received message from host through CC buffer_len: '%zd'", msg_from_host.buffer_len);
    DOCA_LOG_INFO("\n%s", hex_dump(&msg_from_host, msg_from_host_len));

    /* UCP_Send/Recv */
    DOCA_LOG_INFO("DATA/%s/%s", mpi_dpuo_message_type_string(msg_from_host.type), cpxy_sendrecv_type_string(send_recv_type));
    if (msg_from_host.type == MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST) {
        /* This process is sender */
        DOCA_LOG_INFO("UCP_Send start");

#ifdef DEBUG_TIMER_ENABLED
        struct timespec ts, te;
        GET_TIME(ts);
#endif
        ret = send_recv_stream(ucp_worker, ucp_ep, false, msg_from_host.buffer, &msg_from_host.buffer_len);
        if (ret != 0) {
            return ret;
        }
#ifdef DEBUG_TIMER_ENABLED
        GET_TIME(te);
        printf("UCP_Send: ");
        PRINT_TIME(ts, te);
#endif

    } else if (msg_from_host.type == MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST) {
        /* This process is receiver, should sends data to Host through CC. */
        struct mpi_dpuo_message msg;
        size_t msg_len = sizeof(struct mpi_dpuo_message);
        memset(&msg, 0, msg_len);
        size_t buf_len = msg_from_host.buffer_len;

#ifdef DEBUG_TIMER_ENABLED
        struct timespec ts, te;
        DOCA_LOG_INFO("UCP_Recv start");
        GET_TIME(ts);
#endif
        ret = send_recv_stream(ucp_worker, ucp_ep, true, msg.buffer, &buf_len);
        if (ret != 0) {
            return ret;
        }
#ifdef DEBUG_TIMER_ENABLED
        GET_TIME(te);
        printf("UCP_Recv: ");
        PRINT_TIME(ts, te);
#endif

        msg.type = MPI_DPUO_MESSAGE_TYPE_DATA_RESPONSE;
        msg.buffer_len = buf_len;

        DOCA_LOG_INFO("CC_Send to host start");
        result = doca_comm_channel_ep_sendto(cc_objects->cc_ep, &msg, msg_len, DOCA_CC_MSG_FLAG_NONE, cc_objects->cc_peer_addr);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Message was not received: %s", doca_error_get_descr(result));
            return ret;
        }
        DOCA_LOG_INFO("CC_Send to host finished");
    } else {
        DOCA_LOG_ERR("Unknown mpi_dpuo_message_type_t %d", msg_from_host.type);
    }

    return ret;
}


static int run_server(ucp_context_h ucp_context, ucp_worker_h ucp_worker,
                      char *listen_addr, send_recv_type_t send_recv_type,
                      struct cpxy_cc_objects *cc_objects)
{
    ucx_server_ctx_t context;
    ucp_worker_h     ucp_data_worker;
    ucp_ep_h         server_ep;
    ucs_status_t     status;
    int              ret;


    DOCA_LOG_INFO("run_server start");

    /* Create a data worker (to be used for data exchange between the server
     * and the client after the connection between them was established) */
    ret = init_worker(ucp_context, &ucp_data_worker);
    if (ret != 0) {
        goto err;
    }

    /* Initialize the server's context. */
    context.conn_request = NULL;

    /* Create a listener on the worker created at first. The 'connection
     * worker' - used for connection establishment between client and server.
     * This listener will stay open for listening to incoming connection
     * requests from the client */
    status = start_server(ucp_worker, &context, &context.listener, listen_addr);
    if (status != UCS_OK) {
        ret = -1;
        goto err_worker;
    }

    /* Server is always up listening */
    while (!quit_app) {
        /* Wait for the server to receive a connection request from the client.
         * If there are multiple clients for which the server's connection request
         * callback is invoked, i.e. several clients are trying to connect in
         * parallel, the server will handle only the first one and reject the rest */
        DOCA_LOG_DBG("while ucp_worker_progress start");
        while (context.conn_request == NULL) {
            if (quit_app) goto err_listener;
            ucp_worker_progress(ucp_worker);
        }

        /* Server creates an ep to the client on the data worker.
         * This is not the worker the listener was created on.
         * The client side should have initiated the connection, leading
         * to this ep's creation */
        DOCA_LOG_DBG("server_create_ep start");
        status = server_create_ep(ucp_data_worker, context.conn_request,
                                  &server_ep);
        if (status != UCS_OK) {
            ret = -1;
            goto err_listener;
        }

        char hello_msg[5] = "";
        size_t hello_msg_len = 5;
        DOCA_LOG_INFO("Waiting for Hello Message");
        ret = send_recv_stream(ucp_data_worker, server_ep, 1, hello_msg, &hello_msg_len);
        if (ret != 0) {
            goto err_ep;
        }
        DOCA_LOG_INFO("Hello Message received");

        while(!quit_app) {
            /* main loop */
            ret = proxy_progress(ucp_data_worker, server_ep, send_recv_type, cc_objects);
            if (ret != 0) goto err_ep;
        }

        /* Close the endpoint to the client */
        ep_close(ucp_data_worker, server_ep, UCP_EP_CLOSE_FLAG_FORCE);

        /* Reinitialize the server's context to be used for the next client */
        context.conn_request = NULL;

        DOCA_LOG_INFO("Waiting for connection...\n");
    }

err_ep:
    ep_close(ucp_data_worker, server_ep, UCP_EP_CLOSE_FLAG_FORCE);
err_listener:
    ucp_listener_destroy(context.listener);
err_worker:
    ucp_worker_destroy(ucp_data_worker);
err:
    return ret;
}

static int run_client(ucp_worker_h ucp_worker, char *server_addr, send_recv_type_t send_recv_type, struct cpxy_cc_objects *cc_objects)
{
    ucp_ep_h     client_ep;
    ucs_status_t status;
    int          ret;
    DOCA_LOG_INFO("run_client start");


    status = start_client(ucp_worker, server_addr, &client_ep);
    if (status != UCS_OK) {
        DOCA_LOG_ERR("failed to start client (%s)", ucs_status_string(status));
        ret = -1;
        goto out;
    }

    char hello_msg[5] = "HELLO";
    size_t hello_msg_len = 5;
    DOCA_LOG_INFO("Hello Message Sent");
    ret = send_recv_stream(ucp_worker, client_ep, 0, hello_msg, &hello_msg_len);
    if (ret != 0) {
        goto err_ep;
    }

    // Receive buffer for data from Comm Channel
    struct mpi_dpuo_message msg_from_host;
    size_t msg_from_host_len = sizeof(struct mpi_dpuo_message);
    memset(&msg_from_host, 0, msg_from_host_len);

    while(!quit_app) {
        /* main loop */
        ret = proxy_progress(ucp_worker, client_ep, send_recv_type, cc_objects);
        if (ret != 0) goto err_ep;
    }

err_ep:
    /* Close the endpoint to the server */
    ep_close(ucp_worker, client_ep, UCP_EP_CLOSE_FLAG_FORCE);

out:
    return ret;
}

/**
 * Initialize the UCP context and worker.
 */
static int init_ucp_context(ucp_context_h *ucp_context, ucp_worker_h *ucp_worker,
                        send_recv_type_t send_recv_type)
{
    /* UCP objects */
    ucp_params_t ucp_params;
    ucs_status_t status;
    int ret = 0;

    memset(&ucp_params, 0, sizeof(ucp_params));

    /* UCP initialization */
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES | UCP_PARAM_FIELD_NAME;
    ucp_params.name       = "compress_proxy";

    if (send_recv_type == CLIENT_SERVER_SEND_RECV_STREAM) {
        ucp_params.features = UCP_FEATURE_STREAM;
    } else if (send_recv_type == CLIENT_SERVER_SEND_RECV_TAG) {
        ucp_params.features = UCP_FEATURE_TAG;
    } else {
        ucp_params.features = UCP_FEATURE_AM;
    }

    status = ucp_init(&ucp_params, NULL, ucp_context);
    if (status != UCS_OK) {
        fprintf(stderr, "failed to ucp_init (%s)\n", ucs_status_string(status));
        ret = -1;
        goto err;
    }

    ret = init_worker(*ucp_context, ucp_worker);
    if (ret != 0) {
        goto err_cleanup;
    }

    return ret;

err_cleanup:
    ucp_cleanup(*ucp_context);
err:
    return ret;
}

/*
 * Run DOCA Comm Channel server sample
 *
 * @server_name [in]: Server Name
 * @dev_pci_addr [in]: PCI address for device
 * @rep_pci_addr [in]: PCI address for device representor
 * @text [in]: Server message
 * @cpxy_cc_objects[out]: Comm Channel objects
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static int
init_comm_channel_server(
    const char *server_name, const char *dev_pci_addr, const char *rep_pci_addr,
    struct cpxy_cc_objects *cc_objects)
{
	doca_error_t result;

	DOCA_LOG_INFO("init_comm_channel_server");
	/* Create Comm Channel endpoint */
	result = doca_comm_channel_ep_create(&cc_objects->cc_ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_error_get_descr(result));
		return result;
	}

	/* Open DOCA device according to the given PCI address */
	result = open_doca_device_with_pci(dev_pci_addr, NULL, &cc_objects->cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(cc_objects->cc_ep);
		return result;
	}

	/* Open DOCA device representor according to the given PCI address */
	result = open_doca_device_rep_with_pci(cc_objects->cc_dev, DOCA_DEVINFO_REP_FILTER_NET, rep_pci_addr, &cc_objects->cc_dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
		doca_comm_channel_ep_destroy(cc_objects->cc_ep);
		doca_dev_close(cc_objects->cc_dev);
		return result;
	}

	/* Set all endpoint properties */
	result = doca_comm_channel_ep_set_device(cc_objects->cc_ep, cc_objects->cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set device property");
		goto destroy_cc;
	}

    // TODO: max message size is 65535 (uint16)
	result = doca_comm_channel_ep_set_max_msg_size(cc_objects->cc_ep, sizeof(struct mpi_dpuo_message));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_send_queue_size(cc_objects->cc_ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(cc_objects->cc_ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_device_rep(cc_objects->cc_ep, cc_objects->cc_dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device representor property");
		goto destroy_cc;
	}

	/* Start listen for new connections */
	result = doca_comm_channel_ep_listen(cc_objects->cc_ep, server_name);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Comm Channel server couldn't start listening: %s", doca_error_get_descr(result));
		goto destroy_cc;
	}

	DOCA_LOG_INFO("CC Server started Listening, waiting for new connections");
    return result;

destroy_cc:
	/* Disconnect from current connection */
	if (cc_objects->cc_peer_addr != NULL)
		doca_comm_channel_ep_disconnect(cc_objects->cc_ep, cc_objects->cc_peer_addr);

	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(cc_objects->cc_ep);

	/* Destroy Comm Channel DOCA device representor */
	doca_dev_rep_close(cc_objects->cc_dev_rep);

	/* Destroy Comm Channel DOCA device */
	doca_dev_close(cc_objects->cc_dev);

	return result;
}


/*
 * ARGP Callback - Handle Comm Channel DOCA device PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t pci_addr_callback(void *param, void *config)
{
	struct cpxy_config *cfg = (struct cpxy_config *)config;
	const char *dev_pci_addr = (char *)param;
	int len;

	len = strnlen(dev_pci_addr, PCI_ADDR_LEN);
	/* Check using >= to make static code analysis satisfied */
	if (len >= PCI_ADDR_LEN) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", USER_PCI_ADDR_LEN);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* The string will be '\0' terminated due to the strnlen check above */
	strncpy(cfg->cc_dev_pci_addr, dev_pci_addr, len + 1);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device representor PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t rep_pci_addr_callback(void *param, void *config)
{
	struct cpxy_config *cfg = (struct cpxy_config *)config;
	const char *rep_pci_addr = (char *)param;
	int len;

	len = strnlen(rep_pci_addr, PCI_ADDR_LEN);
	/* Check using >= to make static code analysis satisfied */
	if (len >= PCI_ADDR_LEN) {
		DOCA_LOG_ERR("Entered device representor PCI address exceeding the maximum size of %d",
			     USER_PCI_ADDR_LEN);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* The string will be '\0' terminated due to the strnlen check above */
	strncpy(cfg->cc_dev_rep_pci_addr, rep_pci_addr, len + 1);

	return DOCA_SUCCESS;
}

static doca_error_t server_ip_addr_callback(void *param, void *config)
{
	struct cpxy_config *cfg = (struct cpxy_config *)config;
	const char *server_ip_addr = (char *)param;
	int len;

	len = strnlen(server_ip_addr, IP_ADDR_LEN);
	if (len >= IP_ADDR_LEN) {
		DOCA_LOG_ERR("Entered server ip address exceeding the maximum size of %d",
			     IP_ADDR_LEN);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strncpy(cfg->server_ip_addr, server_ip_addr, len + 1);

	return DOCA_SUCCESS;
}

doca_error_t register_cpxy_params()
{
	doca_error_t result;

	struct doca_argp_param 
        *dev_pci_addr_param, *rep_pci_addr_param,
        *server_ip_addr_param;

	/* Comm Channel DOCA device PCI address */
	result = doca_argp_param_create(&dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(dev_pci_addr_param, "p");
	doca_argp_param_set_long_name(dev_pci_addr_param, "pci-addr");
	doca_argp_param_set_description(dev_pci_addr_param, "DOCA Comm Channel device PCI address");
	doca_argp_param_set_callback(dev_pci_addr_param, pci_addr_callback);
	doca_argp_param_set_type(dev_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Comm Channel DOCA device representor PCI address */
	result = doca_argp_param_create(&rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(rep_pci_addr_param, "r");
	doca_argp_param_set_long_name(rep_pci_addr_param, "rep-pci");
	doca_argp_param_set_description(rep_pci_addr_param,
					"DOCA Comm Channel device representor PCI address (needed only on DPU)");
	doca_argp_param_set_callback(rep_pci_addr_param, rep_pci_addr_callback);
	doca_argp_param_set_type(rep_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

    /* Server IP address */
    result = doca_argp_param_create(&server_ip_addr_param);
    if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(server_ip_addr_param, "a");
	doca_argp_param_set_long_name(server_ip_addr_param, "server-addr");
	doca_argp_param_set_description(server_ip_addr_param,
					"Server IP address (needed only on DPU&client)");
	doca_argp_param_set_callback(server_ip_addr_param, server_ip_addr_callback);
	doca_argp_param_set_type(server_ip_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(server_ip_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

void print_cpxy_config(struct cpxy_config *cfg)
{
    printf("-------------COMPRESS-PROXY config----------------\n");
    printf("cfg->server_ip_addr: %s\n", cfg->server_ip_addr);
    printf("cfg->cc_dev_pci_addr: %s\n", cfg->cc_dev_pci_addr);
    printf("cfg->cc_dev_rep_pci_addr: %s\n", cfg->cc_dev_rep_pci_addr);
    printf("-----------------------------\n");

}


int main(int argc, char **argv)
{
	struct cpxy_config cfg;
    struct cpxy_cc_objects cc_objects;
    send_recv_type_t send_recv_type = CLIENT_SERVER_SEND_RECV_DEFAULT;
    char *listen_addr = NULL;
    int result;

    strcpy(cfg.cc_dev_pci_addr, "03:00.1");
	strcpy(cfg.cc_dev_rep_pci_addr, "0c:00.1");
	strcpy(cfg.server_ip_addr, "");

    /* Create a logger backend that prints to the standard output */
	result = (int)doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

    /* Parse cmdline/json arguments */
    result = (int)doca_argp_init("compress_proxy", &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
    }
    DOCA_LOG_INFO("COMPRESS_PROXY pid = %d", getpid());

    result = register_cpxy_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register parameters: %s",
			     doca_error_get_descr(result));
		return EXIT_FAILURE;
    }

    result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse input: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

    /* Set signal handler */
    quit_app = false;
    signal(SIGINT, signal_handler);
    signal(SIGKILL, signal_handler);
    signal(SIGTERM, signal_handler);

    ucp_config_t *ucp_config;
    result = ucp_config_read(NULL, NULL, &ucp_config);
    if (result != UCS_OK) {
        return EXIT_FAILURE;
    }
    // ucp_config_print(ucp_config, stdout, "CONFIG", UCS_CONFIG_PRINT_CONFIG);
    ucp_config_release(ucp_config);

    print_cpxy_config(&cfg);

    /* UCP objects */
    ucp_context_h ucp_context;
    ucp_worker_h  ucp_worker;

    /* Initialize the UCX required objects */
    result = init_ucp_context(&ucp_context, &ucp_worker, send_recv_type);
    if (result != 0) {
        goto err;
    }

    /* Initialize Comm Channel between DPU and HOST */
	result = init_comm_channel_server(
        "compress_proxy_cc", cfg.cc_dev_pci_addr, cfg.cc_dev_rep_pci_addr,
        &cc_objects);
	if (result != DOCA_SUCCESS) {
        goto err;
	}

    /* Client-Server initialization */
    if (strlen(cfg.server_ip_addr) == 0) {
        /* Server side */
        result = run_server(ucp_context, ucp_worker, listen_addr, send_recv_type, &cc_objects);
    } else {
        /* Client side */
        result = run_client(ucp_worker, cfg.server_ip_addr, send_recv_type, &cc_objects);
    }

    /* UCP worker/context cleanup */
    ucp_worker_destroy(ucp_worker);
    ucp_cleanup(ucp_context);

    /* Comm Channel cleanup */
    if (cc_objects.cc_peer_addr != NULL)
		doca_comm_channel_ep_disconnect(cc_objects.cc_ep, cc_objects.cc_peer_addr);
	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(cc_objects.cc_ep);
	/* Destroy Comm Channel DOCA device representor */
	doca_dev_rep_close(cc_objects.cc_dev_rep);
	/* Destroy Comm Channel DOCA device */
	doca_dev_close(cc_objects.cc_dev);

err:
    return result;
}
