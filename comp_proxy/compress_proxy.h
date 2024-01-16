
#ifndef COMPRESS_PROXY_H_
#define COMPRESS_PROXY_H_

typedef enum {
    CLIENT_SERVER_SEND_RECV_STREAM  = UCS_BIT(0),
    CLIENT_SERVER_SEND_RECV_TAG     = UCS_BIT(1),
    CLIENT_SERVER_SEND_RECV_AM      = UCS_BIT(2),
    CLIENT_SERVER_SEND_RECV_DEFAULT = CLIENT_SERVER_SEND_RECV_STREAM
} send_recv_type_t;

char *cpxy_sendrecv_type_string(send_recv_type_t type) {
        switch (type) {
        case CLIENT_SERVER_SEND_RECV_STREAM:
            return "RECV_STREAM";
        case CLIENT_SERVER_SEND_RECV_TAG:
            return "RECV_TAG";
        case CLIENT_SERVER_SEND_RECV_AM:
            return "RECV_AM";
        default:
            return "Unknown send_recv_type";
    }

}

/**
 * Server's application context to be used in the user's connection request
 * callback.
 * It holds the server's listener and the handle to an incoming connection request.
 */
typedef struct ucx_server_ctx {
    volatile ucp_conn_request_h conn_request;
    ucp_listener_h              listener;
} ucx_server_ctx_t;


/**
 * Stream request context. Holds a value to indicate whether or not the
 * request is completed.
 */
typedef struct test_req {
    int complete;
} test_req_t;


/**
 * Descriptor of the data received with AM API.
 */
static struct {
    volatile int complete;
    int          is_rndv;
    void         *desc;
    void         *recv_buf;
} am_data_desc = {0, 0, NULL, NULL};

#endif