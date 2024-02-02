
#ifndef COMPRESS_PROXY_H_
#define COMPRESS_PROXY_H_

#include <stdbool.h>
#include "compress_util.h"

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


/* Comm Channel config data */
#define USER_PCI_ADDR_LEN 7					/* User PCI address string length */
#define PCI_ADDR_LEN (USER_PCI_ADDR_LEN + 1)			/* PCI address string length */
#define IP_ADDR_LEN 16

struct cpxy_config {
    char cc_dev_pci_addr[PCI_ADDR_LEN];			/* Comm Channel DOCA device PCI address */
	char cc_dev_rep_pci_addr[PCI_ADDR_LEN];			/* Comm Channel DOCA device representor PCI address */
    char server_ip_addr[IP_ADDR_LEN];
    send_recv_type_t send_recv_type;
};

struct cpxy_cc_objects {
    struct doca_comm_channel_ep_t *cc_ep;
    struct doca_comm_channel_addr_t *cc_peer_addr;
    struct doca_dev *cc_dev;
    struct doca_dev_rep *cc_dev_rep;
};

struct cpxy_compress_objects {
    struct compress_param compress_param;
    struct compress_param decompress_param;
};

struct cpxy_compress_message {
    struct header_ {
        bool    is_compressed;
        size_t    data_len;
        size_t    plain_data_len;
    } header;
    void        *data;
};

#endif
