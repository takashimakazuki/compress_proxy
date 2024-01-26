#ifndef COMM_CHANNEL_UTIL_H_
#define COMM_CHANNEL_UTIL_H_

#include <doca_comm_channel.h>
#include <doca_error.h>
#include <stdbool.h>

#define MAX_USER_TXT_SIZE 4000					/* Maximum size of user input text */
#define MAX_TXT_SIZE (MAX_USER_TXT_SIZE + 1)			/* Maximum size of input text */
#define USER_PCI_ADDR_LEN 7					/* User PCI address string length */
#define PCI_ADDR_LEN (USER_PCI_ADDR_LEN + 1)			/* PCI address string length */

#define MAX_DATA_SIZE (1 * 1024 * 1024) /* Comm Channel Max data size 1MBytes */
#define MAX_MSG_SIZE 4000		    
#define CC_MAX_MSG_SIZE 100         /* Comm Channel maximum message size */
#define CC_MAX_QUEUE_SIZE 10		/* Maximum amount of message in queue */


struct mpi_dpuo_config {
	char cc_dev_pci_addr[PCI_ADDR_LEN];		/* Comm Channel DOCA device PCI address */
	char text[MAX_TXT_SIZE];				/* DEBUG: Text to send to Comm Channel server */
	bool is_sender;                         /* DEBUG: sender/receiver */
};

struct mpi_dpuo_cc_objects {
    struct doca_comm_channel_ep_t *cc_ep;
    struct doca_comm_channel_addr_t *cc_peer_addr;
    struct doca_dev *cc_dev;
    struct doca_dev_rep *cc_dev_rep;
};

typedef enum  {
	MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST   = 0,
	MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST		= 1,
    MPI_DPUO_MESSAGE_TYPE_DATA_RESPONSE     = 2, /* DPU->HOST(receiver) */
    MPI_DPUO_MESSAGE_TYPE_ACK_RESPONSE      = 3, /* DPU->HOST(sender) */
} mpi_dpuo_message_type_t;

struct mpi_dpuo_message {
    mpi_dpuo_message_type_t type;
    size_t buffer_len;
    char buffer[MAX_MSG_SIZE]; // if the type is MPI_DPUO_MESSAGE_TYPE_RECEIVE, empty.
};

struct mpi_dpuo_message_v2 {
	mpi_dpuo_message_type_t type;
	size_t buffer_len;
	char buffer[MAX_DATA_SIZE];
};

#define MPI_DPUO_MESSAGE_V2_HDR_LEN  (sizeof(mpi_dpuo_message_type_t) + sizeof(size_t))

char *mpi_dpuo_message_type_string(mpi_dpuo_message_type_t type);

doca_error_t
cc_chunk_data_send(struct doca_comm_channel_ep_t *ep, 
		struct doca_comm_channel_addr_t **peer_addr,
		void *buf, 
		size_t buf_len);

doca_error_t
cc_chunk_data_recv(struct doca_comm_channel_ep_t *ep, 
		struct doca_comm_channel_addr_t **peer_addr,
		void **buf,
		size_t *buf_len);

#endif /* COMM_CHANNEL_UTIL_H_ */