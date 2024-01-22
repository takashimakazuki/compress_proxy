
#ifndef MPI_DPUOFFLOAD_H_
#define MPI_DPUOFFLOAD_H_

#include <doca_error.h>
#include <stdbool.h>

#define MAX_USER_TXT_SIZE 128					/* Maximum size of user input text */
#define MAX_TXT_SIZE (MAX_USER_TXT_SIZE + 1)			/* Maximum size of input text */
#define USER_PCI_ADDR_LEN 7					/* User PCI address string length */
#define PCI_ADDR_LEN (USER_PCI_ADDR_LEN + 1)			/* PCI address string length */

#define MAX_MSG_SIZE 200		/* Comm Channel maximum message size */
#define CC_MAX_QUEUE_SIZE 10		/* Maximum amount of message in queue */


struct mpi_dpuo_config {
	char cc_dev_pci_addr[PCI_ADDR_LEN];			/* Comm Channel DOCA device PCI address */
	char text[MAX_TXT_SIZE];				/* Text to send to Comm Channel server */
	bool is_sender;
};

doca_error_t register_mpi_dpuo_params(void);

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

char *mpi_dpuo_message_type_string(mpi_dpuo_message_type_t type) {
    switch (type) {
    case MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST:
        return "MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST";
    case MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST:
        return "MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST";
    case MPI_DPUO_MESSAGE_TYPE_DATA_RESPONSE:
        return "MPI_DPUO_MESSAGE_TYPE_DATA_RESPONSE";
    case MPI_DPUO_MESSAGE_TYPE_ACK_RESPONSE:
        return "MPI_DPUO_MESSAGE_TYPE_ACK_RESPONSE";
    default:
        return "Unknown mpi_dpuo_message_type_t";
    }

}

#endif /* MPI_DPUOFFLOAD_H_ */
