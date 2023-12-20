#ifndef COMPRESS_MPI_H_
#define COMPRESS_MPI_H_

#define MAX_MSG_SIZE 4080			/* Max comm channel message size */
#define PCI_ADDR_LEN 8				/* PCI address string length */

#define MAX_MSG 512               /* Maximum number of messages in CC queue */
#define SLEEP_IN_NANOS (1 * 1000) /* Sample the job every 10 microseconds */
#define DEFAULT_TIMEOUT 10        /* default timeout for receiving messages */


/* File compression configuration struct */
struct msg_compression_config {
	char cc_dev_pci_addr[PCI_ADDR_LEN];  			/* Comm Channel DOCA device PCI address */
	char cc_dev_rep_pci_addr[PCI_ADDR_LEN];			/* Comm Channel DOCA device representor PCI address */;
	int timeout;						/* Application timeout in seconds */
};

#endif /* COMPRESS_MPI_H_ */