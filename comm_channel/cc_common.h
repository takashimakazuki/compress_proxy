
#ifndef CC_COMMON_H_
#define CC_COMMON_H_

#define MAX_USER_TXT_SIZE 128					/* Maximum size of user input text */
#define MAX_TXT_SIZE (MAX_USER_TXT_SIZE + 1)			/* Maximum size of input text */
#define USER_PCI_ADDR_LEN 7					/* User PCI address string length */
#define PCI_ADDR_LEN (USER_PCI_ADDR_LEN + 1)			/* PCI address string length */

struct cc_config {
	char cc_dev_pci_addr[PCI_ADDR_LEN];			/* Comm Channel DOCA device PCI address */
	char cc_dev_rep_pci_addr[PCI_ADDR_LEN];			/* Comm Channel DOCA device representor PCI address */
	char text[MAX_TXT_SIZE];				/* Text to send to Comm Channel server */
};

/*
 * Register the command line parameters for the DOCA CC samples
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t register_cc_params(void);

#endif /* CC_COMMON_H_ */
