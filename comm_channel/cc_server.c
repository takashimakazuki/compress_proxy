
#include <doca_error.h>
#include <doca_argp.h>
#include <doca_log.h>
#include <doca_dev.h>
#include <doca_comm_channel.h>
#include <doca_error.h>

#include <string.h>
#include <stdlib.h> // EXIT_SUCCESS, EXIT_FAILURE
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>

#include "cc_common.h"
#include "common.h"


#define MAX_MSG_SIZE 4080		/* Comm Channel maximum message size */
#define CC_MAX_QUEUE_SIZE 10		/* Maximum amount of message in queue */


DOCA_LOG_REGISTER(CC_SERVER);

static bool end_sample;		/* Shared variable to allow for a proper shutdown */

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		end_sample = true;
	}
}


/*
 * Run DOCA Comm Channel server sample
 *
 * @server_name [in]: Server Name
 * @dev_pci_addr [in]: PCI address for device
 * @rep_pci_addr [in]: PCI address for device representor
 * @text [in]: Server message
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
create_comm_channel_server(const char *server_name, const char *dev_pci_addr, const char *rep_pci_addr, const char *text)
{
	doca_error_t result;
	char rcv_buf[MAX_MSG_SIZE];
	int response_len = strlen(text) + 1;
	size_t msg_len;

	DOCA_LOG_INFO("create_comm_channel_server");

	/* Define Comm Channel endpoint attributes */
	struct doca_comm_channel_ep_t *ep = NULL;
	struct doca_comm_channel_addr_t *peer_addr = NULL;
	struct doca_dev *cc_dev = NULL;
	struct doca_dev_rep *cc_dev_rep = NULL;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Create Comm Channel endpoint */
	result = doca_comm_channel_ep_create(&ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_error_get_descr(result));
		return result;
	}

	/* Open DOCA device according to the given PCI address */
	result = open_doca_device_with_pci(dev_pci_addr, NULL, &cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(ep);
		return result;
	}

	/* Open DOCA device representor according to the given PCI address */
	result = open_doca_device_rep_with_pci(cc_dev, DOCA_DEVINFO_REP_FILTER_NET, rep_pci_addr, &cc_dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
		doca_comm_channel_ep_destroy(ep);
		doca_dev_close(cc_dev);
		return result;
	}

	/* Set all endpoint properties */
	result = doca_comm_channel_ep_set_device(ep, cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set device property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_max_msg_size(ep, MAX_MSG_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_device_rep(ep, cc_dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device representor property");
		goto destroy_cc;
	}

	/* Start listen for new connections */
	result = doca_comm_channel_ep_listen(ep, server_name);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Comm Channel server couldn't start listening: %s", doca_error_get_descr(result));
		goto destroy_cc;
	}

	DOCA_LOG_INFO("Server started Listening, waiting for new connections");

	/* Wait until a message is received */
	msg_len = MAX_MSG_SIZE;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)rcv_buf, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       &peer_addr)) == DOCA_ERROR_AGAIN) {
		if (end_sample) {
			result = DOCA_ERROR_UNEXPECTED;
			break;
		}
		usleep(1);
		msg_len = MAX_MSG_SIZE;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Message was not received: %s", doca_error_get_descr(result));
		goto destroy_cc;
	}

	rcv_buf[MAX_MSG_SIZE - 1] = '\0';
	DOCA_LOG_INFO("Received message: %s", rcv_buf);

	/* Send a response to client */
	while ((result = doca_comm_channel_ep_sendto(ep, text, response_len, DOCA_CC_MSG_FLAG_NONE, peer_addr)) ==
	       DOCA_ERROR_AGAIN) {
		if (end_sample) {
			result = DOCA_ERROR_UNEXPECTED;
			break;
		}
		usleep(1);
	}
	if (result != DOCA_SUCCESS)
		DOCA_LOG_WARN("Response was not sent successfully: %s", doca_error_get_descr(result));

destroy_cc:

	/* Disconnect from current connection */
	if (peer_addr != NULL)
		doca_comm_channel_ep_disconnect(ep, peer_addr);

	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(ep);

	/* Destroy Comm Channel DOCA device representor */
	doca_dev_rep_close(cc_dev_rep);

	/* Destroy Comm Channel DOCA device */
	doca_dev_close(cc_dev);

	return result;
}


int main(int argc, char **argv)
{
    doca_error_t result;
    struct cc_config cfg;
	const char *server_name = "compress_proxy_cc";

	/* Create a logger backend that prints to the standard output */
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}    
    DOCA_LOG_INFO("COMM_CHANNEL started");
	DOCA_LOG_ERR("==========================");
    
	strcpy(cfg.cc_dev_pci_addr, "03:00.0");  // netdev p1
	strcpy(cfg.cc_dev_rep_pci_addr, "0c:00.0"); // netdev representer of ens28f1np1
	strcpy(cfg.text, "MSG_FROM_SERVER");

	/* Parse cmdline/json arguments */
	result = doca_argp_init("comm_channel", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	result = register_cc_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register Comm Channel server sample parameters: %s",
			     doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	/* Start the server*/
	result = create_comm_channel_server(server_name, cfg.cc_dev_pci_addr, cfg.cc_dev_rep_pci_addr, cfg.text);
	if (result != DOCA_SUCCESS) {
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* ARGP cleanup */
	doca_argp_destroy();



    return EXIT_SUCCESS;
}