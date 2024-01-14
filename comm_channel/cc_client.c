/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */


#include <doca_argp.h>
#include <doca_log.h>
#include <doca_dev.h>
#include <doca_comm_channel.h>
#include <doca_error.h>

#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>

#include "cc_common.h"
#include "common.h"


#define MAX_MSG_SIZE 4080		/* Comm Channel maximum message size */
#define CC_MAX_QUEUE_SIZE 10		/* Maximum amount of message in queue */

DOCA_LOG_REGISTER(CC_CLIENT);

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
 * Run DOCA Comm Channel client sample
 *
 * @server_name [in]: Server Name
 * @dev_pci_addr [in]: PCI address for device
 * @text [in]: Client message
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
create_comm_channel_client(const char *server_name, struct dev_pci_addr *dev_pci_addr, const char *text)
{
	doca_error_t result;
	char rcv_buf[MAX_MSG_SIZE];
	int client_msg_len = strlen(text) + 1;
	size_t msg_len;

	/* Define Comm Channel endpoint attributes */
	struct doca_comm_channel_ep_t *ep = NULL;
	struct doca_comm_channel_addr_t *peer_addr = NULL;
	struct doca_dev *cc_dev = NULL;

	/* Signal the while loop to stop */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Create Comm Channel endpoint */
	result = doca_comm_channel_ep_create(&ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel client endpoint: %s", doca_error_get_descr(result));
		return result;
	}

	/* Open DOCA device according to the given PCI address */
	result = open_doca_device_with_pci(dev_pci_addr, NULL, &cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(ep);
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

	/* Connect to server node */
	result = doca_comm_channel_ep_connect(ep, server_name, &peer_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Couldn't establish a connection with the server: %s", doca_error_get_descr(result));
		goto destroy_cc;
	}

	/* Make sure peer address is valid */
	while ((result = doca_comm_channel_peer_addr_update_info(peer_addr)) == DOCA_ERROR_CONNECTION_INPROGRESS) {
		if (end_sample) {
			result = DOCA_ERROR_UNEXPECTED;
			break;
		}
		usleep(1);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to validate the connection with the DPU: %s", doca_error_get_descr(result));
		return result;
	}

	DOCA_LOG_INFO("Connection to server was established successfully");

	/* Send hello message */
	result = doca_comm_channel_ep_sendto(ep, text, client_msg_len, DOCA_CC_MSG_FLAG_NONE, peer_addr);

	while ((result = doca_comm_channel_ep_sendto(ep, text, client_msg_len, DOCA_CC_MSG_FLAG_NONE, peer_addr)) ==
	       DOCA_ERROR_AGAIN) {
		if (end_sample) {
			result = DOCA_ERROR_UNEXPECTED;
			break;
		}
		usleep(1);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Message was not sent: %s", doca_error_get_descr(result));
		goto destroy_cc;
	}

	/* Receive server's response */
	msg_len = MAX_MSG_SIZE;
	result = doca_comm_channel_ep_recvfrom(ep, (void *)rcv_buf, &msg_len, DOCA_CC_MSG_FLAG_NONE, &peer_addr);

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

	DOCA_LOG_INFO("Server response: %s", rcv_buf);

destroy_cc:

	/* Disconnect from current connection */
	if (peer_addr != NULL)
		result = doca_comm_channel_ep_disconnect(ep, peer_addr);

	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(ep);

	/* Destroy Comm Channel DOCA device */
	doca_dev_close(cc_dev);

	return result;
}



/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
	struct cc_config cfg;
	const char *server_name = "cc_sample_server";
	doca_error_t result;

	strcpy(cfg.cc_dev_pci_addr, "0c:00.1");
	strcpy(cfg.text, "MESSAGE_FROM_CLIENT_AAA");
	/* Client, no need for the cc_dev_rep_pci_addr field */

	/* Create a logger backend that prints to the standard output */
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

	/* Parse cmdline/json arguments */
	result = doca_argp_init("doca_cc_client", &cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	result = register_cc_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register Comm Channel client sample parameters: %s",
			     doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	/* Start the client */
	result = create_comm_channel_client(server_name, cfg.cc_dev_pci_addr, cfg.text);
	if (result != DOCA_SUCCESS) {
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* ARGP cleanup */
	doca_argp_destroy();

	return EXIT_SUCCESS;
}
