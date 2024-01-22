
#include "common.h"
#include "mpi_dpuoffload.h"

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

DOCA_LOG_REGISTER(MPI_DPUOFFLOAD);

static bool quit_app;		/* Shared variable to allow for a proper shutdown */

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		quit_app = true;
	}
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device PCI address paramet|er
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
pci_addr_callback(void *param, void *config)
{
	struct mpi_dpuo_config *cfg = (struct mpi_dpuo_config *)config;
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
 * ARGP Callback - Handle text to copy parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
text_callback(void *param, void *config)
{
	struct mpi_dpuo_config *conf = (struct mpi_dpuo_config *)config;
	const char *txt = (char *)param;
	int txt_len = strnlen(txt, MAX_TXT_SIZE);

	/* Check using >= to make static code analysis satisfied */
	if (txt_len >= MAX_TXT_SIZE) {
		DOCA_LOG_ERR("Entered text exceeded buffer size of: %d", MAX_USER_TXT_SIZE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* The string will be '\0' terminated due to the strnlen check above */
	strncpy(conf->text, txt, txt_len + 1);

	return DOCA_SUCCESS;
}

static doca_error_t
is_sender_callback(void *param, void *config)
{
	struct mpi_dpuo_config *conf = (struct mpi_dpuo_config *)config;
	conf->is_sender = *(bool *) param ? 1 : 0;
	return DOCA_SUCCESS;
}

doca_error_t
register_mpi_dpuo_params()
{
	doca_error_t result;

	struct doca_argp_param *dev_pci_addr_param, *text_param, *is_sender_param;

	/* Create and register Comm Channel DOCA device PCI address */
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

	/* Create and register text to send param */
	result = doca_argp_param_create(&text_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(text_param, "t");
	doca_argp_param_set_long_name(text_param, "text");
	doca_argp_param_set_description(text_param, "Text to be sent to the other side of channel");
	doca_argp_param_set_callback(text_param, text_callback);
	doca_argp_param_set_type(text_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(text_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	/* Create and register text to send param */
	result = doca_argp_param_create(&is_sender_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(is_sender_param, "s");
	doca_argp_param_set_long_name(is_sender_param, "is-sender");
	doca_argp_param_set_description(is_sender_param, "If this flag set, this process would be sender");
	doca_argp_param_set_callback(is_sender_param, is_sender_callback);
	doca_argp_param_set_type(is_sender_param, DOCA_ARGP_TYPE_BOOLEAN);
	result = doca_argp_register_param(is_sender_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Run DOCA Comm Channel client sample
 *
 * @server_name [in]: Server Name
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
create_comm_channel_start(const char *server_name, const struct mpi_dpuo_config *dpuo_config, struct mpi_dpuo_cc_objects *cc_objects)
{
	doca_error_t result;

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
	result = open_doca_device_with_pci(dpuo_config->cc_dev_pci_addr, NULL, &cc_dev);
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
		if (quit_app) {
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

	/* Test Message */
	char text[25] = "ABCD_EFGH_";
	size_t text_len = strlen(text);

	if (dpuo_config->is_sender) {
		/* Sender */
		struct mpi_dpuo_message msg;

		/* Fill cc message that is sent to DPU */
		memset(&msg, 0, sizeof(struct mpi_dpuo_message));
		msg.type = MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST;
		strncpy(msg.buffer, text, text_len);
		msg.buffer_len = strlen(msg.buffer);
		DOCA_LOG_INFO("Message sent type: %d", msg.type);
		DOCA_LOG_INFO("Message sent buffer: %s", msg.buffer);
		DOCA_LOG_INFO("Message sent bufferlen %zd", msg.buffer_len);
		DOCA_LOG_INFO("\n%s", hex_dump(&msg, sizeof(struct mpi_dpuo_message)));


		result = doca_comm_channel_ep_sendto(ep, &msg, (size_t)sizeof(struct mpi_dpuo_message), DOCA_CC_MSG_FLAG_NONE, peer_addr);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Message was not sent: %s", doca_error_get_descr(result));
			goto destroy_cc;
		}
		DOCA_LOG_INFO("MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST sent");

	} else {
		/* Receiver */
		struct mpi_dpuo_message msg;
		struct mpi_dpuo_message recv_msg;
		size_t recv_msg_len = sizeof(struct mpi_dpuo_message);
		memset(&msg, 0, sizeof(msg));
		memset(&recv_msg, 0, sizeof(recv_msg));

		/* Fill cc message that is sent to DPU */
		msg.type = MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST;
		msg.buffer_len = text_len;
		DOCA_LOG_INFO("Message sent type: %d", msg.type);
		
		result = doca_comm_channel_ep_sendto(ep, &msg, (size_t)sizeof(struct mpi_dpuo_message), DOCA_CC_MSG_FLAG_NONE, peer_addr);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("cc send failed: %s", doca_error_get_descr(result));
			goto destroy_cc;
		}
		DOCA_LOG_INFO("MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST sent: %d", msg.type);
		
		while ((result = doca_comm_channel_ep_recvfrom(ep, &recv_msg, &recv_msg_len, DOCA_CC_MSG_FLAG_NONE, 
					&peer_addr)) == DOCA_ERROR_AGAIN) {
			if (quit_app) {
				result = DOCA_ERROR_UNEXPECTED;
				break;
			}
			usleep(1);
			recv_msg_len = sizeof(struct mpi_dpuo_message);
		}
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("cc send failed: %s", doca_error_get_descr(result));
			goto destroy_cc;
		}

		DOCA_LOG_INFO("Message received type: %d", recv_msg.type);
		DOCA_LOG_INFO("Message received buffer: %s", recv_msg.buffer);
		DOCA_LOG_INFO("Message received buffer_len: %zd", recv_msg.buffer_len);
		DOCA_LOG_INFO("Message received total len: %ld", recv_msg_len);
	}
	

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


int main(int argc, char **argv)
{
	struct mpi_dpuo_cc_objects cc_objects;
	struct mpi_dpuo_config cfg;
	const char *server_name = "compress_proxy_cc";
	doca_error_t result;

	strcpy(cfg.cc_dev_pci_addr, "0c:00.1");
	strcpy(cfg.text, "DATA_FROM_HOST");
	/* no need for the cc_dev_rep_pci_addr field */

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

	result = register_mpi_dpuo_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register MPI-DPUOFFLOAD parameters: %s",
			     doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse input: %s", doca_error_get_descr(result));
		return EXIT_FAILURE;
	}

	/* Start the client */
	result = create_comm_channel_start(server_name, &cfg, &cc_objects);
	if (result != DOCA_SUCCESS) {
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	/* ARGP cleanup */
	doca_argp_destroy();

	return EXIT_SUCCESS;
}