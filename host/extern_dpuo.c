#include "common.h"
#include "mpi_dpuoffload.h"

#include <doca_error.h>
#include <doca_comm_channel.h>
#include <doca_log.h>
#include <doca_dev.h>

#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>


DOCA_LOG_REGISTER(MPI_DPUO_LIB);

struct mpi_dpuo_cc_objects cc_objects;
struct mpi_dpuo_config cfg;


bool quit_app;		/* Shared variable to allow for a proper shutdown */

void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		quit_app = true;
	}
}


doca_error_t
create_comm_channel(const char *server_name, const struct mpi_dpuo_config *dpuo_config, struct mpi_dpuo_cc_objects *cc_objects)
{
	doca_error_t result;

	/* Signal the while loop to stop */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Create Comm Channel endpoint */
	result = doca_comm_channel_ep_create(&cc_objects->cc_ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel client endpoint: %s", doca_error_get_descr(result));
		return result;
	}

	/* Open DOCA device according to the given PCI address */
	result = open_doca_device_with_pci(dpuo_config->cc_dev_pci_addr, NULL, &cc_objects->cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(cc_objects->cc_ep);
		return result;
	}

	/* Set all endpoint properties */
	result = doca_comm_channel_ep_set_device(cc_objects->cc_ep, cc_objects->cc_dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set device property");
		goto destroy_cc;
	}

	result = doca_comm_channel_ep_set_max_msg_size(cc_objects->cc_ep, MAX_MSG_SIZE);
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

	/* Connect to server node */
	result = doca_comm_channel_ep_connect(cc_objects->cc_ep, server_name, &cc_objects->cc_peer_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Couldn't establish a connection with the server: %s", doca_error_get_descr(result));
		goto destroy_cc;
	}

	/* Make sure peer address is valid */
	while ((result = doca_comm_channel_peer_addr_update_info(cc_objects->cc_peer_addr)) == DOCA_ERROR_CONNECTION_INPROGRESS) {
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

	DOCA_LOG_INFO("Connection to CC server was established successfully");	
  return result;

destroy_cc:

	/* Disconnect from current connection */
	if (cc_objects->cc_peer_addr != NULL)
		result = doca_comm_channel_ep_disconnect(cc_objects->cc_ep, cc_objects->cc_peer_addr);

	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(cc_objects->cc_ep);

	/* Destroy Comm Channel DOCA device */
	doca_dev_close(cc_objects->cc_dev);

	return result;
}

doca_error_t start_comm_channel_sendrecv(void* buffer, size_t data_len, bool is_sender, struct mpi_dpuo_config *dpuo_config, struct mpi_dpuo_cc_objects *cc_objects) {
  /* Test Message */
  doca_error_t result;

	if (is_sender) {
		/* Sender */
		struct mpi_dpuo_message msg;

		/* Fill cc message that is sent to DPU */
		memset(&msg, 0, sizeof(struct mpi_dpuo_message));
		msg.type = MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST;
		msg.buffer_len = data_len;
    	memcpy(msg.buffer, buffer, data_len);
		// DOCA_LOG_INFO("Message sent to DPU");
		// DOCA_LOG_INFO("-type: %s", mpi_dpuo_message_type_string(msg.type));
		// DOCA_LOG_INFO("-buffer: %s", msg.buffer);
		// DOCA_LOG_INFO("-buffer_len %zd", msg.buffer_len);


		result = doca_comm_channel_ep_sendto(cc_objects->cc_ep, &msg, (size_t)sizeof(struct mpi_dpuo_message), DOCA_CC_MSG_FLAG_NONE, cc_objects->cc_peer_addr);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Message was not sent: %s", doca_error_get_descr(result));
			return result;
		}
	} else {
		/* Receiver */
		struct mpi_dpuo_message msg;
		struct mpi_dpuo_message recv_msg;
		size_t recv_msg_len = sizeof(struct mpi_dpuo_message);
		memset(&msg, 0, sizeof(msg));
		memset(&recv_msg, 0, sizeof(recv_msg));

		/* Fill cc message that is sent to DPU */
		msg.type = MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST;
		msg.buffer_len = data_len;
		// DOCA_LOG_INFO("Message sent to DPU");
		// DOCA_LOG_INFO("-type: %s", mpi_dpuo_message_type_string(recv_msg.type));
		// DOCA_LOG_INFO("-buffer_len %zd", msg.buffer_len);
		
		result = doca_comm_channel_ep_sendto(cc_objects->cc_ep, &msg, (size_t)sizeof(struct mpi_dpuo_message), DOCA_CC_MSG_FLAG_NONE, cc_objects->cc_peer_addr);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("cc send failed: %s", doca_error_get_descr(result));
			return result;
		}
		
		while ((result = doca_comm_channel_ep_recvfrom(cc_objects->cc_ep, &recv_msg, &recv_msg_len, DOCA_CC_MSG_FLAG_NONE, 
					&cc_objects->cc_peer_addr)) == DOCA_ERROR_AGAIN) {
			if (quit_app) {
				result = DOCA_ERROR_UNEXPECTED;
				break;
			}
			usleep(1);
			recv_msg_len = sizeof(struct mpi_dpuo_message);
		}
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("cc send failed: %s", doca_error_get_descr(result));
			return result;
		}

		// DOCA_LOG_INFO("Message received from DPU");
		// DOCA_LOG_INFO("-type: %s", mpi_dpuo_message_type_string(recv_msg.type));
		// DOCA_LOG_INFO("-buffer: %s", recv_msg.buffer);
		// DOCA_LOG_INFO("-buffer_len: %zd", recv_msg.buffer_len);
		// DOCA_LOG_INFO("-total length: %ld", recv_msg_len);
		if (recv_msg.type == MPI_DPUO_MESSAGE_TYPE_DATA_RESPONSE) {
			memcpy(buffer, recv_msg.buffer, recv_msg.buffer_len);
		}
	}
  return result;
}

void print_cpxy_config(struct mpi_dpuo_config *cfg)
{
    printf("-------------config----------------\n");
    printf("cfg->cc_dev_pci_addr: %s\n", cfg->cc_dev_pci_addr);
    printf("-----------------------------\n");
}



int MPI_Init(int *argc, char ***argv)
{
    static int ret = 0;
    const char *server_name = "compress_proxy_cc";
    doca_error_t result;
	struct doca_log_backend *log_backend;


	ret = PMPI_Init(argc, argv);

    char hostname[1024];
    hostname[1023] = '\0';
    gethostname(hostname, 1023);
    printf("Hostname: %s\n", hostname);
    if (strncmp(hostname, "rdstore", 8) == 0) {
      strcpy(cfg.cc_dev_pci_addr, "0c:00.1");
    } else if (strncmp(hostname, "deepl", 6) == 0) {
      strcpy(cfg.cc_dev_pci_addr, "83:00.1");
    }
  
    print_cpxy_config(&cfg);

    /* Create a logger backend that prints to the standard output */
    result = doca_log_backend_create_with_file(stderr, &log_backend);
    if (result != DOCA_SUCCESS) {
      DOCA_LOG_ERR("Failed to create doca_log backend on rank");
      return -1;
    }

    result = create_comm_channel(server_name, &cfg, &cc_objects);
    if (result != DOCA_SUCCESS) {
      DOCA_LOG_ERR("Failed to create comm channel");
      return -1;
    }
    return ret;
}

int MPI_Finalize() {
  static int ret = 0;
  static doca_error_t result;
  	/* Disconnect from current connection */
	if (cc_objects.cc_peer_addr != NULL)
		result = doca_comm_channel_ep_disconnect(cc_objects.cc_ep, cc_objects.cc_peer_addr);

	/* Destroy Comm Channel endpoint */
	doca_comm_channel_ep_destroy(cc_objects.cc_ep);
	/* Destroy Comm Channel DOCA device */
	doca_dev_close(cc_objects.cc_dev);

  ret = PMPI_Finalize();
  return ret;
}

int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm)
{
  // Send data buffer to compress_proxy(dpu daemon) and wait for completion
  int total_len, dtype_len;
  
  MPI_Type_size(datatype, &dtype_len);
  total_len = dtype_len * count;

  start_comm_channel_sendrecv((void *)buf, total_len, true, &cfg, &cc_objects);
  return 0;
}

int MPI_Recv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Status *status)
{
  // Wait for writeback request from compress_proxy(dpu daemon). 
  // Polling until request is received.
  int total_len, dtype_len;

  MPI_Type_size(datatype, &dtype_len);
  total_len = dtype_len * count;

  start_comm_channel_sendrecv((void *)buf, total_len, false, &cfg, &cc_objects);
  return MPI_SUCCESS;
}