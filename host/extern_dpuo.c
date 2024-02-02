#include "common.h"
#include "comm_channel_util.h"

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
FILE *log_file;

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

	result = doca_comm_channel_ep_set_max_msg_size(cc_objects->cc_ep, sizeof(struct mpi_dpuo_message));
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

/*
* Comm Channel user defined packet format
* |data type | data length|
* |----------+------------|
* |        data           |
* 
*/
doca_error_t start_comm_channel_sendrecv(void *buffer, size_t data_len, bool is_sender, struct mpi_dpuo_config *dpuo_config, struct mpi_dpuo_cc_objects *cc_objects) {
	doca_error_t result;

	if (is_sender) {
		/* Sender */
		struct mpi_dpuo_message_v2 *msg;

		/* Fill cc message that is sent to DPU */
#ifdef DEBUG_TIMER_ENABLED
		struct timespec ts, te;
		GET_TIME(ts); // "Allocate Compress resource: ": time 2090.812000 us
#endif

		msg = (struct mpi_dpuo_message_v2 *)calloc(1, sizeof(struct mpi_dpuo_message_v2));
		msg->type = MPI_DPUO_MESSAGE_TYPE_SEND_REQUEST;
		msg->buffer_len = data_len;
		memcpy(msg->buffer, buffer, data_len);
		DOCA_LOG_INFO("Sender: Message sent to DPU");
		DOCA_LOG_INFO("-type: %s", mpi_dpuo_message_type_string(msg->type));
		DOCA_LOG_INFO("-buffer_len %zd", msg->buffer_len);

		result = cc_chunk_data_send(cc_objects->cc_ep, &cc_objects->cc_peer_addr, msg, msg->buffer_len+MPI_DPUO_MESSAGE_V2_HDR_LEN);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to send data chunks through CC");
			return result;
		}
		#ifdef DEBUG_TIMER_ENABLED
			GET_TIME(te);
			PRINT_TIME("Sender: cc_chunk_data_send", ts, te);
		#endif

	} else {
		/* Receiver */
		#ifdef DEBUG_TIMER_ENABLED
			struct timespec ts, te;
			GET_TIME(ts); 
		#endif


		struct mpi_dpuo_message_v2 *msg;
		struct mpi_dpuo_message_v2 *recv_msg;
		size_t recv_msg_len = MPI_DPUO_MESSAGE_V2_HDR_LEN + data_len;
		msg = (struct mpi_dpuo_message_v2 *)calloc(1, sizeof(struct mpi_dpuo_message_v2));

		/* Fill cc message that is sent to DPU */
		msg->type = MPI_DPUO_MESSAGE_TYPE_RECEIVE_REQUEST;
		msg->buffer_len = data_len;
		DOCA_LOG_INFO("Receiver: CC_Send Message sent to DPU");
		DOCA_LOG_INFO("-type: %s", mpi_dpuo_message_type_string(msg->type));
		DOCA_LOG_INFO("-buffer_len %zd", msg->buffer_len);

		result = cc_chunk_data_send(cc_objects->cc_ep, &cc_objects->cc_peer_addr, msg, MPI_DPUO_MESSAGE_V2_HDR_LEN);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to send data chunks through CC");
			return result;
		}
		DOCA_LOG_INFO("Receiver: CC_Send finished");
		
		#ifdef DEBUG_TIMER_ENABLED
			GET_TIME(te);
			PRINT_TIME("Receiver: cc_chunk_data_send", ts, te);
		#endif

		
#ifdef DEBUG_TIMER_ENABLED
		GET_TIME(ts);
#endif
		DOCA_LOG_INFO("Receiver: CC_Recv waiting for data from DPU");
		/* Waiting for message from DPU daemon(compress_proxy)*/
		result = cc_chunk_data_recv(cc_objects->cc_ep, &cc_objects->cc_peer_addr, (void **)(&recv_msg), &recv_msg_len);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to receive data chunks through CC");
		}

		DOCA_LOG_INFO("Receiver: Message received from DPU");
		DOCA_LOG_INFO("-type: %s", mpi_dpuo_message_type_string(recv_msg->type));
		// DOCA_LOG_INFO("-buffer: %s", recv_msg->buffer);
		DOCA_LOG_INFO("-buffer_len: %zd", recv_msg->buffer_len);
		DOCA_LOG_INFO("-total length: %ld", recv_msg_len);
		if (recv_msg->type == MPI_DPUO_MESSAGE_TYPE_DATA_RESPONSE) {
			memcpy(buffer, recv_msg->buffer, recv_msg->buffer_len);
		}
#ifdef DEBUG_TIMER_ENABLED
		GET_TIME(te);
		PRINT_TIME("Receiver: cc_chunk_data_recv", ts, te);
#endif
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
	// struct doca_log_backend *log_backend;
	// char filename[40] = "";
	// sprintf(filename, "dpu_log_%s", hostname);
	// log_file = fopen(filename, "w");
	// result = doca_log_backend_create_with_file(log_file, &log_backend);
    // if (result != DOCA_SUCCESS) {
    //   DOCA_LOG_ERR("Failed to create doca_log backend");
    //   return -1;
    // }

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

	if (result != DOCA_SUCCESS) {
		return result;
	}

	// fclose(log_file);
	ret = PMPI_Finalize();
	return ret;
}

int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm)
{
  // Send data buffer to compress_proxy(dpu daemon) and wait for completion
  doca_error_t result;
  int total_len, dtype_len;
  
  MPI_Type_size(datatype, &dtype_len);
  total_len = dtype_len * count;

  result = start_comm_channel_sendrecv((void *)buf, total_len, true, &cfg, &cc_objects);
  return result;
}

int MPI_Recv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Status *status)
{
  // Wait for writeback request from compress_proxy(dpu daemon). 
  // Polling until request is received.
  doca_error_t result;
  int total_len, dtype_len;

  MPI_Type_size(datatype, &dtype_len);
  total_len = dtype_len * count;

  result = start_comm_channel_sendrecv((void *)buf, total_len, false, &cfg, &cc_objects);
  return result;
}