#include <inttypes.h> /* PRIu32 */
#include <time.h> /* nanosleep */
#include <arpa/inet.h>

#include <doca_log.h>
#include <doca_error.h>

#include "utils.h"
#include "common.h"
#include "comm_channel_util.h"

#define SLEEP_IN_NANOS (1 * 1000)		/* Sample the job every 10 microseconds */

#define CHECK_ERR(...) \
if (result != DOCA_SUCCESS) {\
	DOCA_LOG_ERR(__VA_ARGS__);\
	return result;\
}\

DOCA_LOG_REGISTER(COMM_CHANNEL_UTIL);

extern bool quit_app;

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

/*
 * Send the input data with comm channel to a remote peer
 *
 * @ep [in]: handle for comm channel local endpoint
 * @peer_addr [in]: destination address handle of the send operation
 * @buf [in]: data to the source buffer
 * @buf_len [in]: data size
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
cc_chunk_data_send(struct doca_comm_channel_ep_t *ep, 
		struct doca_comm_channel_addr_t **peer_addr,
		void *buf, 
		size_t buf_len)
{
	uint32_t total_chunks;
	uint32_t total_chunks_network_order;
	size_t chunk_len;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Send the number of chunks  */
	total_chunks = (buf_len + CC_MAX_MSG_SIZE - 1) / CC_MAX_MSG_SIZE;
    total_chunks_network_order = htonl(total_chunks);

    DOCA_LOG_INFO("CC_Send total_chunks start.");
	DOCA_LOG_DBG("CC_Send total_chunks: %"PRIu32"", total_chunks);
	DOCA_LOG_DBG("CC_Send total_chunks: ↓\n%s", hex_dump(&total_chunks, sizeof(uint32_t)));
	DOCA_LOG_DBG("CC_Send total_chunks_network_order: ↓\n%s", hex_dump(&total_chunks_network_order, sizeof(uint32_t)));

	while ((result = doca_comm_channel_ep_sendto(ep, (void *)&total_chunks_network_order, sizeof(uint32_t), DOCA_CC_MSG_FLAG_NONE,
						     *peer_addr)) == DOCA_ERROR_AGAIN) {
        nanosleep(&ts, &ts);
    }
    /* This error is happened on Receiver DPU */
	CHECK_ERR("Message was not sent: %s", doca_error_get_descr(result))

	/* Send data to the remote peer */
    DOCA_LOG_DBG("Start sending chunks to host through CC");
	for (uint32_t i = 0; i < total_chunks; i++) {
    	DOCA_LOG_DBG("chunk sending: %"PRIu32"/%"PRIu32"", i, total_chunks);
		chunk_len = MIN(buf_len, CC_MAX_MSG_SIZE);
		while ((result = doca_comm_channel_ep_sendto(ep, buf, chunk_len, DOCA_CC_MSG_FLAG_NONE, 
                                *peer_addr)) == DOCA_ERROR_AGAIN) {
			nanosleep(&ts, &ts);
        }
		CHECK_ERR("Message was not sent: %s", doca_error_get_descr(result))

    	DOCA_LOG_DBG("chunk sent: %"PRIu32"/%"PRIu32"", i, total_chunks);
		buf += chunk_len;
		buf_len -= chunk_len;
	}
	return DOCA_SUCCESS;
}

/*
 * Receive file data with comm channel from a remote peer
 *
 * @ep [in]: handle for comm channel local endpoint
 * @peer_addr [in]: destination address handle of the send operation
 * @buf [out]: pointer to received file data. "Buffer is allocated in this function"
 * @buf_len [out]: received data length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */

doca_error_t
cc_chunk_data_recv(struct doca_comm_channel_ep_t *ep, 
		struct doca_comm_channel_addr_t **peer_addr,
		void **buf,
		size_t *buf_len)
{
	doca_error_t result;
	uint32_t total_chunks;
	uint32_t total_chunks_msg;
	size_t total_chunks_msg_len;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	int timeout_num_of_iterations = (1 * 1000 * 1000) / (SLEEP_IN_NANOS / 1000);
	int counter;
	void *buf_ptr;
	size_t chunk_len;


	// Receive total number of chunks (total_chunks) from a remote peer
	counter = 0;
	total_chunks_msg_len = sizeof(uint32_t);
    DOCA_LOG_INFO("CC_Recv total_chunks start.");
	while((result = doca_comm_channel_ep_recvfrom(ep, &total_chunks_msg, &total_chunks_msg_len, DOCA_CC_MSG_FLAG_NONE,
							peer_addr) == DOCA_ERROR_AGAIN)) {
		if (quit_app) return DOCA_ERROR_UNEXPECTED;
		total_chunks_msg_len = sizeof(uint32_t);
		nanosleep(&ts, &ts);
		if ((counter++) == timeout_num_of_iterations) {
			DOCA_LOG_ERR("total_chunks message was not received at the given timeout");
			return result;
		}
	}
	CHECK_ERR("total_chunks message was not received: %s", doca_error_get_descr(result))
	if (total_chunks_msg_len != sizeof(uint32_t)) {
			DOCA_LOG_ERR("Received wrong message size, required %ld, got %ld", sizeof(uint32_t), total_chunks_msg_len);
			return DOCA_ERROR_UNEXPECTED;
	}

	// Allocate buffer for receiving data
	total_chunks = ntohl(total_chunks_msg);
	DOCA_LOG_DBG("total_chunks=%"PRIu32"", total_chunks);
	DOCA_LOG_DBG("total_chunks_msg_len=%ld(4byte is OK uint32)", total_chunks_msg_len);

	*buf_len = MIN(total_chunks * CC_MAX_MSG_SIZE, MAX_DATA_SIZE);
    DOCA_LOG_DBG("buf_len calcucation succeeded buf_len=%zd", *buf_len);
	
    *buf = calloc(*buf_len, sizeof(char));
	if (buf == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory");
		return DOCA_ERROR_NO_MEMORY;
	}
    DOCA_LOG_DBG("calloc msg succeeded");

	// Receive data (buf) from a remote peer
	buf_ptr = *buf;
	char chunk[CC_MAX_MSG_SIZE] = {0};
	for(uint32_t i=0; i < total_chunks; i++) {
		memset(chunk, 0, sizeof(chunk));
		counter = 0;
		chunk_len = CC_MAX_MSG_SIZE;
		while((result = doca_comm_channel_ep_recvfrom(ep, chunk, &chunk_len, DOCA_CC_MSG_FLAG_NONE,
							peer_addr) == DOCA_ERROR_AGAIN)) {
			if (quit_app) return DOCA_ERROR_UNEXPECTED;
			chunk_len = CC_MAX_MSG_SIZE;
			nanosleep(&ts, &ts);
			counter++;
			if (counter == timeout_num_of_iterations) {
				DOCA_LOG_ERR("Message was not received at the given timeout");
				return result;
			}
		}
		CHECK_ERR("Message was not received: %s", doca_error_get_descr(result))
        
        DOCA_LOG_DBG("chunk%"PRIu32" received %.*s", i, (int)chunk_len, chunk);

		if (buf_ptr - *buf + CC_MAX_MSG_SIZE > MAX_DATA_SIZE) {
			DOCA_LOG_ERR("Received data exceeded maximum size");
			return DOCA_ERROR_UNEXPECTED;
		}
		memcpy(buf_ptr, chunk, chunk_len);
		buf_ptr += chunk_len;
	}

	return DOCA_SUCCESS;
}
