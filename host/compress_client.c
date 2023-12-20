#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "compress_client.h"

doca_error_t msg_compression_client(void *dst, size_t dst_capacity)
{
	char *msg_data;
	char received_msg[MAX_MSG_SIZE] = {0};

	uint32_t i, total_msgs;
	char msg[MAX_MSG_SIZE] = {0};
	size_t msg_len;
	char *received_msg = NULL;
	char *received_ptr;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

    // Send total message size

    // Send message payload to compress

    // Receive compressed message (dst buffer)

}

int DPU_compress(void *dst, size_t dst_capacity, const void *src, size_t src_sz)
{
}
