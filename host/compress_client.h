#ifndef COMPRESS_CLIENT_H_
#define COMPRESS_CLIENT_H_


#include <doca_comm_channel.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_compress.h>

#include "../include/compress_mpi.h"

doca_error_t msg_compression_client(
	struct doca_comm_channel_ep_t *ep,
	struct doca_comm_channel_addr_t **peer_addr,
	struct msg_compression_config *app_cfg,
	struct program_core_objects *state);

int DPU_compress(void *dst, size_t dst_capacity, const void *src, size_t src_sz);

#endif /* COMPRESS_CLIENT_H_ */
