#ifndef COMPRESS_SERVER_H_
#define COMPRESS_SERVER_H_

#include <doca_comm_channel.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_compress.h>

#include "../include/compress_mpi.h"
#include "common.h"


static doca_error_t compress_deflate(
    struct program_core_objects *state, 
    char *msg_data, size_t msg_size,
    enum doca_compress_job_types job_type, 
    size_t dst_buf_size, 
    uint8_t **compressed_msg,
    size_t *compressed_msg_len, uint64_t *output_chksum);

static doca_error_t recv_msg_from_host();
static doca_error_t send_msg_to_host();


doca_error_t msg_compression_client(void *dst, size_t dst_capacity);

#endif /* COMPRESS_SERVER_H_ */
