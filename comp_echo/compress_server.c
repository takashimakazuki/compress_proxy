#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <doca_log.h>
#include <doca_argp.h>

#include <pack.h>
#include <utils.h>
#include <doca_utils.h>

#include "compress_server.h"


// Compression echo server for MPI communication.
// 
DOCA_LOG_REGISTER(MPI_COMPRESSION_ECHO);


/*
 * Populate destination doca buffer for compress jobs
 *
 * @state [in]: application configuration struct
 * @dst_buffer [in]: destination buffer
 * @dst_buf_size [in]: destination buffer size
 * @dst_doca_buf [out]: created doca buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
populate_dst_buf(struct program_core_objects *state, uint8_t **dst_buffer, size_t dst_buf_size, struct doca_buf **dst_doca_buf)
{
	doca_error_t result;

	dst_buffer = calloc(1, dst_buf_size);
	if (dst_buffer == NULL) {
		DOCA_LOG_ERR("Failed to allocate memory");
		return DOCA_ERROR_NO_MEMORY;
	}

	result = doca_mmap_set_memrange(state->dst_mmap, dst_buffer, dst_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memory range destination memory map: %s", doca_get_error_string(result));
		free(dst_buffer);
		return result;
	}

	result = doca_mmap_start(state->dst_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start destination memory map: %s", doca_get_error_string(result));
		free(dst_buffer);
		return result;
	}

	result = doca_buf_inventory_buf_by_addr(state->buf_inv, state->dst_mmap, dst_buffer, dst_buf_size,
						dst_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
			     doca_get_error_string(result));
		return result;
	}
	return result;
}

static doca_error_t
set_endpoint_properties(struct doca_comm_channel_ep_t *ep, struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
    doca_error_t result;

    result = doca_comm_channel_ep_set_device(ep, dev);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set DOCA device property");
        return result;
    }

    result = doca_comm_channel_ep_set_max_msg_size(ep, MAX_MSG_SIZE);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set max_msg_size property");
        return result;
    }

    result = doca_comm_channel_ep_set_send_queue_size(ep, MAX_MSG);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set snd_queue_size property");
        return result;
    }

    result = doca_comm_channel_ep_set_recv_queue_size(ep, MAX_MSG);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set rcv_queue_size property");
        return result;
    }

    result = doca_comm_channel_ep_set_device_rep(ep, dev_rep);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to set DOCA device representor property");
        return result;
    }

    return DOCA_SUCCESS;
}

/**
 * Check if given device is capable of executing a DOCA_DECOMPRESS_DEFLATE_JOB.
 *
 * @devinfo [in]: The DOCA device information
 * @return: DOCA_SUCCESS if the device supports DOCA_DECOMPRESS_DEFLATE_JOB and DOCA_ERROR otherwise.
 */
static doca_error_t
compress_jobs_decompress_is_supported(struct doca_devinfo *devinfo)
{
    return doca_compress_job_get_supported(devinfo, DOCA_DECOMPRESS_DEFLATE_JOB);
}

/*
 * Unmap callback - free doca_buf allocated pointer
 *
 * @addr [in]: Memory range pointer
 * @len [in]: Memory range length
 * @opaque [in]: An opaque pointer passed to iterator
 */
static void
unmap_cb(void *addr, size_t len, void *opaque)
{
    (void)opaque;

    if (addr != NULL)
        munmap(addr, len);
}

/*
 * Submit compress job and retrieve the result
 *
 * @state [in]: application configuration struct
 * @job [in]: job to submit
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
process_job(struct program_core_objects *state, const struct doca_job *job)
{
    struct doca_event event = {0};
    struct timespec ts;
    doca_error_t result;

    /* Enqueue job */
    result = doca_workq_submit(state->workq, job);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to submit doca job: %s", doca_get_error_string(result));
        return result;
    }

    /* Wait for job completion */
    while ((result = doca_workq_progress_retrieve(state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
           DOCA_ERROR_AGAIN)
    {
        /* Wait for the job to complete */
        ts.tv_sec = 0;
        ts.tv_nsec = SLEEP_IN_NANOS;
        nanosleep(&ts, &ts);
    }

    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to retrieve job: %s", doca_get_error_string(result));
    else if (event.result.u64 != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Job finished unsuccessfully");
        result = event.result.u64;
    }
    else
        result = DOCA_SUCCESS;

    return result;
}

static doca_error_t
compress_deflate(struct program_core_objects *state, char *msg_data, size_t msg_size,
                 enum doca_compress_job_types job_type, size_t dst_buf_size, uint8_t **compressed_msg,
                 size_t *compressed_msg_len, uint64_t *output_chksum)
{
    struct doca_buf *dst_doca_buf;
    struct doca_buf *src_doca_buf;
    uint8_t *resp_head;
    doca_error_t result;

    result = doca_mmap_set_memrange(state->src_mmap, msg_data, msg_size);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Unable to set memory range of source memory map: %s", doca_get_error_string(result));
        munmap(msg_data, msg_size);
        return result;
    }
    result = doca_mmap_set_free_cb(state->src_mmap, &unmap_cb, NULL);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Unable to set free callback of source memory map: %s", doca_get_error_string(result));
        munmap(msg_data, msg_size);
        return result;
    }
    result = doca_mmap_start(state->src_mmap);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Unable to start source memory map: %s", doca_get_error_string(result));
        munmap(msg_data, msg_size);
        return result;
    }

    result = doca_buf_inventory_buf_by_addr(state->buf_inv, state->src_mmap, msg_data, msg_size, &src_doca_buf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s", doca_get_error_string(result));
        return result;
    }

    doca_buf_get_data(src_doca_buf, (void **)&resp_head);
    doca_buf_set_data(src_doca_buf, resp_head, msg_size);

    result = populate_dst_buf(state, compressed_msg, dst_buf_size, &dst_doca_buf);
    if (result != DOCA_SUCCESS)
    {
        doca_buf_refcount_rm(src_doca_buf, NULL);
        return result;
    }

    /* Construct compress job */
    const struct doca_compress_deflate_job compress_job = {
        .base = (struct doca_job){
            .type = job_type,
            .flags = DOCA_JOB_FLAGS_NONE,
            .ctx = state->ctx,
        },
        .dst_buff = dst_doca_buf,
        .src_buff = src_doca_buf,
        .output_chksum = output_chksum,
    };

    result = process_job(state, &compress_job.base);
    if (result != DOCA_SUCCESS)
    {
        doca_buf_refcount_rm(dst_doca_buf, NULL);
        doca_buf_refcount_rm(src_doca_buf, NULL);
        return result;
    }

    doca_buf_refcount_rm(src_doca_buf, NULL);

    doca_buf_get_head(dst_doca_buf, (void **)compressed_msg);
    doca_buf_get_data_len(dst_doca_buf, compressed_msg_len);
    doca_buf_refcount_rm(dst_doca_buf, NULL);

    return DOCA_SUCCESS;
}

static doca_error_t msg_compression_server(struct doca_comm_channel_ep_t *ep,
                                           struct doca_comm_channel_addr_t **peer_addr,
                                           struct program_core_objects *state)
{
{
	char received_msg[MAX_MSG_SIZE] = {0};
	uint32_t i, total_msgs;
	size_t msg_len;
	char file_received_msg[] = "OK: Server was done receiving messages";
	char *received_file = NULL;
	char *received_ptr;
	int counter;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;


	/* receive number of total msgs from the client */
	msg_len = MAX_MSG_SIZE;
	counter = 0;
	while ((result = doca_comm_channel_ep_recvfrom(ep, received_msg, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		msg_len = MAX_MSG_SIZE;
		nanosleep(&ts, &ts);
		counter++;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Message was not received: %s", doca_get_error_string(result));
		goto finish_msg;
	}
	if (msg_len != sizeof(uint32_t)) {
		DOCA_LOG_ERR("Received wrong message size, required %ld, got %ld", sizeof(uint32_t), msg_len);
		goto finish_msg;
	}
	total_msgs = ntohl(*(uint32_t *)received_msg);


finish_msg:
	DOCA_DLOG_DBG("Finish Server...");
	return result;
}
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dev_pci_addr_callback(void *param, void *config)
{
	struct msg_compression_config *app_cfg = (struct msg_compression_config *)config;
	char *pci_addr = (char *)param;

	if (strnlen(pci_addr, PCI_ADDR_LEN) == PCI_ADDR_LEN) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", PCI_ADDR_LEN - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	strlcpy(app_cfg->cc_dev_pci_addr, pci_addr, PCI_ADDR_LEN);
	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device representor PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rep_pci_addr_callback(void *param, void *config)
{
	struct msg_compression_config *app_cfg = (struct msg_compression_config *)config;
	const char *rep_pci_addr = (char *)param;

    if (strnlen(rep_pci_addr, PCI_ADDR_LEN) == PCI_ADDR_LEN) {
        DOCA_LOG_ERR("Entered device representor PCI address exceeding the maximum size of %d",
                    PCI_ADDR_LEN - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

    strlcpy(app_cfg->cc_dev_rep_pci_addr, rep_pci_addr, PCI_ADDR_LEN);

	return DOCA_SUCCESS;
}

doca_error_t
register_msg_compression_params()
{
	doca_error_t result;

	struct doca_argp_param *dev_pci_addr_param, *rep_pci_addr_param;

	/* Create and register pci param */
	result = doca_argp_param_create(&dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(dev_pci_addr_param, "p");
	doca_argp_param_set_long_name(dev_pci_addr_param, "pci-addr");
	doca_argp_param_set_description(dev_pci_addr_param, "DOCA Comm Channel device PCI address");
	doca_argp_param_set_callback(dev_pci_addr_param, dev_pci_addr_callback);
	doca_argp_param_set_type(dev_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(dev_pci_addr_param);
	result = doca_argp_register_param(dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register rep PCI address param */
	result = doca_argp_param_create(&rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rep_pci_addr_param, "r");
	doca_argp_param_set_long_name(rep_pci_addr_param, "rep-pci");
	doca_argp_param_set_description(rep_pci_addr_param, "DOCA Comm Channel device representor PCI address");
	doca_argp_param_set_callback(rep_pci_addr_param, rep_pci_addr_callback);
	doca_argp_param_set_type(rep_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}


doca_error_t
msg_compression_init(struct doca_comm_channel_ep_t **ep, struct doca_comm_channel_addr_t **peer_addr,
                     struct msg_compression_config *app_cfg, struct program_core_objects *state,
                     struct doca_compress **compress_ctx)
{
    struct doca_pci_bdf pci_bdf;
    struct doca_dev *cc_doca_dev;
    struct doca_dev_rep *cc_doca_dev_rep = NULL;
    uint32_t workq_depth = 1; /* The app will run 1 compress job at a time */
    uint32_t max_bufs = 2;    /* The app will use 2 doca buffers */
    doca_error_t result;
    struct timespec ts = {
        .tv_nsec = SLEEP_IN_NANOS,
    };

    /* set default timeout */
    if (app_cfg->timeout == 0)
        app_cfg->timeout = DEFAULT_TIMEOUT;

    /* Create Comm Channel endpoint */
    result = doca_comm_channel_ep_create(ep); // 参照：https://docs.nvidia.com/doca/sdk/comm-channel-programming-guide/graphics/establishing-connection.png
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_get_error_string(result));
        return result;
    }

    /* create compress library */
    result = doca_compress_create(compress_ctx);
    if (result != DOCA_SUCCESS)
    {
        doca_comm_channel_ep_destroy(*ep);
        DOCA_LOG_ERR("Failed to init compress library: %s", doca_get_error_string(result));
        return result;
    }

    state->ctx = doca_compress_as_ctx(*compress_ctx);

    result = doca_pci_bdf_from_string(app_cfg->cc_dev_pci_addr, &pci_bdf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Invalid PCI address: %s", doca_get_error_string(result));
        goto compress_destroy;
    }

    /* open DOCA device for CC */
    result = open_doca_device_with_pci(&pci_bdf, NULL, &cc_doca_dev);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open DOCA device: %s", doca_get_error_string(result));
        goto compress_destroy;
    }

    /* open representor device for CC server */
    result = doca_pci_bdf_from_string(app_cfg->cc_dev_rep_pci_addr, &pci_bdf);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Invalid PCI address: %s", doca_get_error_string(result));
        goto dev_close;
    }

    result = open_doca_device_rep_with_pci(cc_doca_dev, DOCA_DEV_REP_FILTER_NET, &pci_bdf, &cc_doca_dev_rep);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open representor device: %s", doca_get_error_string(result));
        goto dev_close;
    }

    /* open device for compress job */
    result = open_doca_device_with_capabilities(&compress_jobs_decompress_is_supported, &state->dev);

    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to open DOCA device for DOCA Compress: %s", doca_get_error_string(result));
        goto rep_dev_close;
    }

    /* Set ep attributes */
    result = set_endpoint_properties(*ep, cc_doca_dev, cc_doca_dev_rep);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init DOCA core objects: %s", doca_get_error_string(result));
        goto rep_dev_close;
    }

    result = init_core_objects(state, workq_depth, max_bufs);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to init DOCA core objects: %s", doca_get_error_string(result));
        goto destroy_core_objs;
    }

    result = doca_comm_channel_ep_listen(*ep, "SERVER");
    if (result != DOCA_SUCCESS)
    {
        doca_dev_rep_close(cc_doca_dev_rep);
        DOCA_LOG_ERR("Comm channel server couldn't start listening: %s", doca_get_error_string(result));
        goto destroy_core_objs;
    }

    DOCA_LOG_INFO("Started Listening, waiting for new connection");

    return DOCA_SUCCESS;

destroy_core_objs:
    destroy_core_objects(state);
rep_dev_close:
    doca_dev_rep_close(cc_doca_dev_rep);
dev_close:
    doca_dev_close(cc_doca_dev);
compress_destroy:
    doca_compress_destroy(*compress_ctx);
    doca_comm_channel_ep_destroy(*ep);
    return result;
}

void msg_compression_cleanup(struct program_core_objects *state, struct msg_compression_config *app_cfg,
                              struct doca_compress *compress_ctx, struct doca_comm_channel_ep_t *ep,
                              struct doca_comm_channel_addr_t **peer_addr)
{
    doca_error_t result;

    result = doca_comm_channel_ep_disconnect(ep, *peer_addr);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to disconnect channel: %s", doca_get_error_string(result));

    result = doca_comm_channel_ep_destroy(ep);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy channel: %s", doca_get_error_string(result));

    result = destroy_core_objects(state);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy core objects: %s", doca_get_error_string(result));

    result = doca_compress_destroy(compress_ctx);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy compress: %s", doca_get_error_string(result));
}

int main(int argc, char **argv)
{
    struct msg_compression_config app_cfg = {0};
    struct doca_comm_channel_ep_t *ep = NULL;
    struct doca_comm_channel_addr_t *peer_addr = NULL;
    struct doca_compress *compress_ctx = NULL;
    struct program_core_objects state = {0};
    doca_error_t result;
	struct doca_logger_backend *stdout_logger = NULL;

    /* Create a logger backend that prints to the standard output */
	result = doca_log_create_file_backend(stdout, &stdout_logger);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;
    
    /* Parse cmdline/json arguments */
	result = doca_argp_init("doca_file_compression", &app_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
		return EXIT_FAILURE;
	}

	result = register_msg_compression_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register application params: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

    result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_get_error_string(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}


    result = msg_compression_init(&ep, &peer_addr, &app_cfg, &state, &compress_ctx);
    if (result != DOCA_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    result = msg_compression_server(ep, &peer_addr, &state);
    if (result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("msg compression encountered errors");
        msg_compression_cleanup(&state, &app_cfg, compress_ctx, ep, &peer_addr);
        return EXIT_FAILURE;
    }

    msg_compression_cleanup(&state, &app_cfg, compress_ctx, ep, &peer_addr);

    return EXIT_SUCCESS;
}