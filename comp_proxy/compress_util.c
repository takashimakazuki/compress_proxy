#include <time.h> /* nanosleep */

#include <doca_log.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_compress.h>
#include <doca_error.h>
#include <doca_ctx.h>

#include "common.h"
#include "compress_util.h"

DOCA_LOG_REGISTER(COMPRESS_UTIL);

doca_error_t 
compress_deflate(
	void *plain_data, size_t plain_data_len, 
	void **compressed_data, size_t *compressed_data_len, 
	struct compress_param *param)
{
    struct compress_resources resources = {0};
	struct program_core_objects *state;
	struct doca_buf *src_doca_buf;
	struct doca_buf *dst_doca_buf;
	/* This compression util will use 2 doca buffers */
	uint32_t max_bufs = 2;
	doca_error_t result, tmp_result;
	uint64_t max_buf_size;

	/* Allocate resources */
	resources.mode = COMPRESS_MODE_COMPRESS_DEFLATE;
	result = allocate_compress_resources(param->pci_address, max_bufs, &resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate compress resources: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}
	state = resources.state;

	result = doca_compress_cap_task_decompress_deflate_get_max_buf_size(doca_dev_as_devinfo(state->dev), &max_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query compress max buf size: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}
	if (plain_data_len > max_buf_size) {
		DOCA_LOG_ERR("Invalid data size. Should be smaller than %lu", max_buf_size);
		goto destroy_resources;
	}

	/* Start compress context */
	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}

	*compressed_data = calloc(1, max_buf_size);
	if (*compressed_data == NULL) {
		result = DOCA_ERROR_NO_MEMORY;
		DOCA_LOG_ERR("Failed to allocate memory: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}

	result = doca_mmap_set_memrange(state->dst_mmap, *compressed_data, max_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}
	result = doca_mmap_start(state->dst_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	result = doca_mmap_set_memrange(state->src_mmap, plain_data, plain_data_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	result = doca_mmap_start(state->src_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	/* Construct DOCA buffer for each address range */
	result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap,
						    plain_data, plain_data_len, &src_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	/* Construct DOCA buffer for each address range */
	result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->dst_mmap, *compressed_data,
						    max_buf_size, &dst_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_error_get_descr(result));
		goto destroy_src_buf;
	}

	/* Set data length in doca buffer */
	result = doca_buf_set_data(src_doca_buf, plain_data, plain_data_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_error_get_descr(result));
		goto destroy_dst_buf;
	}


    /* Submit compress task without checksum */
    // TODO
	result = submit_compress_deflate_task(&resources, src_doca_buf, dst_doca_buf, NULL);
	

    /* Compress is done! */
    doca_buf_get_data_len(dst_doca_buf, compressed_data_len);

    DOCA_LOG_INFO("Compression succeeded! (%zuBytes->%zuBytes)", plain_data_len, *compressed_data_len);

    /* Deconstruct compress resources */
destroy_dst_buf:
	tmp_result = doca_buf_dec_refcount(dst_doca_buf, NULL);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to decrease DOCA destination buffer reference count: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_src_buf:
	tmp_result = doca_buf_dec_refcount(src_doca_buf, NULL);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to decrease DOCA source buffer reference count: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_dst_buf:
destroy_resources:
	tmp_result = destroy_compress_resources(&resources);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy compress resources: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

    return result;
}


doca_error_t
submit_compress_deflate_task(struct compress_resources *resources, struct doca_buf *src_buf, struct doca_buf *dst_buf,
				uint64_t *output_checksum)
{
	struct doca_compress_task_compress_deflate *compress_task;
	struct program_core_objects *state = resources->state;
	struct doca_task *task;
	union doca_data task_user_data = {0};
	struct compress_result task_result = {0};
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;

	/* Include result in user data of task to be used in the callbacks */
	task_user_data.ptr = &task_result;
	/* Allocate and construct compress task */
	result = doca_compress_task_compress_deflate_alloc_init(resources->compress, src_buf, dst_buf, task_user_data,
								&compress_task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate compress task: %s", doca_error_get_descr(result));
		return result;
	}

	task = doca_compress_task_compress_deflate_as_task(compress_task);

	/* Submit compress task */
	resources->num_remaining_tasks += 1;
	result = doca_task_submit(task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit compress task: %s", doca_error_get_descr(result));
		doca_task_free(task);
		return result;
	}

	resources->run_main_loop = true;

	/* Wait for all tasks to be completed */
	while (resources->run_main_loop) {
		if (doca_pe_progress(state->pe) == 0)
			nanosleep(&ts, &ts);
	}

	/* Check result of task according to the result we update in the callbacks */
	if (task_result.status != DOCA_SUCCESS)
		return task_result.status;

	return result;
}

doca_error_t
decompress_deflate(
	void *compressed_data, size_t compressed_data_len, 
	void **plain_data, size_t *plain_data_len,
	struct compress_param *param)
{
	struct compress_resources resources = {0};
	struct program_core_objects *state;
	struct doca_buf *src_doca_buf;
	struct doca_buf *dst_doca_buf;
	/* The sample will use 2 doca buffers */
	uint32_t max_bufs = 2;
	doca_error_t result, tmp_result;
	uint64_t max_buf_size;


	/* Allocate resources */
	resources.mode = COMPRESS_MODE_DECOMPRESS_DEFLATE;
	result = allocate_compress_resources(param->pci_address, max_bufs, &resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate compress resources: %s", doca_error_get_descr(result));
		return result;
	}
	state = resources.state;
	result = doca_compress_cap_task_decompress_deflate_get_max_buf_size(doca_dev_as_devinfo(state->dev), &max_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query decompress max buf size: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}
	if (compressed_data_len > max_buf_size) {
		DOCA_LOG_ERR("Invalid data size %zu. Should be smaller then %lu", compressed_data_len, max_buf_size);
		goto destroy_resources;
	}
	/* Start compress context */
	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}

	*plain_data = calloc(1, max_buf_size);
	if (*plain_data == NULL) {
		result = DOCA_ERROR_NO_MEMORY;
		DOCA_LOG_ERR("Destination buffer (for plain data) is not initialized correctly");
		goto destroy_resources;
	}

	result = doca_mmap_set_memrange(state->dst_mmap, *plain_data, max_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}
	result = doca_mmap_start(state->dst_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	result = doca_mmap_set_memrange(state->src_mmap, compressed_data, compressed_data_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	result = doca_mmap_start(state->src_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	/* Construct DOCA buffer for each address range */
	result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap, compressed_data, compressed_data_len, &src_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

	/* Construct DOCA buffer for each address range */
	result = doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->dst_mmap, *plain_data, max_buf_size, &dst_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_error_get_descr(result));
		goto destroy_src_buf;
	}

	/* Set data length in doca buffer */
	result = doca_buf_set_data(src_doca_buf, compressed_data, compressed_data_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set DOCA buffer data: %s", doca_error_get_descr(result));
		goto destroy_dst_buf;
	}

	/* Submit decompress task with checksum according to user configuration */
	result = submit_decompress_deflate_task(&resources, src_doca_buf, dst_doca_buf, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Decompress task failed: %s", doca_error_get_descr(result));
		goto destroy_dst_buf;
	}

	doca_buf_get_data_len(dst_doca_buf, plain_data_len);

destroy_dst_buf:
	tmp_result = doca_buf_dec_refcount(dst_doca_buf, NULL);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to decrease DOCA destination buffer reference count: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_src_buf:
	tmp_result = doca_buf_dec_refcount(src_doca_buf, NULL);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to decrease DOCA source buffer reference count: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_dst_buf:
destroy_resources:
	tmp_result = destroy_compress_resources(&resources);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy compress resources: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	return result;
}


doca_error_t
submit_decompress_deflate_task(struct compress_resources *resources, struct doca_buf *src_buf, struct doca_buf *dst_buf,
				uint64_t *output_checksum)
{
	struct doca_compress_task_decompress_deflate *decompress_task;
	struct program_core_objects *state = resources->state;
	struct doca_task *task;
	union doca_data task_user_data = {0};
	struct compress_result task_result = {0};
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;

	/* Include result in user data of task to be used in the callbacks */
	task_user_data.ptr = &task_result;
	/* Allocate and construct decompress task */
	result = doca_compress_task_decompress_deflate_alloc_init(resources->compress, src_buf, dst_buf, task_user_data,
								&decompress_task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate decompress task: %s", doca_error_get_descr(result));
		return result;
	}

	task = doca_compress_task_decompress_deflate_as_task(decompress_task);

	/* Submit decompress task */
	resources->num_remaining_tasks += 1;
	result = doca_task_submit(task);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit decompress task: %s", doca_error_get_descr(result));
		doca_task_free(task);
		return result;
	}

	resources->run_main_loop = true;

	/* Wait for all tasks to be completed */
	while (resources->run_main_loop) {
		if (doca_pe_progress(state->pe) == 0)
			nanosleep(&ts, &ts);
	}

	/* Check result of task according to the result we update in the callbacks */
	if (task_result.status != DOCA_SUCCESS)
		return task_result.status;

	return result;
}



doca_error_t
allocate_compress_resources(const char *pci_addr, uint32_t max_bufs, struct compress_resources *resources)
{
	struct program_core_objects *state = NULL;
	union doca_data ctx_user_data = {0};
	doca_error_t result, tmp_result;


	resources->state = malloc(sizeof(*resources->state));
	if (resources->state == NULL) {
		result = DOCA_ERROR_NO_MEMORY;
		DOCA_LOG_ERR("Failed to allocate DOCA program core objects: %s", doca_error_get_descr(result));
		return result;
	}
	resources->num_remaining_tasks = 0;

	state = resources->state;

	/* Open DOCA device */
	if (pci_addr != NULL) {
		/* If pci_addr was provided then open using it */
		if (resources->mode == COMPRESS_MODE_COMPRESS_DEFLATE)
			result = open_doca_device_with_pci(pci_addr,
							   &compress_task_compress_is_supported,
							   &state->dev);
		else
			result = open_doca_device_with_pci(pci_addr,
							   &compress_task_decompress_is_supported,
							   &state->dev);
	} else {
		/* If pci_addr was not provided then look for DOCA device */
		if (resources->mode == COMPRESS_MODE_COMPRESS_DEFLATE)
			result = open_doca_device_with_capabilities(&compress_task_compress_is_supported,
								    &state->dev);
		else
			result = open_doca_device_with_capabilities(&compress_task_decompress_is_supported,
								    &state->dev);
	}


	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for DOCA compress: %s", doca_error_get_descr(result));
		goto free_state;
	}

	result = doca_compress_create(state->dev, &resources->compress);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create compress engine: %s", doca_error_get_descr(result));
		goto close_device;
	}

	state->ctx = doca_compress_as_ctx(resources->compress);

	result = create_core_objects(state, max_bufs);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DOCA core objects: %s", doca_error_get_descr(result));
		goto destroy_compress;
	}

	result = doca_pe_connect_ctx(state->pe, state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set progress engine for PE: %s", doca_error_get_descr(result));
		goto destroy_core_objects;
	}

	result = doca_ctx_set_state_changed_cb(state->ctx, compress_state_changed_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set Compress state change callback: %s", doca_error_get_descr(result));
		goto destroy_core_objects;
	}

	if (resources->mode == COMPRESS_MODE_COMPRESS_DEFLATE)
		result = doca_compress_task_compress_deflate_set_conf(resources->compress,
									compress_completed_callback,
									compress_error_callback,
									NUM_COMPRESS_TASKS);
	else
		result = doca_compress_task_decompress_deflate_set_conf(resources->compress,
									decompress_completed_callback,
									decompress_error_callback,
									NUM_COMPRESS_TASKS);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set configurations for compress task: %s", doca_error_get_descr(result));
		goto destroy_core_objects;
	}

	/* Include resources in user data of context to be used in callbacks */
	ctx_user_data.ptr = resources;
	doca_ctx_set_user_data(state->ctx, ctx_user_data);

	return result;

destroy_core_objects:
	tmp_result = destroy_core_objects(state);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA core objects: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_compress:
	tmp_result = doca_compress_destroy(resources->compress);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA compress: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
close_device:
	tmp_result = doca_dev_close(state->dev);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to close device: %s", doca_error_get_descr(tmp_result));
	}

free_state:
	free(resources->state);
	resources->state = NULL;
	return result;
}



doca_error_t destroy_compress_resources(struct compress_resources *resources)
{
	struct program_core_objects *state = resources->state;
	doca_error_t result = DOCA_SUCCESS, tmp_result;

	if (resources->compress != NULL) {
		result = doca_ctx_stop(state->ctx);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Unable to stop context: %s", doca_error_get_descr(result));
		state->ctx = NULL;

		tmp_result = doca_compress_destroy(resources->compress);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy DOCA compress: %s", doca_error_get_descr(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
	}

	if (resources->state != NULL) {
		tmp_result = destroy_core_objects(state);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to destroy DOCA core objects: %s", doca_error_get_descr(tmp_result));
			DOCA_ERROR_PROPAGATE(result, tmp_result);
		}
		free(state);
		resources->state = NULL;
	}

	return result;
}

doca_error_t
compress_task_compress_is_supported(struct doca_devinfo *devinfo)
{
	return doca_compress_cap_task_compress_deflate_is_supported(devinfo);
}

doca_error_t
compress_task_decompress_is_supported(struct doca_devinfo *devinfo)
{
	return doca_compress_cap_task_decompress_deflate_is_supported(devinfo);
}

/**
 * Callback triggered whenever Compress context state changes
 *
 * @user_data [in]: User data associated with the Compress context. Will hold struct compress_resources *
 * @ctx [in]: The Compress context that had a state change
 * @prev_state [in]: Previous context state
 * @next_state [in]: Next context state (context is already in this state when the callback is called)
 */
void
compress_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx, enum doca_ctx_states prev_state,
				enum doca_ctx_states next_state)
{
	(void)ctx;
	(void)prev_state;

	struct compress_resources *resources = (struct compress_resources *)user_data.ptr;

	switch (next_state) {
	case DOCA_CTX_STATE_IDLE:
		DOCA_LOG_INFO("Compress context has been stopped");
		/* We can stop the main loop */
		resources->run_main_loop = false;
		break;
	case DOCA_CTX_STATE_STARTING:
		/**
		 * The context is in starting state, this is unexpected for Compress.
		 */
		DOCA_LOG_ERR("Compress context entered into starting state. Unexpected transition");
		break;
	case DOCA_CTX_STATE_RUNNING:
		DOCA_LOG_INFO("Compress context is running");
		break;
	case DOCA_CTX_STATE_STOPPING:
		/**
		 * The context is in stopping due to failure encountered in one of the tasks, nothing to do at this stage.
		 * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
		 */
		DOCA_LOG_ERR("Compress context entered into stopping state. All inflight tasks will be flushed");
		break;
	default:
		break;
	}
}

void
compress_completed_callback(struct doca_compress_task_compress_deflate *compress_task, union doca_data task_user_data,
			    union doca_data ctx_user_data)
{
	struct compress_resources *resources = (struct compress_resources *)ctx_user_data.ptr;
	struct compress_result *result = (struct compress_result *)task_user_data.ptr;

	DOCA_LOG_INFO("Compress task was done successfully");

	/* Prepare task result */
	result->crc_cs = doca_compress_task_compress_deflate_get_crc_cs(compress_task);
	result->adler_cs = doca_compress_task_compress_deflate_get_adler_cs(compress_task);
	result->status = DOCA_SUCCESS;

	/* Free task */
	doca_task_free(doca_compress_task_compress_deflate_as_task(compress_task));
	/* Decrement number of remaining tasks */
	--resources->num_remaining_tasks;
	/* Stop context once all tasks are completed */
	if (resources->num_remaining_tasks == 0)
		(void)doca_ctx_stop(resources->state->ctx);
}

void
compress_error_callback(struct doca_compress_task_compress_deflate *compress_task, union doca_data task_user_data,
			union doca_data ctx_user_data)
{
	struct compress_resources *resources = (struct compress_resources *)ctx_user_data.ptr;
	struct doca_task *task = doca_compress_task_compress_deflate_as_task(compress_task);
	struct compress_result *result = (struct compress_result *)task_user_data.ptr;

	/* Get the result of the task */
	result->status = doca_task_get_status(task);
	DOCA_LOG_ERR("Compress task failed: %s", doca_error_get_descr(result->status));
	/* Free task */
	doca_task_free(task);
	/* Decrement number of remaining tasks */
	--resources->num_remaining_tasks;
	/* Stop context once all tasks are completed */
	if (resources->num_remaining_tasks == 0)
		(void)doca_ctx_stop(resources->state->ctx);
}

void
decompress_completed_callback(struct doca_compress_task_decompress_deflate *decompress_task,
			      union doca_data task_user_data, union doca_data ctx_user_data)
{
	struct compress_resources *resources = (struct compress_resources *)ctx_user_data.ptr;
	struct compress_result *result = (struct compress_result *)task_user_data.ptr;

	DOCA_LOG_INFO("Decompress task was done successfully");

	/* Prepare task result */
	result->crc_cs = doca_compress_task_decompress_deflate_get_crc_cs(decompress_task);
	result->adler_cs = doca_compress_task_decompress_deflate_get_adler_cs(decompress_task);
	result->status = DOCA_SUCCESS;

	/* Free task */
	doca_task_free(doca_compress_task_decompress_deflate_as_task(decompress_task));
	/* Decrement number of remaining tasks */
	--resources->num_remaining_tasks;
	/* Stop context once all tasks are completed */
	if (resources->num_remaining_tasks == 0)
		(void)doca_ctx_stop(resources->state->ctx);
}

void
decompress_error_callback(struct doca_compress_task_decompress_deflate *decompress_task,
			  union doca_data task_user_data, union doca_data ctx_user_data)
{
	struct compress_resources *resources = (struct compress_resources *)ctx_user_data.ptr;
	struct doca_task *task = doca_compress_task_decompress_deflate_as_task(decompress_task);
	struct compress_result *result = (struct compress_result *)task_user_data.ptr;

	/* Get the result of the task */
	result->status = doca_task_get_status(task);
	DOCA_LOG_ERR("Decompress task failed: %s", doca_error_get_descr(result->status));
	/* Free task */
	doca_task_free(task);
	/* Decrement number of remaining tasks */
	--resources->num_remaining_tasks;
	/* Stop context once all tasks are completed */
	if (resources->num_remaining_tasks == 0)
		(void)doca_ctx_stop(resources->state->ctx);
}
