
#ifndef COMPRESS_COMMON_H_
#define COMPRESS_COMMON_H_

#include <doca_log.h>
#include <doca_error.h>
#include <doca_compress.h>

#define SLEEP_IN_NANOS		(10 * 1000)		/* Sample the task every 10 microseconds */
#define NUM_COMPRESS_TASKS	(1)			/* Number of compress tasks */

/* Compress modes */
enum compress_mode {
	COMPRESS_MODE_COMPRESS_DEFLATE,			/* Compress mode */
	COMPRESS_MODE_DECOMPRESS_DEFLATE,		/* Decompress mode */
};

/* Configuration struct */
struct compress_param {
	enum compress_mode mode;			/* Compress task type */
	char pci_address[DOCA_DEVINFO_PCI_ADDR_SIZE];	/* Device PCI address */
	bool output_checksum;				/* To output checksum or not */
};

/* DOCA compress resources */
struct compress_resources {
	struct program_core_objects *state;		/* DOCA program core objects */
	struct doca_compress *compress;			/* DOCA compress context */
	size_t num_remaining_tasks;			/* Number of remaining compress tasks */
	enum compress_mode mode;			/* Compress mode - compress/decompress */
	bool run_main_loop;				/* Controls whether progress loop should be run */
};

/* Describes result of a compress/decompress task */
struct compress_result {
	doca_error_t status;	/**< The completion status */
	uint32_t crc_cs;	/**< The CRC checksum */
	uint32_t adler_cs;	/**< The Adler Checksum */
};


doca_error_t 
compress_deflate(
	void *plain_data, size_t plain_data_len, 
	void **compressed_data, size_t *compressed_data_len, 
	struct compress_param *param);

doca_error_t 
decompress_deflate(
	void *compressed_data, size_t compressed_data_len, 
	void **plain_data, size_t *plain_data_len,
	struct compress_param *param);


doca_error_t 
allocate_compress_resources(const char *pci_addr, uint32_t max_bufs, struct compress_resources *resources);

doca_error_t 
destroy_compress_resources(struct compress_resources *resources);

doca_error_t
submit_compress_deflate_task(struct compress_resources *resources, struct doca_buf *src_buf, struct doca_buf *dst_buf,
				uint64_t *output_checksum);

doca_error_t
submit_decompress_deflate_task(struct compress_resources *resources, struct doca_buf *src_buf, struct doca_buf *dst_buf,
				uint64_t *output_checksum);

doca_error_t
allocate_compress_resources(const char *pci_addr, uint32_t max_bufs, struct compress_resources *resources);

doca_error_t destroy_compress_resources(struct compress_resources *resources);

doca_error_t
compress_task_compress_is_supported(struct doca_devinfo *devinfo);

doca_error_t
compress_task_decompress_is_supported(struct doca_devinfo *devinfo);

void
compress_state_changed_callback(const union doca_data user_data, struct doca_ctx *ctx, enum doca_ctx_states prev_state,
				enum doca_ctx_states next_state);

void
compress_completed_callback(struct doca_compress_task_compress_deflate *compress_task, union doca_data task_user_data,
			    union doca_data ctx_user_data);

void
compress_error_callback(struct doca_compress_task_compress_deflate *compress_task, union doca_data task_user_data,
			union doca_data ctx_user_data);

void
decompress_completed_callback(struct doca_compress_task_decompress_deflate *decompress_task,
			      union doca_data task_user_data, union doca_data ctx_user_data);

void
decompress_error_callback(struct doca_compress_task_decompress_deflate *decompress_task,
			  union doca_data task_user_data, union doca_data ctx_user_data);

#endif /* COMPRESS_COMMON_H_ */