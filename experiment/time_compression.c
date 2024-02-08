#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <zstd.h>

#include <doca_log.h>
#include <doca_error.h>

#include "compress_util.h"
#include "common.h"


DOCA_LOG_REGISTER(TIME_DEFLATE_ENGINE);

size_t get_data_from_file(const char *filename, void **buf)
{
    FILE *fp;
    struct stat sb;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open file\n");
        return -1;
    }
    int fd = fileno(fp);
    fstat(fd, &sb);

    *buf = malloc(sb.st_size);
    size_t size = fread(*buf, 1, sb.st_size, fp);
    if (size < 0) {
        fprintf(stderr, "Failed to read file\n");
        return -1;
    }

    fclose(fp);

    return size;
}

int zstd_time()
{
    struct timespec ts, te;
    size_t plain_data_len, comp_data_len;
    size_t compressed_size;
    void *plain_data, *comp_data;

    printf("================== Zstandard =======================\n");

    /* Data 'aaaa' 1MB */
    plain_data_len = 1000*1000*1;
    plain_data = malloc(plain_data_len);
    memset(plain_data, 'a', plain_data_len);
    printf("=========================================\n");
    GET_TIME(ts);
    comp_data_len = ZSTD_compressBound(plain_data_len);
    comp_data = malloc(comp_data_len);

    compressed_size = ZSTD_compress(comp_data, comp_data_len, plain_data, plain_data_len, 1);
    GET_TIME(te);
    printf("Data 'aaaa..1MB': size %zu -> %zu\n", plain_data_len, compressed_size);
    PRINT_TIME("compression time", ts, te);

    free(plain_data);
    free(comp_data);

    /* Data novel-corona-virus */
    plain_data_len = get_data_from_file("../host/novel-corona-virus-2019-dataset.csv", &plain_data);
    printf("=========================================\n");
    GET_TIME(ts);
    comp_data_len = ZSTD_compressBound(plain_data_len);
    comp_data = malloc(comp_data_len);

    compressed_size = ZSTD_compress(comp_data, comp_data_len, plain_data, plain_data_len, 1);
    GET_TIME(te);
    printf("novel-corona-virus-2019-dataset.csv: size %zu -> %zu\n", plain_data_len, compressed_size);
    PRINT_TIME("compression time", ts, te);

    free(plain_data);
    free(comp_data);

    /* Data QVAPOR */
    plain_data_len = get_data_from_file("../host/QVAPORf01.bin", &plain_data);
    printf("=========================================\n");
    GET_TIME(ts);
    comp_data_len = ZSTD_compressBound(plain_data_len);
    comp_data = malloc(comp_data_len);

    compressed_size = ZSTD_compress(comp_data, comp_data_len, plain_data, plain_data_len, 1);
    GET_TIME(te);
    printf("QVAPORf01.bin: size %zu -> %zu\n", plain_data_len, compressed_size);
    PRINT_TIME("compression time", ts, te);

    free(plain_data);
    free(comp_data);

    return 0;
}

int compress_engine_time()
{
    doca_error_t result;
    void *plain_data;
    size_t plain_data_len;
    void *compressed_data; // This ptr is initialized in compress_deflate
    struct timespec ts, te;
    size_t compressed_data_len;

    printf("================== Compress engine =======================\n");

    // Parameters
    struct compress_param comp_param;
    comp_param.mode = COMPRESS_MODE_COMPRESS_DEFLATE;
    strncpy(comp_param.pci_address, "03:00.1", DOCA_DEVINFO_PCI_ADDR_SIZE);



    /* Data 'aaaa 1MB */
    plain_data_len = 1000*1000;
    plain_data = malloc(plain_data_len);
    memset(plain_data, 'a', plain_data_len);

    printf("=========================================\n");
    GET_TIME(ts);
    result = compress_deflate(
        plain_data, plain_data_len,
        &compressed_data, &compressed_data_len, &comp_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Compress failed: %s", doca_error_get_descr(result));
        return -1;
    }
    GET_TIME(te);
    printf("aaa...: size %zu -> %zu\n", plain_data_len, compressed_data_len);

    PRINT_TIME("Compress time", ts, te);

    free(plain_data);
    free(compressed_data);

    /* Data novel-corona-virus */
    plain_data_len = get_data_from_file("../host/novel-corona-virus-2019-dataset.csv", &plain_data);
    printf("=========================================\n");
    GET_TIME(ts);
    result = compress_deflate(
        plain_data, plain_data_len,
        &compressed_data, &compressed_data_len, &comp_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Compress failed: %s", doca_error_get_descr(result));
        return -1;
    }
    
    GET_TIME(te);
    printf("novel-corona-virus-2019-dataset.csv: size %zu -> %zu\n", plain_data_len, compressed_data_len);
    PRINT_TIME("compression time", ts, te);

    free(plain_data);
    free(compressed_data);


    /* Data QVAPOR */
    plain_data_len = get_data_from_file("../host/QVAPORf01.bin", &plain_data);
    printf("=========================================\n");
    GET_TIME(ts);
    result = compress_deflate(
        plain_data, plain_data_len,
        &compressed_data, &compressed_data_len, &comp_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Compress failed: %s", doca_error_get_descr(result));
        return -1;
    }
    
    GET_TIME(te);
    printf("QVAPORf01.bin: size %zu -> %zu\n", plain_data_len, compressed_data_len);
    PRINT_TIME("compression time", ts, te);

    free(plain_data);
    free(compressed_data);

    return 0;
}

int main(int argc, char** argv)
{
    zstd_time();
    compress_engine_time();

    return 0;
}