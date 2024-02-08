#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>
#include <time.h>
#include <sys/stat.h>

#define GET_TIME(_timespec_val) {\
    clock_gettime(CLOCK_MONOTONIC_COARSE, &(_timespec_val));\
}
#define PRINT_TIME(_name, _ts, _te) {\
    double _f = ((double)(_te).tv_sec*1e9 + (_te).tv_nsec) - ((double)(_ts).tv_sec*1e9 + (_ts).tv_nsec);\
    printf("%30s: %15.7fus %10.4fms\n", #_name, _f/1000, _f/1000/1000);\
}

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

void measure_compress_time()
{
    struct timespec ts, te;
    size_t plain_data_len, comp_data_len;
    size_t compressed_size;
    void *plain_data, *comp_data;


    /* Data 'aaaa' 1MB */
    plain_data_len = 1000*1000*6;
    plain_data = malloc(plain_data_len);
    memset(plain_data, 'a', plain_data_len);
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
    GET_TIME(ts);
    comp_data_len = ZSTD_compressBound(plain_data_len);
    comp_data = malloc(comp_data_len);

    compressed_size = ZSTD_compress(comp_data, comp_data_len, plain_data, plain_data_len, 1);
    GET_TIME(te);
    printf("QVAPORf01.bin: size %zu -> %zu\n", plain_data_len, compressed_size);
    PRINT_TIME("compression time", ts, te);

    free(plain_data);
    free(comp_data);

}
