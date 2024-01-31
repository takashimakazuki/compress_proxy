#include "mpi.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>

#define CHECK(cond, ...)                        \
    do {                                        \
        if (!(cond)) {                          \
            fprintf(stderr,                     \
                    "%s:%d CHECK(%s) failed: ", \
                    __FILE__,                   \
                    __LINE__,                   \
                    #cond);                     \
            fprintf(stderr, "" __VA_ARGS__);    \
            fprintf(stderr, "\n");              \
            exit(1);                            \
        }                                       \
    } while (0)

#define CHECK_ZSTD(fn)                                           \
    do {                                                         \
        size_t const err = (fn);                                 \
        CHECK(!ZSTD_isError(err), "%s", ZSTD_getErrorName(err)); \
    } while (0)


#define MAX_ZSTD_HEAER_LEN 22

int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm)
{
    int dtype_len;
    size_t src_total_len; 
  
    MPI_Type_size(datatype, &dtype_len);
    src_total_len = (size_t)dtype_len * count;


    size_t  c_buff_size = ZSTD_compressBound(src_total_len);
    void* c_buff = malloc(c_buff_size);


    size_t c_size = ZSTD_compress(c_buff, c_buff_size, buf, src_total_len, 1);

    return PMPI_Send(c_buff, c_size, MPI_CHAR, dest, tag, comm);
}

int MPI_Recv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Status *status)
{
    int dtype_len;
    int result = MPI_SUCCESS;
    void *recv_buf;
    size_t recv_buf_len;

    // 圧縮後のデータサイズが元のデータサイズより大きくなる場合を考慮して，MAX_ZSTD_HEAER_LENのバッファ余分に確保する
    MPI_Type_size(datatype, &dtype_len);
    recv_buf_len = (size_t)dtype_len * count + MAX_ZSTD_HEAER_LEN;

    recv_buf = calloc(recv_buf_len, 1);
    
    result = PMPI_Recv(recv_buf, recv_buf_len, MPI_CHAR, source, tag, comm, status);
    if (result != MPI_SUCCESS) {
        fprintf(stderr, "PMPI_Recv Failed\n");
        free(recv_buf);
        return result;
    }

    unsigned long long decompressed_size = ZSTD_getFrameContentSize(recv_buf, recv_buf_len);
    CHECK(decompressed_size != ZSTD_CONTENTSIZE_ERROR, "compress_mpi_recv: not compressed by zstd!");
    CHECK(decompressed_size != ZSTD_CONTENTSIZE_UNKNOWN, "compress_mpi_recv: original size unknown!");

    size_t compressed_size = ZSTD_findFrameCompressedSize(recv_buf, recv_buf_len);

    size_t d_size = ZSTD_decompress(buf, decompressed_size, recv_buf, compressed_size);
    CHECK_ZSTD(d_size);
    CHECK(d_size == decompressed_size, "Impossible because zstd will check this condition!");

    free(recv_buf);


    return (int)compressed_size;
}
