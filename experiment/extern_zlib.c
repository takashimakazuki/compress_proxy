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


int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm)
{
    int dtype_len;
    size_t src_total_len; 
  
    MPI_Type_size(datatype, &dtype_len);
    src_total_len = (size_t)dtype_len * count;



    return PMPI_Send(c_buff, c_size, MPI_CHAR, dest, tag, comm);
}

int MPI_Recv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Status *status)
{
    int dtype_len;
    int result = MPI_SUCCESS;
    void *recv_buf;
    size_t recv_buf_len;

    MPI_Type_size(datatype, &dtype_len);
    recv_buf_len = (size_t)dtype_len * count + MAX_ZSTD_HEAER_LEN;

    recv_buf = calloc(recv_buf_len, 1);
    
    result = PMPI_Recv(recv_buf, recv_buf_len, MPI_CHAR, source, tag, comm, status);
    if (result != MPI_SUCCESS) {
        fprintf(stderr, "PMPI_Recv Failed\n");
        free(recv_buf);
        return result;
    }


    free(recv_buf);


    return (int)compressed_size;
}
