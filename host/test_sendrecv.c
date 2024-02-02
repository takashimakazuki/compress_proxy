#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);

    int procs;
    int rank;
    char version[1024];
    int resultlen;
    MPI_Comm_size(MPI_COMM_WORLD, &procs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    if (rank == 0) {
        MPI_Get_library_version(version, &resultlen);
        printf("version: %s\n", version);
    }


    double t_start, t_end;
    int result;

    // 1KB->64MB
    for(int len=1024; len<64*1024*1024; len*=32) { 
        char *src_buf = (char *)calloc(1, len);
        char *dst_buf = (char *)calloc(1, len);
        memset(src_buf, 'A', len);

        if (rank == 0) {
            t_start = MPI_Wtime();
            
            MPI_Send(src_buf, len, MPI_CHAR, 1, 0xbeef, MPI_COMM_WORLD);

            MPI_Recv(dst_buf, len, MPI_CHAR, 1, 0xbeef, MPI_COMM_WORLD, NULL);
            t_end = MPI_Wtime();
        } else {
            MPI_Recv(dst_buf, len, MPI_CHAR, 0, 0xbeef, MPI_COMM_WORLD, NULL);
            MPI_Send(src_buf, len, MPI_CHAR, 0, 0xbeef, MPI_COMM_WORLD);
        }
        MPI_Barrier(MPI_COMM_WORLD);
        if (rank == 0) {
            // printf("==========Barrier==========\n");
            double latency = (t_end - t_start) * 1e6;
            printf("%10d  %f\n", len, latency/2);
        }
    }

    MPI_Finalize();
    return 0;
}