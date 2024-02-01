#include <mpi.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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


    int len = 1*1024*1024; // 1MB
    char src_buf[len+1];
    char dst_buf[len+1];
    
    memset(src_buf, 'A', len);
    src_buf[len] = '\0';

    double t_start, t_end;

    for(int iter=0; iter<1; iter++) {
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
            printf("==========Barrier==========\n");
            printf("Iter%d finished\n", iter);
            double latency = (t_end - t_start) * 1e6;
            printf("ping-pong latency/ latency: %f us / %f us\n", latency, latency/2);
            printf("ping-pong latency/ latency: %f ms / %f ms\n", latency/1000, latency/1000/2);
        }
    }

    MPI_Finalize();
    return 0;
}