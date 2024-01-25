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


    char src_buf[8+1];
    char dst_buf[8+1];
    for(int iter=0; iter<10; iter++) {
        MPI_Barrier(MPI_COMM_WORLD);
        if (rank == 0) {
            strcpy(src_buf, "TEST_RK0\0");
            MPI_Send(src_buf, 8, MPI_CHAR, 1, 0xbeef, MPI_COMM_WORLD);
            printf("Iter%d, rank%d Send finished '%.8s'\n", iter, rank, src_buf);

            // MPI_Recv(dst_buf, 8, MPI_CHAR, 1, 0xbee, MPI_COMM_WORLD, NULL);
            // printf("rank%d Receive finished %s\n", rank, dst_buf);
        } else {
            strcpy(src_buf, "TEST_RK1\0");
            MPI_Recv(dst_buf, 8, MPI_CHAR, 0, 0xbeef, MPI_COMM_WORLD, NULL);
            printf("Iter%d, rank%d Receive finished '%.8s'\n", iter, rank, dst_buf);

            // MPI_Send(src_buf, 8, MPI_CHAR, 0, 0xbee, MPI_COMM_WORLD);
        }
    }

    MPI_Finalize();
    return 0;
}