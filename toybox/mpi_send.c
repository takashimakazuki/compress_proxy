#include <mpi.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);

    int procs;
    int rank;
    MPI_Comm_size(MPI_COMM_WORLD, &procs);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);

    int length = 100;
    char src_buf[length];
    char dst_buf[length];

    if (rank == 0) {
        memset(src_buf, 'A', length);
        MPI_Send(src_buf, length, MPI_CHAR, 1, 0xbeef, MPI_COMM_WORLD);
    } else {
        MPI_Recv(dst_buf, length, MPI_CHAR, 0, 0xbeef, MPI_COMM_WORLD, NULL);
    }

    MPI_Finalize();
    return 0;
}