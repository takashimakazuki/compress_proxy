#include <stdio.h>
#include <string.h>
#include "mpi.h"

int main(int argc, char *argv[])
{
    MPI_Init(&argc, &argv);

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    char buf[100];
    if (world_rank == 0)
    {
        memset(buf, 'A', 100);
        printf("Process 0 sent char(len=%ld) to process 1\n %s\n", strlen(buf), buf);
        MPI_Send(&buf, 100, MPI_CHAR, 1, 0, MPI_COMM_WORLD);
    }
    else if (world_rank == 1)
    {
        int cmp_size = MPI_Recv(&buf, 100, MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        printf("Process 1 received char(len=%ld) from process 0, %s\n compressed_data_size=%d\n", strlen(buf), buf, cmp_size);
    }
    MPI_Barrier(MPI_COMM_WORLD);

    MPI_Finalize();
    return 0;
}