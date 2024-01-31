#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mpi.h"

#define MAX_SIZE  4194304+1

int main(int argc, char *argv[])
{
    MPI_Init(&argc, &argv);

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    char *buf;

    if (world_rank == 1) {
        printf("# Size          CompressedSize\n");
    }

    int cmp_size;

    for (int size = 1; size < MAX_SIZE; size *= 2 )
    {
        if (world_rank == 0)
        {
            buf = (char *)malloc(size);
            cmp_size = MPI_Recv(buf, size, MPI_CHAR, 1, 0xaa, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        }
        else if (world_rank == 1)
        {
            buf = (char *)malloc(size);
            memset(buf, 'A', size);
            MPI_Send(buf, size, MPI_CHAR, 0, 0xaa, MPI_COMM_WORLD);
        }
        MPI_Barrier(MPI_COMM_WORLD);
        if (world_rank == 0) {
            printf("%d\t\t%d\n", size, cmp_size);
        }
    }

    MPI_Finalize();
    return 0;
}