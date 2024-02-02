#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "mpi.h"

int main(int argc, char *argv[])
{
    MPI_Init(&argc, &argv);

    int rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    double t_start, t_end;
    FILE *file;
    int fd;
    struct stat sb;

    // file = fopen("novel-corona-virus-2019-dataset.csv", "r");
    file = fopen("QVAPORf01.bin", "r");
    
    if (file < 0) {
        printf("Error failed to open file\n");
        return 1;
    }
    fd = fileno(file);
    fstat(fd, &sb);

    char *buf = malloc(sb.st_size);
    int size = fread(buf, 1, sb.st_size, file);
    if (size < 0) {
        printf("Error failed to read file\n");
        return 1;
    }


    if (rank == 0)
    {
        t_start = MPI_Wtime();
        MPI_Send(buf, size, MPI_CHAR, 1, 0, MPI_COMM_WORLD);
        MPI_Recv(buf, size, MPI_CHAR, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        t_end = MPI_Wtime();
    }
    else if (rank == 1)
    {
        MPI_Recv(buf, size, MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        MPI_Send(buf, size, MPI_CHAR, 0, 0, MPI_COMM_WORLD);
    }
    MPI_Barrier(MPI_COMM_WORLD);
    if (rank == 0) {
        double latency = (t_end - t_start) * 1e6;
        printf("%dB  %f\n", size, latency/2);
    }

    fclose(file);
    MPI_Finalize();
    return 0;
}