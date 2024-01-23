#include <mpi.h>
#include <stdio.h>
#include <doca_error.h>

int MPI_Init(int *argc, char ***argv)
{
    static int init_count = 0;
    static int ret = 0;
    init_count++;

    printf("\n---MPI_Init (OVERLOADED)---\n");
    printf("MPI_Init: mpi_init entrance count %d...\n", init_count);
    ret = PMPI_Init(argc, argv);
    printf("+++MPI_Init (OVERLOADED) done!+++\n\n");

    return ret;
}

int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm)
{
  // Send data buffer to compress_proxy(dpu daemon) and wait for completion

  

  return 0;
}

int MPI_Recv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Status *status)
{
  // Wait for writeback request from compress_proxy(dpu daemon). 
  // Polling until request is received.


  return 0;
}