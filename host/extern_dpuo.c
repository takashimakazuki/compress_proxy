#include "mpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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