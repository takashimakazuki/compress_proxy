#include "mpi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zstd.h" 


int compression(char *dst, int dst_sz, const char *src, int src_sz)
{
  int c_payload_sz;
  int *sz_hdr_ptr;

  // Compression
  c_payload_sz = ZSTD_compress(dst + sizeof(int), dst_sz, src, src_sz, 1);

  // Add header data
  sz_hdr_ptr = (int *)dst;
  *sz_hdr_ptr = c_payload_sz;

  // Total size = header size(integer) + compressed payload size
  return sizeof(int) + c_payload_sz;
}

int decompression(char *dst, int dst_sz, const char *src, int src_sz)
{
  int size, c_payload_sz;
  int *sz_hdr_ptr;

  // check compressed payload size
  sz_hdr_ptr = (int *)src;
  c_payload_sz = *sz_hdr_ptr;

  // Decompression
  size = ZSTD_decompress(dst, dst_sz, &src[sizeof(int)], c_payload_sz);

  // Payload size
  return size;
}

int MPI_Send(const void *buf, int count, MPI_Datatype datatype, int dest, int tag, MPI_Comm comm)
{
  int total_len, len, data_c, vSend_len;
  char *vSend;
  MPI_Type_size(datatype, &len);

  total_len = len * count;
  vSend_len = (total_len + 5000) * sizeof(char); // 解凍後のバッファを余分にとる．5000は適当
  vSend = (char *)malloc(vSend_len);
  data_c = compression(vSend, vSend_len, (const char *)buf, total_len);
  // printf("[extern.c]compressed data: %d\n", data_c);

  PMPI_Send(vSend, data_c, MPI_CHAR, dest, tag, comm);
  free(vSend);
  return 0;
}

int MPI_Recv(void *buf, int count, MPI_Datatype datatype, int source, int tag, MPI_Comm comm, MPI_Status *status)
{
  int bytes, total_bytes, vSend_len, len_payload;
  char *vSend;


  MPI_Type_size(datatype, &bytes);
  total_bytes = bytes * count;
  vSend_len = (total_bytes + 5000) * sizeof(char); // 受信バッファを余分にとる．5000は適当
  vSend = (char *)malloc(vSend_len);
  PMPI_Recv(vSend, vSend_len, MPI_CHAR, source, tag, comm, status);
  // MPI_Get_count(status, MPI_CHAR, &len_payload);
  // printf("[extern.c]received data: %d\n", len_payload);

  decompression(buf, total_bytes, (const char *)vSend, vSend_len);

  return 0;
}