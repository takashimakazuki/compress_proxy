CC=mpicc
INC=/home/k-takashima/dpdk_compression/src/zstd/lib/libzstd.so

extern: extern.c
	$(CC) -shared $^ -o extern.so -lzstd 
extern_dpu: extern_dpu.c
	$(CC) -shared $^ -o extern_dpu.so 

test_init: test_init.c
	$(CC) test_init.c -o test_init.o

test_send: test_send.c
	$(CC) test_send.c -o test_send.o


clean:
	rm *.so