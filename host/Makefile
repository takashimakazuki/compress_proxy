CC=mpicc
INC=/home/k-takashima/dpdk_compression/src/zstd/lib/libzstd.so

extern: extern.c
	$(CC) -shared $^ -o extern.so -lzstd 
extern_dpu: extern_dpu.c
	$(CC) -shared $^ -o extern_dpu.so 

test: test.c
	$(CC) test.c -o test.o

clean:
	rm *.so