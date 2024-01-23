# make
# make test_send
# LD_PRELOAD=./extern.so mpiexec -np 2 -f machinefile_bf /home/k-takashima/build-ch3/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -m 65536:


ninja -C build # build shared library
make test_init # build executable MPI program
LD_PRELOAD=./build/libextern_dpuo.so mpiexec -np 1 ./test_init.o
