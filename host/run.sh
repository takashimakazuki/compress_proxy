#!/bin/bash

set -x ## Display commands
set -e ## Enable error check

# make
# make test_send
# LD_PRELOAD=./extern.so mpiexec -np 2 -f machinefile_bf /home/k-takashima/build-ch3/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -m 65536:


ninja -C build # build shared library
make test_init # build executable MPI program

mpirun  --mca pml ob1 \
-x "LD_PRELOAD=./build/libextern_dpuo.so" \
--mca btl tcp,self \
--hostfile machinefile_bf \
--mca btl_tcp_if_include 192.168.200.0/24 \
-np 2 ./test_init.o