#!/bin/bash

set -x ## Display commands
set -e ## Enable error check


# if [ $# -eq 0 ]; then
#     echo "No arguments provided. [c/s]"
#     exit 1
# fi

env CC=/home/k-takashima/ompi/build/bin/mpicc ninja -C build 

# mpirun  --mca pml ob1 \
# -x "LD_PRELOAD=./build/libextern_zstd.so" \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 /home/k-takashima/ompi/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -c


mpirun  --mca pml ob1 \
-x "LD_PRELOAD=./build/libextern_zstd.so" \
--mca btl tcp,self \
--hostfile machinefile_bf \
--mca btl_tcp_if_include 192.168.200.0/24 \
-np 2 ./build/test_send_nbytes