#!/bin/bash

set -x ## Display commands
set -e ## Enable error check


ninja -C build # build shared library


# mpirun  --mca pml ob1 \
# --hostfile machinefile_bf \
# --mca btl tcp,self \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 ./build/test_send

mpirun  --mca pml ob1 \
-x "LD_PRELOAD=../experiment/build/libextern_zstd.so" \
--mca btl tcp,self \
--hostfile machinefile_bf \
--mca btl_tcp_if_include 192.168.200.0/24 \
-np 2 ./build/test_file_send


mpirun  --mca pml ob1 \
-x "LD_PRELOAD=./build/libextern_dpuo.so" \
--mca btl tcp,self \
--hostfile machinefile_bf \
--mca btl_tcp_if_include 192.168.200.0/24 \
-np 2 ./build/test_file_send




# mpirun  --mca pml ob1 \
# -x "LD_PRELOAD=./build/libextern_dpuo.so" \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 ./build/test_sendrecv


# mpirun  --mca pml ob1 \
# -x "LD_PRELOAD=../experiment/build/libextern_zstd.so" \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 ./build/test_sendrecv


# mpirun  --mca pml ob1 \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 ./build/test_sendrecv

# mpirun  --mca pml ob1 \
# -x "LD_PRELOAD=./build/libextern_dpuo.so" \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 /home/k-takashima/ompi/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -x 1 -i 1 -m 1024:67108864


# mpirun  --mca pml ob1 \
# -x "LD_PRELOAD=../experiment/build/libextern_zstd.so" \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 /home/k-takashima/ompi/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -x 10 -i 4 -m 67108864


# mpirun  --mca pml ob1 \
# --mca btl tcp,self \
# --hostfile machinefile_bf \
# --mca btl_tcp_if_include 192.168.200.0/24 \
# -np 2 /home/k-takashima/ompi/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -x 10 -i 4 -m 67108864
