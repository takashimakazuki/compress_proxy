make
make test
LD_PRELOAD=./extern.so mpiexec -np 2 -f machinefile_bf /home/k-takashima/build-ch3/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency -m 65536: