


## Setup

ホストマシン上に本gitリポジトリをクローンし，BlueField-2 DPUのファイルシステムにNFSマウントする方法で開発環境をセットアップする．


```
# /etc/exports　ホストマシンのファイル内に以下を追加
/home/k-takashima/compress_proxy 192.168.100.0/30(rw,sync,no_wdelay,no_subtree_check)
```

```bash
host$ git clone git@github.com:takashimakazuki/compress_proxy.git
host$ sudo mount -t nfs 192.168.100.1:/path/to/compress_proxy /home/ubuntu/compress_proxy -o hard,intr
```

## Run dpu module

```bash
dpu$ cd comp_proxy
dpu$ meson buildarm # Build settings for ARM64
dpu$ ninja -C buildarm/
dpu$ ./run.sh s
# dpu2$ ./run.sh c
```

## Run PMPI library
```bash
host$ cd host
host$ ./run.sh
```


```
cd host
mpirun  --mca pml ob1 \
-x "LD_PRELOAD=./build/libextern_dpuo.so" \
--mca btl tcp,self \
--hostfile machinefile_bf \
--mca btl_tcp_if_include 192.168.200.0/24 \
-np 2 /home/k-takashima/ompi/osu-micro-benchmarks-7.2/c/mpi/pt2pt/standard/osu_latency
```