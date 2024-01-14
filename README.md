


## TODO
- 圧縮オフロードあり通信オフロードなしver
    - host/compress_client.c：DPUの圧縮処理の呼び出しを行うコードを追加する
    - comp_server/compress_server.c：HOSTからの圧縮リクエストを受け付けるサーバとして実装する
- 通信＋圧縮オフロードver
    - HOSTプロセスが利用するインタフェースを作成する．（LD_PRELOADライブラリとして作成）
    - comp_proxy/compress_proxy.c：HOSTからの圧縮リクエストを受信＆圧縮処理を実行＆宛先DPUプロセスに対してデータを送信


## Setup

```
# /etc/exports
/home/k-takashima/dpdk_compression 192.168.100.0/30(rw,sync,no_wdelay,no_subtree_check)
```

```
$ sudo mount -t nfs 192.168.100.1:/path/to/compress_proxy /home/ubuntu/compress_proxy -o hard,intr
```

## Run

```
dpu$ cd comp_proxy && ./run.sh
```