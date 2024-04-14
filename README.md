# 修士論文の提案実装

"DPUを活用したデータ圧縮によるMPIノード間通信データ量の削減"

## Setup

#### DPUのセットアップ
BlueField-2 DPUの設置方法・ソフトウェアインストールは，公式ドキュメントを参照する．
バージョンアップが頻繁に行われるため，各バージョンのインストール方法に従う．

DPUのセットアップ方法の大まかな流れを以下に示す．

- DPUの設置：サーバマシンのPCIeインタフェースにDPUを差し込む作業．
- ケーブルの接続：DPUとL2スイッチを接続する作業．4又のDACケーブル（Direct Attach Cable）があるので，100GbpsのスイッチとDPUを接続するためにこれを使う．物理的な作業としてはDACケーブルをスイッチ側とDPU側にそれぞれ差し込むだけ．
- DPUへのOSインストール：BFBファイル
- HOSTマシンでのソフトウェアのセットアップ：DOCA SDKなど，DPUを用いたプログラムの開発を行うための開発者用ツールをHOSTマシンにインストールする必要がある．
- HOSTマシンからDPUのコンソールにsshログインできることを確認する．


#### 提案実装ソースコードの配置
実験環境では，2台のHOSTマシンと2台のDPUマシン上でソースコードファイルや実行可能ファイルを共有する必要がある．
HOST-DPU間やHOST-HOST間で都度ファイルをコピーするのは手間なので，NFSなどでディレクトリを同期しておくと楽．
HOST1にソースコードの全部を配置しておき，HOST2，DPU1，DPU2にはNFSマウントすることで同期させる．

BlueField-2 DPUのファイルシステムに，HOSTのディレクトリをNFSマウントする方法は以下．


```
# /etc/exports　HOST1のファイル内に以下を追加
/home/k-takashima/compress_proxy 192.168.100.0/30(rw,sync,no_wdelay,no_subtree_check)
```

```bash
DPU$ sudo mount -t nfs 192.168.100.1:/path/to/compress_proxy /home/ubuntu/compress_proxy -o hard,intr
```

## 圧縮通信モジュール (compress_proxy) の実行
提案実装のうち，DPU上で動作する圧縮通信モジュール（compress_proxy）を実行する．

```bash
DPU1$ cd comp_proxy/
DPU1$ meson buildarm # Build settings for ARM64
DPU1$ ninja -C buildarm/
# DPU1で実行する
DPU1$ ./run.sh s

# DPU2上でも実行する
DPU2$ ./run.sh c
```

## 圧縮通信動作テスト用プログラムの実行

提案実装と比較実装による圧縮通信の動作テストを行うプログラム`test_file_send.c`を実行する．

このプログラムは，2台のDPU（DPU1とDPU2）を介して，HOST1-HOST2間での圧縮転送を行う．そのため，上記の`圧縮通信モジュール (compress_proxy) の実行`を事前に行っておく必要がある．

- 提案実装：圧縮通信モジュール（dpuo．ソースコードはhost/extern_dpuo.c）
- 比較実装：zstd圧縮モジュール（zstd．ソースコードはexperiment/extern_zstd.c）


#### OpenMPIのインストール
OpenMPI（ver4.1.6では動作確認済み）のビルド&インストールを行う．
インストール方法はOpenMPIのドキュメントを参照．

公式サイトからソースコードをダウンロードし，ビルド，インストールを行うことを推奨する．UbuntuのリポジトリからOpenMPIをインストールすることもできるが，バージョン指定やビルドオプション指定ができないためあまりお勧めしない．

```bash
# ビルド例
# --without-verbs： InfiniBandなし
# --without-ucx：UCXなし
./autogen.pl \
&& ./configure --prefix=/home/k-takashima/ompi/build --without-verbs --without-ucx \
&& make -j20 \
&& make install
```


#### meson.buildの修正
meson.buildのコンパイル設定を修正する．
OpenMPIのヘッダファイルの場所の指定部分を修正する必要がある．
```
# host/meson.buildより抜粋
inc_dir = include_directories(
    '/opt/mellanox/doca/include',
	'/home/k-takashima/ompi/build/include', # OpenMPIのヘッダファイルの場所を変更
    '../comp_proxy',
    '../comp_proxy/include',
)
```


#### 圧縮通信モジュールとzstd圧縮モジュールのコンパイル
shared object（圧縮通信モジュールextern_dpuo.soとzstd圧縮モジュールextern_zstd.so）のコンパイルを実行する．
```bash
# experiment/ に移動
HOST1$ meson build
HOST1$ ninja -C build

# host/ に移動
HOST1$ meson build
HOST1$ ninja -C build
```

#### 動作テスト
動作テストを行うプログラム`test_file_send.c`の実行．
以下を実行することで，HOST1→DPU1→DPU2→HOST2の流れ（逆方向も）でファイルデータの圧縮転送が行われる．
```bash
HOST1$ ./run.sh
```
