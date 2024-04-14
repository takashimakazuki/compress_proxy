# Compress Proxyコード

本ディレクトリには，修士論文の提案実装のうち，DPU上で動作するサーバプログラム（compress_proxyと呼ぶ）のソースコードを配置している．

compress_proxyは，DPU上でサーバプログラムとして動作する．２台のDPU間（作者の実験環境ではrdstore-bfとdeepl-bf）でのデータ送受信，HOST-DPU間のデータ送受信，データの圧縮，展開処理を行う．

以下で，主要なファイル，ディレクトリの内容を説明する．

- compress_proxy.c：compress_proxyのエントリポイントを含むファイル．
- meson.build：compress_proxyのコンパイル設定．その他テスト用プログラムのコンパイル設定も含まれる．
- run.sh：compress_proxyの実行スクリプト．
- include/：共通コードのヘッダファイルを配置している．このディレクトリに入っていないヘッダファイルもあるが，特に理由はない．
- mpi_dpuoffload.c：提案実装には関係ない．
- proxy_proxy.c：提案実装には関係ない．

## compress_proxy実行方法

1台目のDPU(rdstore-bf)でcompress_proxy実行
```bash
# mesonでのコンパイル設定
DPU1(rdstore-bf)$ meson buildarm
# コンパイル実行．実行可能ファイル`buildarm/compress_proxy`が生成される．
DPU1(rdstore-bf)$ ninja -C buildarm/
# compress_proxy実行
DPU1(rdstore-bf)$ ./run.sh s
```

1台目のDPU(deepl-bf)でcompress_proxy実行．（NFS等で2つのDPUのディレクトリを同期している前提）
```bash
DPU2(deepl-bf)$ ./run.sh c
```