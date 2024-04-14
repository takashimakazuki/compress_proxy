# Communication Channel 動作確認用コード

本ディレクトリ内のファイルには，DOCA Communication Channelの動作確認用のソースコードが配置される．
HOST→DPUのデータ転送と，DPU→HOSTのデータ転送の実装をテストするためのソースコード群であるため，修士論文での実験とは無関係．

以下に，主要なファイルの何用について説明する．

- cc_client.c：HOST上で動作するコード．HOST→DPUにテストデータを送信するプログラム
- cc_server.c：DPU上で動作するコード．cc_client.cプログラムから送信されたテストデータを受信し，その後DPU→HOSTにデータを送信して返す．
- meson.build：cc_client.cとcc_server.cのコンパイル設定．
  - cc_client.cはX86_64アーキテクチャでコンパイル
  - cc_server.cはARMアーキテクチャでコンパイル
- Makefile：使っていない．
- DOCA_cross.sh：HOST上でcc_server.cをクロスコンパイルしたいために作成したが，使用していない．

## 実行方法

DPU側でのコンパイル＆実行
```bash
# mesonでのコンパイル設定
DPU$ meson buildarm
# コンパイル実行．実行可能ファイル`buildarm/cc_server`が生成される．
DPU$ ninja -C buildarm/
# cc_server実行
DPU$ ./run.sh s
```

HOST側でのコンパイル＆実行
```bash
# mesonでのコンパイル設定
HOST$ meson build
# コンパイル実行．実行可能ファイル`build/cc_client`が生成される．
HOST$ ninja -C build/
# cc_client実行
HOST$ ./run.sh c
```
