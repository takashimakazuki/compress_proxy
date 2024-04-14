# DPU-Oコード

本ディレクトリには，修士論文の提案実装のうち，HOST上で動作するクライアントプログラム（dpuoと呼ぶ．dpu-offloadingの略）のソースコードを配置している．


- extern_dpuo.c：HOST上で動作するDPU連携モジュール．shared objectとしてコンパイルする．
- test_file_send.c：2つのプロセス間でファイルの送受信を行うMPIプログラム．動作テスト・実験での実行時間計測のために使用する．