#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "compress_client.h"

/* DPUに対して圧縮処理をオフロードするためのAPI */ 
// - 圧縮処理をオフロードする．一方，通信処理のオフロードは行わない
// 圧縮処理のステップ（同期関数として実装する）
// - 圧縮処理のリクエストをDPUのデーモンに送信（デーモンは未実装）．ここでターゲットデータも送信
// - DPUでの圧縮リクエストが完了するまでポーリング
// - リクエストが完了した場合，圧縮データをDPU→ホストマシンに送信させる．
// - アプリケーションのバッファに圧縮データを書き込み．
// - 圧縮処理完了

doca_error_t msg_compression_client(void *dst, size_t dst_capacity)
{
	char *msg_data;
	char received_msg[MAX_MSG_SIZE] = {0};

	uint32_t i, total_msgs;
	char msg[MAX_MSG_SIZE] = {0};
	size_t msg_len;
	char *received_msg = NULL;
	char *received_ptr;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

    // Send total message size

    // Send message payload to compress

    // Receive compressed message (dst buffer)

}

int DPU_compress(void *dst, size_t dst_capacity, const void *src, size_t src_sz)
{
}
