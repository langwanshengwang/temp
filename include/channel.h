/*
 * channel.h —— P0 与 P1 之间唯一的协议信道。
 *
 * 两方协议的每一步都是“同时交换”：双方各自准备好本轮消息，调用
 * channel_exchange()，函数内部并发地发送自己的消息、接收对方的消息。
 * 这样整个协议可以写成两边完全相同的顺序代码，不需要事件驱动状态机，
 * 也不存在“谁先发”的特权角色。
 *
 * 传输层唯一的不对称是 TCP 建连：P0 监听、P1 主动连接。它只决定 socket 由谁 accept，
 * 与协议内容无关（连接建立后双方地位完全相同）。
 */
#ifndef CHANNEL_H
#define CHANNEL_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int fd;
    int self_index;          /* 0 或 1 */
    int timeout_seconds;
    uint64_t seq;            /* 双方同步递增的交换序号，用于检测失步 */
    uint64_t sent_bytes;     /* 含 16 字节帧头 */
    uint64_t recv_bytes;
    uint64_t sent_msgs;
    uint64_t recv_msgs;
    uint64_t rounds;         /* exchange 次数 = 通信轮数 */
} Channel;

/* P0：在本方端口上等待 P1；P1：连接 p0_ip:p0_port，失败则重试直至超时。 */
int channel_open(Channel *ch, int self_index, const char *p0_ip, int p0_port, int timeout_seconds);
/* 用已有 fd 构造信道（单进程自检用 socketpair）。 */
void channel_from_fd(Channel *ch, int fd, int self_index, int timeout_seconds);
void channel_close(Channel *ch);

/*
 * 同时交换一帧：发送 out[0..out_len)，接收对方同 tag 的帧。
 * *in 由 malloc 分配，调用方 free。tag 或序号不一致返回 -1。
 */
int channel_exchange(Channel *ch, uint32_t tag, const uint8_t *out, size_t out_len,
                     uint8_t **in, size_t *in_len);

/* 定长版本：对方长度必须等于 len，否则返回 -1。 */
int channel_exchange_fixed(Channel *ch, uint32_t tag, const uint8_t *out, uint8_t *in, size_t len);

/*
 * 先承诺后打开（两轮）：
 *   轮 1 交换 H = SHA3-256("TPM2-COMMIT-v1" || ctx || index || nonce || msg)
 *   轮 2 交换 nonce || msg，并校验对方承诺。
 * 双方消息长度必须同为 len。用于防止后发言一方看到对方消息后再决定自己的消息。
 */
int channel_commit_open(Channel *ch, uint32_t tag, const uint8_t ctx[32],
                        const uint8_t *msg, uint8_t *peer_msg, size_t len);

#endif
