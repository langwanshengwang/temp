/*
 * channel.c —— 两方 TCP 信道：帧格式 [magic][tag][len][seq] + payload。
 */
#define _GNU_SOURCE
#include "channel.h"

#include "fips202.h"
#include "secure_random.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define FRAME_MAGIC 0x324d5054U   /* "TPM2" */
#define FRAME_HDR 16
#define MAX_FRAME (64U * 1024U * 1024U)

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static void set_socket_options(int fd, int timeout_seconds) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (timeout_seconds > 0) {
        struct timeval tv = { timeout_seconds, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
}

void channel_from_fd(Channel *ch, int fd, int self_index, int timeout_seconds) {
    memset(ch, 0, sizeof(*ch));
    ch->fd = fd;
    ch->self_index = self_index;
    ch->timeout_seconds = timeout_seconds;
    set_socket_options(fd, timeout_seconds);
}

int channel_open(Channel *ch, int self_index, const char *p0_ip, int p0_port, int timeout_seconds) {
    memset(ch, 0, sizeof(*ch));
    ch->fd = -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)p0_port);

    if (self_index == 0) {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) return -1;
        int one = 1;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(lfd, 1) != 0) {
            fprintf(stderr, "[channel] P0 无法监听端口 %d: %s\n", p0_port, strerror(errno));
            close(lfd);
            return -1;
        }
        if (timeout_seconds > 0) {
            struct timeval tv = { timeout_seconds, 0 };
            setsockopt(lfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
        int fd = accept(lfd, NULL, NULL);
        close(lfd);
        if (fd < 0) { fprintf(stderr, "[channel] P0 等待 P1 连接超时\n"); return -1; }
        channel_from_fd(ch, fd, 0, timeout_seconds);
        return 0;
    }

    if (inet_pton(AF_INET, p0_ip, &addr.sin_addr) != 1) return -1;
    time_t deadline = time(NULL) + (timeout_seconds > 0 ? timeout_seconds : 60);
    while (time(NULL) < deadline) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            channel_from_fd(ch, fd, 1, timeout_seconds);
            return 0;
        }
        close(fd);
        usleep(200000);
    }
    fprintf(stderr, "[channel] P1 连接 %s:%d 超时\n", p0_ip, p0_port);
    return -1;
}

void channel_close(Channel *ch) {
    if (ch && ch->fd >= 0) { shutdown(ch->fd, SHUT_RDWR); close(ch->fd); ch->fd = -1; }
}

typedef struct { int fd; const uint8_t *hdr; const uint8_t *payload; size_t len; int rc; } SendJob;

static void *send_thread(void *arg) {
    SendJob *job = (SendJob *)arg;
    job->rc = write_all(job->fd, job->hdr, FRAME_HDR);
    if (job->rc == 0 && job->len) job->rc = write_all(job->fd, job->payload, job->len);
    return NULL;
}

int channel_exchange(Channel *ch, uint32_t tag, const uint8_t *out, size_t out_len,
                     uint8_t **in, size_t *in_len) {
    *in = NULL; *in_len = 0;
    if (!ch || ch->fd < 0 || out_len > MAX_FRAME) return -1;
    uint8_t hdr[FRAME_HDR];
    put32(hdr, FRAME_MAGIC);
    put32(hdr + 4, tag);
    put32(hdr + 8, (uint32_t)out_len);
    put32(hdr + 12, (uint32_t)ch->seq);

    SendJob job = { ch->fd, hdr, out, out_len, -1 };
    pthread_t th;
    if (pthread_create(&th, NULL, send_thread, &job) != 0) return -1;

    uint8_t rhdr[FRAME_HDR];
    int rc = read_all(ch->fd, rhdr, FRAME_HDR);
    uint8_t *buf = NULL;
    uint32_t rlen = 0;
    if (rc == 0) {
        rlen = get32(rhdr + 8);
        if (get32(rhdr) != FRAME_MAGIC || rlen > MAX_FRAME) {
            rc = -1;
        } else if (get32(rhdr + 4) != tag || get32(rhdr + 12) != (uint32_t)ch->seq) {
            fprintf(stderr, "[channel] 协议失步: 期望 tag=0x%08x seq=%llu，收到 tag=0x%08x seq=%u\n",
                    tag, (unsigned long long)ch->seq, get32(rhdr + 4), get32(rhdr + 12));
            rc = -1;
        } else {
            buf = (uint8_t *)malloc(rlen ? rlen : 1);
            if (!buf || (rlen && read_all(ch->fd, buf, rlen) != 0)) rc = -1;
        }
    }
    if (rc != 0) shutdown(ch->fd, SHUT_RDWR);
    pthread_join(th, NULL);
    if (rc != 0 || job.rc != 0) { free(buf); return -1; }
    ch->seq++;
    ch->rounds++;
    ch->sent_msgs++;
    ch->recv_msgs++;
    ch->sent_bytes += FRAME_HDR + out_len;
    ch->recv_bytes += FRAME_HDR + rlen;
    *in = buf;
    *in_len = rlen;
    return 0;
}

int channel_exchange_fixed(Channel *ch, uint32_t tag, const uint8_t *out, uint8_t *in, size_t len) {
    uint8_t *buf = NULL;
    size_t got = 0;
    if (channel_exchange(ch, tag, out, len, &buf, &got) != 0) return -1;
    if (got != len) {
        fprintf(stderr, "[channel] tag=0x%08x 长度不符: 期望 %zu 收到 %zu\n", tag, len, got);
        free(buf);
        return -1;
    }
    if (len) memcpy(in, buf, len);
    free(buf);
    return 0;
}

static void commit_hash(const uint8_t ctx[32], int index, const uint8_t nonce[32],
                        const uint8_t *msg, size_t len, uint8_t out[32]) {
    static const uint8_t domain[] = "TPM2-COMMIT-v1";
    size_t total = sizeof(domain) - 1 + 32 + 1 + 32 + len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) { memset(out, 0, 32); return; }
    size_t off = 0;
    memcpy(buf + off, domain, sizeof(domain) - 1); off += sizeof(domain) - 1;
    memcpy(buf + off, ctx, 32); off += 32;
    buf[off++] = (uint8_t)index;
    memcpy(buf + off, nonce, 32); off += 32;
    if (len) memcpy(buf + off, msg, len);
    sha3_256(out, buf, total);
    free(buf);
}

int channel_commit_open(Channel *ch, uint32_t tag, const uint8_t ctx[32],
                        const uint8_t *msg, uint8_t *peer_msg, size_t len) {
    uint8_t nonce[32], h[32], peer_h[32], expect[32];
    if (secure_random_os_bytes(nonce, sizeof(nonce)) != 0) return -1;
    commit_hash(ctx, ch->self_index, nonce, msg, len, h);
    if (channel_exchange_fixed(ch, tag | 0x100U, h, peer_h, 32) != 0) return -1;

    uint8_t *open = (uint8_t *)malloc(32 + len);
    uint8_t *peer_open = (uint8_t *)malloc(32 + len);
    if (!open || !peer_open) { free(open); free(peer_open); return -1; }
    memcpy(open, nonce, 32);
    if (len) memcpy(open + 32, msg, len);
    int rc = channel_exchange_fixed(ch, tag | 0x200U, open, peer_open, 32 + len);
    if (rc == 0) {
        commit_hash(ctx, 1 - ch->self_index, peer_open, peer_open + 32, len, expect);
        if (memcmp(expect, peer_h, 32) != 0) {
            fprintf(stderr, "[channel] tag=0x%08x 对方打开值与承诺不符，fail-closed\n", tag);
            rc = -1;
        } else if (len) {
            memcpy(peer_msg, peer_open + 32, len);
        }
    }
    secure_bzero(open, 32 + len);
    free(open);
    free(peer_open);
    return rc;
}
