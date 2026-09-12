/*
 * main.c —— 节点入口。
 *
 * 用法：
 *   node <config.conf>                          以配置中的 self_index 运行一方
 *   node <config.conf> --message "..."          直接给出待签消息
 *   node <config.conf> --message-file <path>   从文件读取待签消息（scripts/gen_message.py 生成）
 *   node <config.conf> --out-dir <dir>          输出 public_key.bin/signature.bin/summary.json
 *   node selftest [--mldsa-mode-check] [...]    单进程双线程自检（使用 mock DFSS 替身）
 *   node verify <pk.bin> <sig.bin> <msg.txt>    用标准 ML-DSA 接口离线验证
 *
 * 两方运行的是同一个二进制、同一份代码；唯一区别是配置里的 self_index。
 * 参数集由 dispatch/node_dispatch.c 在运行时选择（--mldsa-mode 或配置中的 mldsa_mode）。
 */
#include "mldsa_compat.h"
#include "party.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MESSAGE "threshold-mldsa-2of2-demo-message"

int selftest_main(int argc, char **argv);   /* selftest.c */

static void usage(const char *prog) {
    fprintf(stderr,
            "用法:\n"
            "  %s <config.conf> [--message <text> | --message-file <path>] [--out-dir <dir>]\n"
            "  %s selftest [--batch K] [--pool L] [--pool-mode fixed|refill] [--fault-inject]\n"
            "  %s verify <public_key.bin> <signature.bin> <message.txt>\n",
            prog, prog, prog);
}

static long read_file(const char *path, unsigned char *buf, size_t cap) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    size_t n = fread(buf, 1, cap, fp);
    int extra = fgetc(fp) != EOF;
    fclose(fp);
    return extra ? -1 : (long)n;
}

static int verify_main(int argc, char **argv) {
    if (argc != 5) { usage(argv[0]); return 2; }
    unsigned char pk[MLDSA_PUBLICKEY_BYTES], sig[MLDSA_SIGNATURE_BYTES];
    char msg[MAX_MESSAGE_BYTES + 1];
    memset(msg, 0, sizeof(msg));
    if (read_file(argv[2], pk, sizeof(pk)) != (long)sizeof(pk)) {
        fprintf(stderr, "公钥长度必须是 %d 字节\n", MLDSA_PUBLICKEY_BYTES); return 1;
    }
    if (read_file(argv[3], sig, sizeof(sig)) != (long)sizeof(sig)) {
        fprintf(stderr, "签名长度必须是 %d 字节\n", MLDSA_SIGNATURE_BYTES); return 1;
    }
    long mn = read_file(argv[4], (unsigned char *)msg, MAX_MESSAGE_BYTES);
    if (mn < 0) { fprintf(stderr, "无法读取消息文件\n"); return 1; }
    msg[mn] = '\0';
    int ok = mldsa44_verify(pk, msg, sig);
    printf("[verify] %s 标准验证结果: %s\n", MLDSA_LEVEL_NAME, ok ? "ACCEPT" : "REJECT");
    return ok ? 0 : 1;
}

/* 不再是进程入口：构建时被重命名为 node_main_<mode>，由 dispatch/node_dispatch.c 在运行时
 * 按参数集调用。同一个 node 二进制因此同时包含 ML-DSA-44/65/87。 */
int node_mode_main(int argc, char **argv);

int node_mode_main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 2; }
    if (strcmp(argv[1], "selftest") == 0) return selftest_main(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return verify_main(argc, argv);

    const char *conf = argv[1];
    const char *message = DEFAULT_MESSAGE;
    const char *out_dir = "";
    static char msg_buf[MAX_MESSAGE_BYTES];
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) message = argv[++i];
        else if (strcmp(argv[i], "--message-file") == 0 && i + 1 < argc) {
            /* 推荐路径：消息由 scripts/gen_message.py 事先落盘，节点只读那一份字节，
             * 日志里因此留下的是“真正被签名的内容”，两方也能核对是同一个文件。 */
            const char *path = argv[++i];
            long n = read_file(path, (unsigned char *)msg_buf, sizeof(msg_buf) - 1);
            if (n < 0) {
                fprintf(stderr, "[node] 无法读取消息文件 %s（不存在，或超过 %d 字节）\n",
                        path, (int)sizeof(msg_buf) - 1);
                return 1;
            }
            msg_buf[n] = '\0';
            if ((long)strlen(msg_buf) != n) {
                fprintf(stderr, "[node] 消息文件 %s 含 NUL 字节，当前协议只签名文本消息\n", path);
                return 1;
            }
            if (n == 0) { fprintf(stderr, "[node] 消息文件 %s 为空\n", path); return 1; }
            message = msg_buf;
        }
        else if (strcmp(argv[i], "--out-dir") == 0 && i + 1 < argc) out_dir = argv[++i];
        else { usage(argv[0]); return 2; }
    }

    NodeConfig cfg;
    if (config_load(conf, &cfg, 1) != 0) return 1;
    config_print(&cfg);

    Party *P = party_new(&cfg, &DCF_BACKEND_DFSS, message, out_dir);
    if (!P) return 1;
    plog(P, "打开与对方的协议信道（P0 监听 %s:%d，P1 主动连接）…",
         cfg.party[0].ip, cfg.party[0].port);
    if (channel_open(&P->ch, cfg.self_index, cfg.party[0].ip, cfg.party[0].port,
                     cfg.timeout_seconds) != 0) {
        P->terminal = TERM_CHANNEL_ERROR;
        party_print_summary(P);
        party_free(P);
        return 1;
    }
    int rc = party_run(P);
    party_print_summary(P);
    party_write_outputs(P);
    party_free(P);
    return rc == 0 ? 0 : 1;
}
