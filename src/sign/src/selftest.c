/*
 * selftest.c —— 单进程双线程自检。
 *
 * 两个 Party 跑在同一进程的两个线程里，用 socketpair 当协议信道，
 * DFSS 换成 mock_dcf.c 的进程内替身。它验证的是协议逻辑（握手、DKG、承诺轮、
 * 掩码交换、Algorithm 7、一致性检查、编码与标准验证），不验证真实 DFSS 后端。
 *
 * --fault-inject 会让 P0 在一致性检查前篡改自己的 w 视图，用来确认
 * open_check 能抓到视图分叉并 fail-closed（期望 OPEN_CHECK_FAILED）。
 */
#include "mock_dcf.h"
#include "party.h"
#include "protocol.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct { Party *P; int rc; } Job;

static void *run_party(void *arg) {
    Job *j = (Job *)arg;
    j->rc = party_run(j->P);
    return NULL;
}

int selftest_main(int argc, char **argv) {
    int K = 1, L = 4, fault = 0;
    PoolMode mode = POOL_MODE_REFILL;
    const char *message = "selftest-message";
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--batch") == 0 && i + 1 < argc) K = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pool") == 0 && i + 1 < argc) L = atoi(argv[++i]);
        else if (strcmp(argv[i], "--pool-mode") == 0 && i + 1 < argc)
            mode = strcmp(argv[++i], "fixed") == 0 ? POOL_MODE_FIXED : POOL_MODE_REFILL;
        else if (strcmp(argv[i], "--fault-inject") == 0) fault = 1;
        else if (strcmp(argv[i], "--message") == 0 && i + 1 < argc) message = argv[++i];
        else { fprintf(stderr, "selftest: 未知参数 %s\n", argv[i]); return 2; }
    }

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { perror("socketpair"); return 1; }

    NodeConfig cfg[2];
    Party *P[2];
    for (int b = 0; b < 2; b++) {
        config_defaults(&cfg[b]);
        cfg[b].self_index = b;
        cfg[b].batch_size = K;
        cfg[b].pool_size = L;
        cfg[b].pool_mode = mode;
        cfg[b].open_check = OPEN_CHECK_STRICT;
        for (int i = 0; i < 2; i++) {
            cfg[b].party[i].present = 1;
            snprintf(cfg[b].party[i].ip, sizeof(cfg[b].party[i].ip), "127.0.0.1");
            cfg[b].party[i].port = 19000 + i;
            cfg[b].party[i].dfss_port = 19100 + 200 * i;
        }
        if (config_validate(&cfg[b], 1) != 0) return 1;
        P[b] = party_new(&cfg[b], &DCF_BACKEND_MOCK, message, "");
        if (!P[b]) return 1;
        channel_from_fd(&P[b]->ch, sv[b], b, 60);
    }
    P[0]->fault_inject = fault;

    printf("[selftest] %s，K=%d L=%d pool_mode=%s%s；DFSS 使用进程内替身（不安全，仅测协议逻辑）\n",
           MLDSA_LEVEL_NAME, K, L, pool_mode_name(mode), fault ? "，已注入 w 视图分叉" : "");

    Job jobs[2] = { { P[0], -1 }, { P[1], -1 } };
    pthread_t th[2];
    for (int b = 0; b < 2; b++) pthread_create(&th[b], NULL, run_party, &jobs[b]);
    for (int b = 0; b < 2; b++) pthread_join(th[b], NULL);

    for (int b = 0; b < 2; b++) party_print_summary(P[b]);

    int ok;
    if (fault) {
        ok = P[0]->terminal == TERM_OPEN_CHECK_FAILED && P[1]->terminal == TERM_OPEN_CHECK_FAILED;
        printf("[selftest] 故障注入用例：期望两方都 OPEN_CHECK_FAILED，实际 P0=%s P1=%s -> %s\n",
               terminal_name(P[0]->terminal), terminal_name(P[1]->terminal), ok ? "OK" : "REGRESSION");
    } else {
        ok = jobs[0].rc == 0 && jobs[1].rc == 0 &&
             P[0]->terminal == TERM_SUCCESS && P[1]->terminal == TERM_SUCCESS &&
             memcmp(P[0]->sig_hash, P[1]->sig_hash, 32) == 0 &&
             memcmp(P[0]->pk, P[1]->pk, MLDSA_PUBLICKEY_BYTES) == 0;
        printf("[selftest] 正常用例：期望两方 SUCCESS 且签名/公钥一致，实际 P0=%s P1=%s -> %s\n",
               terminal_name(P[0]->terminal), terminal_name(P[1]->terminal), ok ? "OK" : "REGRESSION");
    }
    for (int b = 0; b < 2; b++) party_free(P[b]);
    return ok ? 0 : 1;
}
