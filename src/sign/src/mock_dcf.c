/*
 * mock_dcf.c —— 仅供 `node selftest` 使用的进程内 DFSS 替身（不安全，绝不用于真实运行）。
 *
 * 两个参与方以线程形式运行在同一进程内，替身在全局表里“交汇”：
 *   keygen：为 (pool_item, C_b) 生成随机掩码份额 rho_b，返回占位 token；
 *   eval  ：等两方都提交后，计算 x = u - rho_0 - rho_1 = z + B，统计 x >= 2B 的系数个数，
 *           把失败计数随机拆成 Z_{2^32} 上的加性份额分别返回。
 * 输入输出语义与真实适配器一致，因此可以在没有 EzPC 的机器上检验协议逻辑，
 * 包括 ML-DSA-65/87（仓库自带的预编译适配器只支持 ML-DSA-44）。
 */
#include "mock_dcf.h"

#include "field.h"
#include "secure_random.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MOCK_MAX_ITEMS 4096

typedef struct {
    int have[2];
    uint32_t mask[2][DILITHIUM_S_COEFFS];
} MockItem;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static MockItem *g_items[MOCK_MAX_ITEMS];

static struct {
    int arrived[2];
    int taken[2];
    int done;
    int rc;
    int first_item;
    int candidates;
    uint32_t *u;
    uint32_t phi[2][TDILITHIUM_DCF_BATCH_MAX];
} g_rv;

static int mock_available(void) { return 1; }

static uint32_t rand32(void) {
    uint8_t b[4];
    if (secure_random_os_bytes(b, 4) != 0) return 0x9e3779b9U;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static int mock_keygen(const DcfDealerlessKeygenCtx *ctx, DcfDealerlessKeyShare *out) {
    memset(out, 0, sizeof(*out));
    if (!ctx || ctx->pool_item < 0 || ctx->pool_item >= MOCK_MAX_ITEMS ||
        ctx->helper_index < 0 || ctx->helper_index > 1 || ctx->coeff_count != DILITHIUM_S_COEFFS) return -1;
    pthread_mutex_lock(&g_lock);
    if (!g_items[ctx->pool_item]) g_items[ctx->pool_item] = calloc(1, sizeof(MockItem));
    MockItem *it = g_items[ctx->pool_item];
    if (!it) { pthread_mutex_unlock(&g_lock); return -1; }
    for (int j = 0; j < ctx->coeff_count; j++) {
        uint32_t r;
        do { r = rand32() & 0x7fffffU; } while (r >= (uint32_t)DILITHIUM_Q);
        it->mask[ctx->helper_index][j] = r;
        out->local_mask_shares[j] = r;
    }
    it->have[ctx->helper_index] = 1;
    pthread_mutex_unlock(&g_lock);
    out->key_bytes = malloc(32);
    if (!out->key_bytes) return -1;
    memset(out->key_bytes, 0, 32);
    memcpy(out->key_bytes, "MOCKDCF", 7);
    out->key_bytes[8] = (unsigned char)ctx->helper_index;
    memcpy(out->key_bytes + 12, &ctx->pool_item, sizeof(int));
    out->key_len = 32;
    return 0;
}

static int mock_eval(const DcfDealerlessEvalCtx *ctx, uint32_t *phi, uint64_t *digests) {
    if (!ctx || ctx->candidates < 1 || ctx->candidates > TDILITHIUM_DCF_BATCH_MAX) return -1;
    const int b = ctx->helper_index;
    const int K = ctx->candidates, M = ctx->coeff_count;
    pthread_mutex_lock(&g_lock);
    if (!g_rv.arrived[0] && !g_rv.arrived[1]) {
        memset(&g_rv, 0, sizeof(g_rv));
        g_rv.first_item = ctx->pool_item;
        g_rv.candidates = K;
        g_rv.u = malloc((size_t)K * (size_t)M * sizeof(uint32_t));
        if (g_rv.u) memcpy(g_rv.u, ctx->public_u, (size_t)K * (size_t)M * sizeof(uint32_t));
    }
    g_rv.arrived[b] = 1;
    if (g_rv.first_item != ctx->pool_item || g_rv.candidates != K || !g_rv.u ||
        memcmp(g_rv.u, ctx->public_u, (size_t)K * (size_t)M * sizeof(uint32_t)) != 0) {
        g_rv.rc = -1;   /* 两方公开输入不一致 */
    }
    if (g_rv.arrived[0] && g_rv.arrived[1] && !g_rv.done) {
        for (int p = 0; p < K && g_rv.rc == 0; p++) {
            MockItem *it = g_items[ctx->pool_item + p];
            if (!it || !it->have[0] || !it->have[1]) { g_rv.rc = -1; break; }
            uint32_t fails = 0;
            for (int j = 0; j < M; j++) {
                int64_t x = (int64_t)g_rv.u[(size_t)p * (size_t)M + (size_t)j] - it->mask[0][j] - it->mask[1][j];
                x %= DILITHIUM_Q;
                if (x < 0) x += DILITHIUM_Q;
                if (x >= 2LL * ctx->bound_B) fails++;
            }
            uint32_t r = rand32();
            g_rv.phi[0][p] = r;
            g_rv.phi[1][p] = fails - r;
            free(it);
            g_items[ctx->pool_item + p] = NULL;
        }
        g_rv.done = 1;
        pthread_cond_broadcast(&g_cond);
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 60;
    while (!g_rv.done) {
        if (pthread_cond_timedwait(&g_cond, &g_lock, &deadline) == ETIMEDOUT) break;
    }
    int rc = g_rv.done ? g_rv.rc : -1;
    for (int p = 0; p < K; p++) { phi[p] = g_rv.phi[b][p]; digests[p] = 0; }
    g_rv.taken[b] = 1;
    if (g_rv.taken[0] && g_rv.taken[1]) { free(g_rv.u); memset(&g_rv, 0, sizeof(g_rv)); }
    pthread_mutex_unlock(&g_lock);
    return rc;
}

static void mock_free_share(DcfDealerlessKeyShare *share) {
    if (!share) return;
    free(share->key_bytes);
    memset(share, 0, sizeof(*share));
}

const DcfBackendOps DCF_BACKEND_MOCK = {
    "MOCK in-process test double (NOT SECURE, selftest only)",
    mock_available, mock_keygen, mock_eval, mock_free_share,
};
