/*
 * dcf_rejects.c —— DCF 拒绝采样（离线池 + 在线批量比较），P_b 同时承担 C_b。
 *
 * 与原“协调方 + 独立比较节点 C0/C1”结构相比的变化：
 *
 *  原结构：签名方 P_i 把自己的 z_i 随机拆成两份分别发给 C0/C1；C_b 汇总所有签名方的份额，
 *          加上离线掩码份额 rho_b 后与 C_{1-b} 交换，打开 u = z + B + rho；C_b 在线比较后把
 *          失败计数份额 phi_b 发给协调方，由协调方相加判定。
 *
 *  现结构：C_b 就是 P_b 自己，它本来就持有 z 的加性份额 z_b，所以“再拆一次发给两台比较机”
 *          这一步整体消失：
 *              g_b = z_b + [b=0]·B + rho_b      （P_b 本地计算）
 *              交换 g_0, g_1，打开 u = g_0 + g_1 = z + B + rho
 *              P_b 调用 DFSS 在线比较（与对方交互），得到 phi_b
 *              先承诺后打开 phi_b，accept ⟺ phi_0 + phi_1 = 0 (mod 2^32)
 *          phi 由两方共同打开、共同判定，不再发送给任何“请求方”。
 *
 * 隐私：P_{1-b} 只看到 g_b = z_b + (常数) + rho_b，rho_b 是 P_b 私有、一次性、均匀的掩码份额，
 *       因此 z_b 不被泄露；u 对双方都是均匀随机的。DCF 判拒的候选，其 z_b 永远不会被发送。
 *
 * DFSS 适配器 ABI（v4，结构体按最大参数集定长、与 ML-DSA 模式无关）：keygen 在两方之间交互生成一次性密钥与各自掩码；
 * eval 把 u 转成输入份额，再与对方交互完成比较。
 */
#include "candidate.h"
#include "field.h"
#include "protocol.h"
#include "secure_random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* 没有协调方后，DFSS 上下文中的 requester 字段不再代表任何角色，两方统一填 0。 */
#define DCF_REQUESTER_NONE 0

const DcfBackendOps DCF_BACKEND_DFSS = {
    "ezpc-dfss/libdfss_sign_adapter",
    dcf_dealerless_backend_available,
    dcf_dealerless_backend_keygen_share,
    dcf_dealerless_backend_eval_failure_shares,
    dcf_dealerless_backend_free_key_share,
};

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void dcf_pool_free(DcfPool *pool) {
    if (!pool) return;
    if (pool->items) secure_bzero(pool->items, (size_t)pool->capacity * sizeof(PoolItem));
    free(pool->items);
    memset(pool, 0, sizeof(*pool));
}

static int pool_reserve(DcfPool *pool, int need) {
    if (need <= pool->capacity) return 0;
    int cap = pool->capacity ? pool->capacity : 8;
    while (cap < need) cap *= 2;
    PoolItem *items = (PoolItem *)realloc(pool->items, (size_t)cap * sizeof(PoolItem));
    if (!items) return -1;
    memset(items + pool->capacity, 0, (size_t)(cap - pool->capacity) * sizeof(PoolItem));
    pool->items = items;
    pool->capacity = cap;
    return 0;
}

static void fill_keygen_ctx(const Party *P, int item, DcfDealerlessKeygenCtx *ctx) {
    const int b = P->b;
    memset(ctx, 0, sizeof(*ctx));
    ctx->abi_version = DCF_DEALERLESS_BACKEND_ABI_VERSION;
    ctx->helper_index = b;                     /* P_b 就是 C_b */
    ctx->self_node_id = b;
    ctx->peer_node_id = 1 - b;
    snprintf(ctx->self_ip, sizeof(ctx->self_ip), "%s", P->cfg.party[b].ip);
    ctx->self_port = P->cfg.party[b].port;
    snprintf(ctx->peer_ip, sizeof(ctx->peer_ip), "%s", P->cfg.party[1 - b].ip);
    ctx->peer_port = P->cfg.party[1 - b].port;
    ctx->self_dfss_port = P->cfg.party[b].dfss_port;
    ctx->peer_dfss_port = P->cfg.party[1 - b].dfss_port;
    ctx->requester_id = DCF_REQUESTER_NONE;
    ctx->session_id = P->session_id;
    ctx->coeff_count = DILITHIUM_S_COEFFS;
    ctx->bound_B = TDILITHIUM_Z_BOUND;
    ctx->pool_item = item;
    ctx->rejection_round = item;
}

int dcf_pool_generate(Party *P, int first, int count) {
    phase_begin(P, PH_DCF_PREP);
    int rc = -1;
    uint8_t sync[12], peer_sync[12];
    put32(sync, (uint32_t)first);
    put32(sync + 4, (uint32_t)count);
    put32(sync + 8, (uint32_t)P->session_id);
    if (channel_exchange_fixed(&P->ch, TAG_POOL_SYNC, sync, peer_sync, sizeof(sync)) != 0) {
        P->terminal = TERM_CHANNEL_ERROR;
        goto out;
    }
    if (memcmp(sync, peer_sync, sizeof(sync)) != 0) {
        plog(P, "DCFPrep：双方池区间不一致（本方 [%d,+%d)，对方 [%u,+%u)），fail-closed",
             first, count, get32(peer_sync), get32(peer_sync + 4));
        P->terminal = TERM_DCF_ERROR;
        goto out;
    }
    if (pool_reserve(&P->pool, first + count) != 0) goto out;

    plog(P, "DCFPrep：以 C%d 身份与对方无 dealer 生成一次性 DFSS 密钥/掩码，池项 [%d, %d)", P->b, first, first + count);
    {
        int local_ok = 1;
        double t0 = now_ms();
        for (int item = first; item < first + count && local_ok; item++) {
            DcfDealerlessKeygenCtx ctx;
            DcfDealerlessKeyShare share;
            fill_keygen_ctx(P, item, &ctx);
            memset(&share, 0, sizeof(share));
            if (P->dcf->keygen(&ctx, &share) != 0 || !share.key_bytes ||
                share.key_len == 0 || share.key_len > sizeof(P->pool.items[item].token)) {
                plog(P, "DCFPrep：池项 %d 的 DFSS keygen 失败", item);
                P->dcf->free_share(&share);
                local_ok = 0;
                break;
            }
            PoolItem *it = &P->pool.items[item];
            memcpy(it->token, share.key_bytes, share.key_len);
            it->token_len = share.key_len;
            for (int j = 0; j < DILITHIUM_S_COEFFS; j++) {
                if (share.local_mask_shares[j] >= (uint32_t)DILITHIUM_Q) local_ok = 0;
                it->mask[j] = (DilithiumCoeff)share.local_mask_shares[j];
            }
            it->valid = local_ok;
            P->dcf->free_share(&share);
        }
        P->stats.dfss_keygen_ms += now_ms() - t0;

        uint8_t done[4], peer_done[4];
        put32(done, (uint32_t)local_ok);
        if (channel_exchange_fixed(&P->ch, TAG_POOL_DONE, done, peer_done, 4) != 0) {
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
        if (!local_ok || get32(peer_done) != 1u) {
            plog(P, "DCFPrep：%s池生成失败，fail-closed", local_ok ? "对方" : "本方");
            P->terminal = TERM_DCF_ERROR;
            goto out;
        }
    }
    P->pool.end = first + count;
    P->stats.pool_items_generated += count;
    P->stats.pool_segments++;
    rc = 0;
out:
    phase_end(P, PH_DCF_PREP);
    return rc;
}

int dcf_pool_ensure(Party *P, int a0, int K) {
    if (a0 + K <= P->pool.end) return 0;
    if (P->cfg.pool_mode == POOL_MODE_FIXED) {
        plog(P, "DCF 离线池已耗尽（已生成 %d 项，下一批需要 [%d,%d)），pool_mode=fixed，明确停止",
             P->pool.end, a0, a0 + K);
        P->terminal = TERM_PREPROCESSING_EXHAUSTED;
        return -1;
    }
    while (a0 + K > P->pool.end) {
        plog(P, "DCF 离线池耗尽，pool_mode=refill：生成下一段 [%d,%d)", P->pool.end, P->pool.end + P->cfg.pool_size);
        if (dcf_pool_generate(P, P->pool.end, P->cfg.pool_size) != 0) {
            if (P->terminal == TERM_DCF_ERROR || P->terminal == TERM_NONE) P->terminal = TERM_POOL_REFILL_FAILED;
            return -1;
        }
        P->stats.pool_refills++;
    }
    return 0;
}

int dcf_rejects_batch(Party *P, Candidate *cands, int K) {
    phase_begin(P, PH_REJECTS);
    int rc = -1;
    const int M = DILITHIUM_S_COEFFS;
    const int a0 = cands[0].attempt;
    size_t n = (size_t)K * (size_t)M;
    DilithiumCoeff *g = calloc(n, sizeof(DilithiumCoeff));
    DilithiumCoeff *g_peer = calloc(n, sizeof(DilithiumCoeff));
    uint32_t *u = calloc(n, sizeof(uint32_t));
    uint8_t *buf = malloc(field_pack24_len((int)n));
    uint8_t *peer_buf = malloc(field_pack24_len((int)n));
    unsigned char *keys = calloc((size_t)K, 64);
    size_t key_len = 0;
    if (!g || !g_peer || !u || !buf || !peer_buf || !keys) goto out;

    key_len = P->pool.items[a0].token_len;
    for (int p = 0; p < K; p++) {
        PoolItem *it = &P->pool.items[a0 + p];
        if (cands[p].attempt != a0 + p || !it->valid || it->token_len != key_len) {
            plog(P, "RejectS：池项 %d 不可用或已被使用（一次性材料绝不复用）", a0 + p);
            P->terminal = TERM_DCF_ERROR;
            goto out;
        }
        memcpy(keys + (size_t)p * key_len, it->token, key_len);
        for (int j = 0; j < M; j++) {
            int64_t v = (int64_t)cands[p].z_share[j] + it->mask[j] + (P->b == 0 ? TDILITHIUM_Z_BOUND : 0);
            g[(size_t)p * (size_t)M + (size_t)j] = dilithium_mod_q(v);
        }
    }

    /* 轮 1：交换掩码后的输入，打开 u = z + B + rho */
    field_pack24(buf, g, (int)n);
    if (channel_exchange_fixed(&P->ch, TAG_DCF_MASKED, buf, peer_buf, field_pack24_len((int)n)) != 0 ||
        field_unpack24(g_peer, peer_buf, (int)n) != 0) {
        P->terminal = TERM_CHANNEL_ERROR;
        goto out;
    }
    for (size_t i = 0; i < n; i++) u[i] = (uint32_t)dilithium_mod_q((int64_t)g[i] + g_peer[i]);

    /* 轮 2（DFSS 内部）：以 C_b 身份在公开点 u 上运行在线比较 */
    {
        DcfDealerlessEvalCtx ectx;
        memset(&ectx, 0, sizeof(ectx));
        ectx.abi_version = DCF_DEALERLESS_BACKEND_ABI_VERSION;
        ectx.helper_index = P->b;
        ectx.requester_id = DCF_REQUESTER_NONE;
        ectx.session_id = P->session_id;
        ectx.coeff_count = M;
        ectx.bound_B = TDILITHIUM_Z_BOUND;
        ectx.pool_item = a0;
        ectx.rejection_round = a0;
        ectx.worker_threads = P->cfg.worker_threads;
        ectx.candidates = K;
        ectx.key_bytes = keys;
        ectx.key_len = key_len;
        ectx.public_u = u;
        uint32_t phi[TDILITHIUM_DCF_BATCH_MAX];
        uint64_t digests[TDILITHIUM_DCF_BATCH_MAX];
        double t0 = now_ms();
        int eval_rc = P->dcf->eval(&ectx, phi, digests);
        P->stats.dfss_eval_ms += now_ms() - t0;
        for (int p = 0; p < K; p++) {                       /* 一次性材料：无论成败都作废 */
            P->pool.items[a0 + p].valid = 0;
            secure_bzero(P->pool.items[a0 + p].mask, sizeof(P->pool.items[a0 + p].mask));
        }

        /* 轮 3-4：先承诺后打开 phi_b，附带本方 eval 状态，任一方失败双方同时 fail-closed */
        uint8_t msg[4 + 4 * TDILITHIUM_DCF_BATCH_MAX], peer_msg[4 + 4 * TDILITHIUM_DCF_BATCH_MAX];
        size_t mlen = 4 + 4u * (size_t)K;
        put32(msg, eval_rc == 0 ? 1u : 0u);
        for (int p = 0; p < K; p++) put32(msg + 4 + 4 * p, eval_rc == 0 ? phi[p] : 0u);
        uint8_t ctx[32];
        party_ctx(P, "DCF-PHI", a0, K, ctx);
        if (channel_commit_open(&P->ch, TAG_DCF_PHI, ctx, msg, peer_msg, mlen) != 0) {
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
        if (eval_rc != 0 || get32(peer_msg) != 1u) {
            plog(P, "RejectS：%s DFSS 在线比较失败，fail-closed", eval_rc != 0 ? "本方" : "对方");
            P->terminal = TERM_DCF_ERROR;
            goto out;
        }
        for (int p = 0; p < K; p++) {
            cands[p].phi_self = phi[p];
            cands[p].phi_peer = get32(peer_msg + 4 + 4 * p);
            uint32_t opened = cands[p].phi_self + cands[p].phi_peer;   /* 适配器输出在 Z_{2^32} 上加性共享 */
            cands[p].dcf_accept = opened == 0;
            if (cands[p].dcf_accept) P->stats.dcf_accepts++;
            else P->stats.dcf_rejects++;
            plog(P, "RejectS attempt=%d：phi_0+phi_1=%u → %s", cands[p].attempt + 1, opened,
                 cands[p].dcf_accept ? "ACCEPT（||z||_inf 检查通过）" : "REJECT（z 份额不打开，直接丢弃）");
        }
    }
    rc = 0;
out:
    phase_end(P, PH_REJECTS);
    if (g) secure_bzero(g, n * sizeof(DilithiumCoeff));
    free(g); free(g_peer); free(u); free(buf); free(peer_buf); free(keys);
    return rc;
}
