/*
 * open_check.c —— 严格打开一致性检查（对原工程 strict MACCheck 的两方对称化改写）。
 *
 * 目的：确认 P0 与 P1 对若干“应当相同的公开量”（t、com、w、z、r、决策向量）
 * 持有逐系数一致的视图 view_0 = view_1，而不必把整条向量再传一遍。
 *
 * 流程（四轮，全部走 channel_commit_open，因此每一对都是“先承诺后打开”）：
 *   轮 1-2  抛币：双方各出 32 字节随机数 theta_b，seed = SHA3(ctx || theta_0 || theta_1)
 *   本地    对每个检查项 k、每一行 i：v_b[k][i] = Σ_j chi_{k,i,j} · view_b[k][j] mod q，
 *           chi 由 SHAKE256(seed || k || i) 拒绝采样得到
 *   轮 3-4  交换 v_b，要求 v_0 = v_1
 *
 * 可靠性：若 view_0 ≠ view_1，由于 chi 在视图固定之后才由双方共同决定，
 *         每一行 Pr[chi·(view_0 - view_1) = 0] = 1/q，m=16 行联合误判概率约 q^{-16} ≈ 2^{-368}。
 *
 * 与原 strict MACCheck 的关系：原实现中协调方公布 claimed 值，其余签名方用私有 MAC key
 * α_i 对 (claimed - view_i) 加权，使协调方无法伪造零和。现在没有协调方，没有任何一方替
 * 别人“声明”打开值——每方都用自己的视图参与，因此 α 失去作用，被去掉了。
 *
 * 必须如实说明的边界：两方之间每条消息都只发给唯一的对方，不存在 equivocation；
 * 双方视图都是同一份转录的确定性函数。所以本检查检测的是传输错误、状态机分叉、
 * 实现缺陷，而不是恶意行为——恶意一方可以直接在 v_b 上说谎。
 */
#include "field.h"
#include "fips202.h"
#include "protocol.h"
#include "secure_random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void derive_seed(const uint8_t ctx[32], const uint8_t theta0[32], const uint8_t theta1[32], uint8_t out[32]) {
    uint8_t buf[16 + 96];
    memcpy(buf, "TPM2-CHECK-SEED\0", 16);
    memcpy(buf + 16, ctx, 32);
    memcpy(buf + 48, theta0, 32);
    memcpy(buf + 80, theta1, 32);
    sha3_256(out, buf, sizeof(buf));
}

/* v = Σ_j chi_j view[j]，chi 从 SHAKE256(seed||k||row) 中以 23 比特拒绝采样得到。 */
static DilithiumCoeff compress_row(const uint8_t seed[32], int k, int row,
                                   const DilithiumCoeff *view, int n) {
    keccak_state st;
    uint8_t hdr[40];
    memcpy(hdr, seed, 32);
    for (int i = 0; i < 4; i++) hdr[32 + i] = (uint8_t)((uint32_t)k >> (8 * i));
    for (int i = 0; i < 4; i++) hdr[36 + i] = (uint8_t)((uint32_t)row >> (8 * i));
    shake256_init(&st);
    shake256_absorb(&st, hdr, sizeof(hdr));
    shake256_finalize(&st);
    uint8_t block[3 * 256];
    size_t pos = sizeof(block);
    int64_t acc = 0;
    for (int j = 0; j < n; j++) {
        uint32_t chi;
        do {
            if (pos + 3 > sizeof(block)) { shake256_squeeze(block, sizeof(block), &st); pos = 0; }
            chi = ((uint32_t)block[pos] | ((uint32_t)block[pos + 1] << 8) |
                   ((uint32_t)block[pos + 2] << 16)) & 0x7fffffU;
            pos += 3;
        } while (chi >= (uint32_t)DILITHIUM_Q);
        acc = (acc + (int64_t)chi * (int64_t)dilithium_mod_q(view[j])) % DILITHIUM_Q;
    }
    return (DilithiumCoeff)acc;
}

int open_check_run(Party *P, const char *scope, int attempt, const OpenCheckItem *items, int count) {
    phase_begin(P, PH_OPEN_CHECK);
    int result = -1;
    const int m = OPEN_CHECK_ROWS;
    size_t vlen = (size_t)count * (size_t)m * 4u;
    uint8_t *v = calloc(vlen, 1);
    uint8_t *peer_v = calloc(vlen, 1);
    if (!v || !peer_v) goto out;

    uint8_t ctx0[32], ctx[32];
    party_ctx(P, scope, attempt, count, ctx0);
    {
        keccak_state st;
        shake256_init(&st);
        shake256_absorb(&st, ctx0, 32);
        for (int k = 0; k < count; k++) {
            uint8_t nb[4];
            for (int i = 0; i < 4; i++) nb[i] = (uint8_t)((uint32_t)items[k].n >> (8 * i));
            shake256_absorb(&st, (const uint8_t *)items[k].label, strlen(items[k].label) + 1);
            shake256_absorb(&st, nb, 4);
        }
        shake256_finalize(&st);
        shake256_squeeze(ctx, 32, &st);
    }

    {
        uint8_t theta[32], peer_theta[32], seed[32];
        if (secure_random_os_bytes(theta, 32) != 0 ||
            channel_commit_open(&P->ch, TAG_CHECK_COIN, ctx, theta, peer_theta, 32) != 0) {
            goto out;
        }
        derive_seed(ctx, P->b == 0 ? theta : peer_theta, P->b == 0 ? peer_theta : theta, seed);
        for (int k = 0; k < count; k++) {
            for (int row = 0; row < m; row++) {
                uint32_t x = (uint32_t)compress_row(seed, k, row, items[k].view, items[k].n);
                uint8_t *p = v + 4u * ((size_t)k * (size_t)m + (size_t)row);
                p[0] = (uint8_t)x; p[1] = (uint8_t)(x >> 8); p[2] = (uint8_t)(x >> 16); p[3] = (uint8_t)(x >> 24);
            }
        }
    }

    if (channel_commit_open(&P->ch, TAG_CHECK_VALUES, ctx, v, peer_v, vlen) != 0) goto out;

    result = 1;
    {
        char detail[256];
        size_t off = 0;
        detail[0] = '\0';
        for (int k = 0; k < count; k++) {
            int same = memcmp(v + 4u * (size_t)k * (size_t)m, peer_v + 4u * (size_t)k * (size_t)m, 4u * (size_t)m) == 0;
            if (!same) result = 0;
            if (off < sizeof(detail)) {
                int w = snprintf(detail + off, sizeof(detail) - off, "%s%s=%s(%d)",
                                 k ? " " : "", items[k].label, same ? "OK" : "MISMATCH", items[k].n);
                if (w > 0) off += (size_t)w;
            }
        }
        P->stats.open_checks++;
        P->stats.open_check_items += count;
        plog(P, "OpenCheck[%s attempt=%d]: %s  rows=%d  error<=q^-%d  => %s",
             scope, attempt + 1, detail, m, m, result == 1 ? "PASS" : "FAIL (fail-closed)");
    }

out:
    phase_end(P, PH_OPEN_CHECK);
    free(v);
    free(peer_v);
    return result;
}
