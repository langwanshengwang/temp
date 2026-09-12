/*
 * dkg.c —— 两方分布式密钥生成 DKeyGen。
 *
 * 两方运行完全相同的代码（只有 b 不同），每方同时是 dealer 与 receiver：
 *   阶段 1  本地采样 s1_b, s2_b ∈ S_eta、一次 Shamir 多项式 F_b(X)=v_b+a_b X、A_b ← R_q^{k×l}
 *   阶段 2  对 A_b 先承诺后打开；rho = H(A_0 + A_1)，A = ExpandA(rho)
 *   阶段 3  交换 t_b = A s1_b + s2_b 与 F_b(x_{1-b})
 *   阶段 4  sk^(b) = F_0(x_b) + F_1(x_b)，t = t_0 + t_1，编码标准公钥 (rho, t1)
 *   阶段 5  严格模式下对 t 做打开一致性检查
 */
#include "field.h"
#include "fips202.h"
#include "mldsa_compat.h"
#include "protocol.h"
#include "secure_random.h"

#include <stdlib.h>
#include <string.h>

static int sample_eta(SecureRandom *rng, DilithiumCoeff *out, int n) {
    for (int i = 0; i < n; i++) {
        uint32_t x;
        if (secure_random_u32_below(rng, 2 * DILITHIUM_ETA + 1, &x) != 0) return -1;
        out[i] = dilithium_centered_to_mod_q((int32_t)x - DILITHIUM_ETA);
    }
    return 0;
}

static int sample_uniform(SecureRandom *rng, DilithiumCoeff *out, int n) {
    for (int i = 0; i < n; i++) {
        uint32_t x;
        if (secure_random_u32_below(rng, DILITHIUM_Q, &x) != 0) return -1;
        out[i] = (DilithiumCoeff)x;
    }
    return 0;
}

int dkg_run(Party *P) {
    phase_begin(P, PH_DKG);
    int rc = -1;
    const int b = P->b;
    const int64_t x_self = b + 1, x_peer = 2 - b;     /* Shamir 求值点：P0→1，P1→2 */

    DilithiumCoeff *s1 = calloc(DILITHIUM_S_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *s2 = calloc(DILITHIUM_E_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *coef_a = calloc(DILITHIUM_SK_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *A_b = calloc(DILITHIUM_A_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *A_peer = calloc(DILITHIUM_A_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *A_sum = calloc(DILITHIUM_A_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *t_b = calloc(DILITHIUM_PK_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *t_peer = calloc(DILITHIUM_PK_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *d_self = calloc(DILITHIUM_SK_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *d_peer = calloc(DILITHIUM_SK_COEFFS, sizeof(DilithiumCoeff));
    DilithiumCoeff *d_from_peer = calloc(DILITHIUM_SK_COEFFS, sizeof(DilithiumCoeff));
    size_t a_len = field_pack24_len(DILITHIUM_A_COEFFS);
    size_t ts_len = field_pack24_len(DILITHIUM_PK_COEFFS) + field_pack24_len(DILITHIUM_SK_COEFFS);
    size_t big = a_len > ts_len ? a_len : ts_len;
    uint8_t *buf = malloc(big);
    uint8_t *peer_buf = malloc(big);
    SecureRandom rng;
    memset(&rng, 0, sizeof(rng));
    if (!s1 || !s2 || !coef_a || !A_b || !A_peer || !A_sum || !t_b || !t_peer ||
        !d_self || !d_peer || !d_from_peer || !buf || !peer_buf) goto out;

    /* 阶段 1：本地 dealer 材料 */
    if (secure_random_init(&rng, "tpm2-dkg-dealer", P->sid, sizeof(P->sid)) != 0 ||
        sample_eta(&rng, s1, DILITHIUM_S_COEFFS) != 0 ||
        sample_eta(&rng, s2, DILITHIUM_E_COEFFS) != 0 ||
        sample_uniform(&rng, coef_a, DILITHIUM_SK_COEFFS) != 0 ||
        sample_uniform(&rng, A_b, DILITHIUM_A_COEFFS) != 0) {
        plog(P, "DKeyGen：CSPRNG 失败");
        goto out;
    }

    /* 阶段 2：A_b 先承诺后打开，防止后发言方看到对方 A 分量后再挑选自己的分量 */
    {
        uint8_t ctx[32];
        party_ctx(P, "DKG-A", 0, 0, ctx);
        field_pack24(buf, A_b, DILITHIUM_A_COEFFS);
        if (channel_commit_open(&P->ch, TAG_DKG_A_COMMIT, ctx, buf, peer_buf, a_len) != 0 ||
            field_unpack24(A_peer, peer_buf, DILITHIUM_A_COEFFS) != 0) {
            plog(P, "DKeyGen：A 分量的承诺打开失败");
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
    }
    field_add_vec(A_sum, A_b, A_peer, DILITHIUM_A_COEFFS);
    {
        const int ids[MAX_MEMBERS] = { 1, 2 };
        mldsa44_derive_rho_from_transcript(A_sum, P->session_id, ids, 2, P->rho);
    }
    mldsa44_expand_matrix_from_rho(P->rho, P->A);
    mm_expand_A_ntt(P->A, P->A_ntt);
    P->A_digest = field_digest_coeffs(P->A, DILITHIUM_A_COEFFS);
    mm_commit_cache_init(P->commit, P->A_digest);

    /* 阶段 3：t_b 与发给对方的 Shamir 份额 */
    mm_compute_t_share(P->A_ntt, s1, s2, t_b);
    for (int j = 0; j < DILITHIUM_SK_COEFFS; j++) {
        DilithiumCoeff v = j < DILITHIUM_S_COEFFS ? s1[j] : s2[j - DILITHIUM_S_COEFFS];
        d_self[j] = dilithium_mod_q((int64_t)v + (int64_t)coef_a[j] * x_self);
        d_peer[j] = dilithium_mod_q((int64_t)v + (int64_t)coef_a[j] * x_peer);
    }
    {
        size_t tl = field_pack24_len(DILITHIUM_PK_COEFFS);
        field_pack24(buf, t_b, DILITHIUM_PK_COEFFS);
        field_pack24(buf + tl, d_peer, DILITHIUM_SK_COEFFS);
        if (channel_exchange_fixed(&P->ch, TAG_DKG_T_SHARE, buf, peer_buf, ts_len) != 0 ||
            field_unpack24(t_peer, peer_buf, DILITHIUM_PK_COEFFS) != 0 ||
            field_unpack24(d_from_peer, peer_buf + tl, DILITHIUM_SK_COEFFS) != 0) {
            plog(P, "DKeyGen：t_b / 份额交换失败");
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
    }

    /* 阶段 4：本地聚合 */
    field_add_vec(P->sk_share, d_self, d_from_peer, DILITHIUM_SK_COEFFS);
    field_add_vec(P->t, t_b, t_peer, DILITHIUM_PK_COEFFS);
    mldsa44_encode_public_key_from_t(P->rho, P->t, P->pk);
    plog(P, "DKeyGen 完成：rho=%02x%02x…  pk_digest=0x%016llx  t_digest=0x%016llx  本方 Shamir 点 x=%lld",
         P->rho[0], P->rho[1], (unsigned long long)field_digest_bytes(P->pk, MLDSA_PUBLICKEY_BYTES),
         (unsigned long long)field_digest_coeffs(P->t, DILITHIUM_PK_COEFFS), (long long)x_self);
    rc = 0;

out:
    phase_end(P, PH_DKG);
    secure_random_destroy(&rng);
    if (s1) secure_bzero(s1, DILITHIUM_S_COEFFS * sizeof(DilithiumCoeff));
    if (s2) secure_bzero(s2, DILITHIUM_E_COEFFS * sizeof(DilithiumCoeff));
    if (coef_a) secure_bzero(coef_a, DILITHIUM_SK_COEFFS * sizeof(DilithiumCoeff));
    if (d_self) secure_bzero(d_self, DILITHIUM_SK_COEFFS * sizeof(DilithiumCoeff));
    if (d_peer) secure_bzero(d_peer, DILITHIUM_SK_COEFFS * sizeof(DilithiumCoeff));
    if (d_from_peer) secure_bzero(d_from_peer, DILITHIUM_SK_COEFFS * sizeof(DilithiumCoeff));
    if (buf) secure_bzero(buf, big);
    free(s1); free(s2); free(coef_a); free(A_b); free(A_peer); free(A_sum);
    free(t_b); free(t_peer); free(d_self); free(d_peer); free(d_from_peer);
    free(buf); free(peer_buf);
    if (rc != 0) return rc;

    /* 阶段 5：严格模式下确认双方聚合出的 t 一致 */
    if (P->cfg.open_check == OPEN_CHECK_STRICT) {
        OpenCheckItem items[] = { { "T", P->t, DILITHIUM_PK_COEFFS } };
        int ok = open_check_run(P, "DKeyGen", 0, items, 1);
        if (ok != 1) {
            P->terminal = ok < 0 ? TERM_CHANNEL_ERROR : TERM_OPEN_CHECK_FAILED;
            return -1;
        }
    }
    return 0;
}
