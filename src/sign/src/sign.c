/*
 * sign.c —— 两方签名 DSign：批量候选 → DCF 拒绝采样 → 打开并做 Algorithm 7 → 一致性检查 → 验证。
 *
 * 每个 attempt a（两方同时执行，代码完全相同）：
 *   1. 采样 y_b、r_b；w_b = A y_b；com_b = Com(r_b, w_b)
 *   2. 先承诺后打开 (com_b, w_b)，聚合 com、w；两方各自由 (pk, μ, w) 算出同一个挑战 c
 *   3. z_b = y_b + c · λ_b · s1(sk^(b))，λ_0 = 2, λ_1 = -1；z_b 暂不发送
 * 攒满 K 个候选后：
 *   4. DCF 批量比较 ||z||_inf < B（dcf_rejects.c）；判拒的候选 z_b 永不发送
 *   5. 按顺序取第一个 DCF 通过的候选，先承诺后打开 (z_b, r_b)，两方各自运行 Algorithm 7
 *   6. 若通过：严格模式下对 com/w/z/r/决策向量做打开一致性检查，编码签名、标准验证，
 *      交换签名摘要确认两方输出一致。否则取下一个候选或进入下一批。
 */
#include "candidate.h"
#include "field.h"
#include "fips202.h"
#include "mldsa_compat.h"
#include "protocol.h"
#include "secure_random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 每方 nonce 份额的采样界：聚合后仍落在 B = gamma1 - beta 以内，并预留 4096 余量。 */
#define NONCE_HEADROOM 4096

static int attempt_local(Party *P, Candidate *cd, int attempt, SecureRandom *rng) {
    phase_begin(P, PH_SIGN_ATTEMPT);
    int rc = -1;
    const int32_t y_bound = (TDILITHIUM_Z_BOUND - NONCE_HEADROOM) / TWOPC_PARTY_COUNT;
    const int32_t r_bound = (TDILITHIUM_GAMMA1 - NONCE_HEADROOM) / TWOPC_PARTY_COUNT;
    const DilithiumCoeff lambda = P->b == 0 ? 2 : DILITHIUM_Q - 1;   /* 点集 {1,2} 上的 Lagrange 系数 */
    DilithiumCoeff y[DILITHIUM_S_COEFFS];
    DilithiumCoeff w_b[DILITHIUM_PK_COEFFS], com_b[TDILITHIUM_COM_COEFFS];
    DilithiumCoeff w_peer[DILITHIUM_PK_COEFFS], com_peer[TDILITHIUM_COM_COEFFS];
    size_t lc = field_pack24_len(TDILITHIUM_COM_COEFFS), lw = field_pack24_len(DILITHIUM_PK_COEFFS);
    uint8_t *msg = malloc(lc + lw), *peer = malloc(lc + lw);
    if (!msg || !peer) goto out;

    memset(cd, 0, sizeof(*cd));
    cd->attempt = attempt;
    for (int j = 0; j < DILITHIUM_S_COEFFS; j++) {
        int32_t x;
        if (secure_random_centered(rng, y_bound, &x) != 0) goto out;
        y[j] = dilithium_centered_to_mod_q(x);
    }
    for (int j = 0; j < TDILITHIUM_R_COEFFS; j++) {
        int32_t x;
        if (secure_random_centered(rng, r_bound, &x) != 0) goto out;
        cd->r_share[j] = dilithium_centered_to_mod_q(x);
    }
    mm_A_mul_svec(P->A_ntt, y, w_b);
    mm_commitment(P->commit, cd->r_share, w_b, com_b);

    /* 承诺轮：防止后发言一方看到对方 w 后再选择自己的 w 去碾磨挑战 c */
    {
        uint8_t ctx[32];
        party_ctx(P, "SIGN-COMMIT", attempt, 0, ctx);
        field_pack24(msg, com_b, TDILITHIUM_COM_COEFFS);
        field_pack24(msg + lc, w_b, DILITHIUM_PK_COEFFS);
        if (channel_commit_open(&P->ch, TAG_SIGN_COMMIT, ctx, msg, peer, lc + lw) != 0 ||
            field_unpack24(com_peer, peer, TDILITHIUM_COM_COEFFS) != 0 ||
            field_unpack24(w_peer, peer + lc, DILITHIUM_PK_COEFFS) != 0) {
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
    }
    field_add_vec(cd->com, com_b, com_peer, TDILITHIUM_COM_COEFFS);
    field_add_vec(cd->w, w_b, w_peer, DILITHIUM_PK_COEFFS);
    mldsa44_challenge_from_public_key_message_w(P->pk, P->message, cd->w, cd->c, cd->c_tilde);

    /* z_b = y_b + c * lambda_b * s1(sk^(b)) */
    memcpy(cd->z_share, y, sizeof(y));
    for (int poly = 0; poly < DILITHIUM_L; poly++) {
        DilithiumCoeff scaled[DILITHIUM_N], acc[DILITHIUM_N];
        memset(acc, 0, sizeof(acc));
        for (int j = 0; j < DILITHIUM_N; j++) {
            scaled[j] = dilithium_mod_q((int64_t)P->sk_share[poly * DILITHIUM_N + j] * lambda);
        }
        mm_poly_mul_challenge_acc(acc, cd->c, scaled);
        for (int j = 0; j < DILITHIUM_N; j++) {
            int idx = poly * DILITHIUM_N + j;
            cd->z_share[idx] = dilithium_mod_q((int64_t)cd->z_share[idx] + acc[j]);
        }
        secure_bzero(scaled, sizeof(scaled));
    }
    P->stats.attempts++;
    rc = 0;
out:
    secure_bzero(y, sizeof(y));
    free(msg);
    free(peer);
    phase_end(P, PH_SIGN_ATTEMPT);
    return rc;
}

typedef struct {
    DilithiumCoeff z[DILITHIUM_S_COEFFS];
    DilithiumCoeff r[TDILITHIUM_R_COEFFS];
    DilithiumCoeff r0[DILITHIUM_PK_COEFFS];
    DilithiumCoeff ct0[DILITHIUM_PK_COEFFS];
    DilithiumCoeff hint[DILITHIUM_PK_COEFFS];
    MldsaAttemptCheck check;
} Opened;

/* 返回 1：Algorithm 7 通过；0：拒绝（z 已向双方打开）；-1：通信错误 */
static int open_and_check(Party *P, const Candidate *cd, Opened *o) {
    phase_begin(P, PH_OPEN_ALG7);
    int rc = -1;
    size_t lz = field_pack24_len(DILITHIUM_S_COEFFS), lr = field_pack24_len(TDILITHIUM_R_COEFFS);
    uint8_t *msg = malloc(lz + lr), *peer = malloc(lz + lr);
    DilithiumCoeff z_peer[DILITHIUM_S_COEFFS], r_peer[TDILITHIUM_R_COEFFS];
    if (!msg || !peer) goto out;
    {
        uint8_t ctx[32];
        party_ctx(P, "OPEN-ZR", cd->attempt, 0, ctx);
        field_pack24(msg, cd->z_share, DILITHIUM_S_COEFFS);
        field_pack24(msg + lz, cd->r_share, TDILITHIUM_R_COEFFS);
        if (channel_commit_open(&P->ch, TAG_OPEN_ZR, ctx, msg, peer, lz + lr) != 0 ||
            field_unpack24(z_peer, peer, DILITHIUM_S_COEFFS) != 0 ||
            field_unpack24(r_peer, peer + lz, TDILITHIUM_R_COEFFS) != 0) {
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
    }
    field_add_vec(o->z, cd->z_share, z_peer, DILITHIUM_S_COEFFS);
    field_add_vec(o->r, cd->r_share, r_peer, TDILITHIUM_R_COEFFS);
    {
        int ok = mm_algorithm7_checks(P->A_ntt, P->t, o->z, cd->c, o->r0, o->ct0, o->hint, &o->check);
        int r_ok = mm_vector_norm_below(o->r, TDILITHIUM_R_COEFFS, TDILITHIUM_GAMMA1);
        P->stats.opened_candidates++;
        if (!(ok && r_ok)) {
            P->stats.alg7_rejects_after_open++;
            if (!o->check.z_ok) P->stats.alg7_z_fail++;
            if (!o->check.r0_ok) P->stats.alg7_r0_fail++;
            if (!o->check.ct0_ok) P->stats.alg7_ct0_fail++;
            if (!o->check.hint_ok) P->stats.alg7_hint_fail++;
        }
        plog(P, "Algorithm7 attempt=%d：z=%s r0=%s ct0=%s hint=%s(%d/%d) r_audit=%s → %s",
             cd->attempt + 1, o->check.z_ok ? "PASS" : "REJECT", o->check.r0_ok ? "PASS" : "REJECT",
             o->check.ct0_ok ? "PASS" : "REJECT", o->check.hint_ok ? "PASS" : "REJECT",
             o->check.hint_ones, TDILITHIUM_OMEGA, r_ok ? "PASS" : "REJECT",
             (ok && r_ok) ? "ACCEPT" : "REJECT（注意：此候选的 z 已向双方打开）");
        rc = (ok && r_ok) ? 1 : 0;
    }
out:
    if (msg) secure_bzero(msg, lz + lr);
    secure_bzero(z_peer, sizeof(z_peer));
    secure_bzero(r_peer, sizeof(r_peer));
    free(msg);
    free(peer);
    phase_end(P, PH_OPEN_ALG7);
    return rc;
}

/*
 * 审计：两方都知道完整的 w、z 与 t，于是 A z - c t = w - c s2，
 * 任意一方都能算出 c·s2 = w - (A z - c t)。这里把它算出来并报告其范数，
 * 直观说明文档安全边界一节所述：在当前“明文聚合 w”的结构下，签名方之间不保密 s2。
 */
static void audit_cs2(Party *P, const Candidate *cd, const Opened *o) {
    DilithiumCoeff az[DILITHIUM_PK_COEFFS];
    mm_A_mul_svec(P->A_ntt, o->z, az);
    int max_abs = 0;
    for (int row = 0; row < DILITHIUM_K; row++) {
        DilithiumCoeff ct[DILITHIUM_N];
        memset(ct, 0, sizeof(ct));
        mm_poly_mul_challenge_acc(ct, cd->c, &P->t[row * DILITHIUM_N]);
        for (int j = 0; j < DILITHIUM_N; j++) {
            int idx = row * DILITHIUM_N + j;
            DilithiumCoeff d = dilithium_mod_q((int64_t)cd->w[idx] - az[idx] + ct[j]);
            int32_t cen = dilithium_mod_q_to_centered(d);
            if (cen < 0) cen = -cen;
            if (cen > max_abs) max_abs = cen;
        }
    }
    P->stats.cs2_audit_norm = max_abs;
    P->stats.cs2_audit_small = max_abs <= TDILITHIUM_TAU * 2 * DILITHIUM_ETA;
}

static int finalize(Party *P, const Candidate *cd, const Opened *o) {
    if (P->cfg.open_check == OPEN_CHECK_STRICT) {
        DilithiumCoeff *dec = calloc(MM_DECISION_COEFFS, sizeof(DilithiumCoeff));
        if (!dec) return -1;
        int dec_n = mm_build_decision_vector(P->A_ntt, P->t, o->z, cd->c, cd->attempt, cd->dcf_accept, dec);
        DilithiumCoeff w_view[DILITHIUM_PK_COEFFS];
        memcpy(w_view, cd->w, sizeof(w_view));
        if (P->fault_inject) {                 /* 仅自检使用：模拟一方视图分叉 */
            w_view[7] = dilithium_mod_q((int64_t)w_view[7] + 1);
        }
        OpenCheckItem items[] = {
            { "COM", cd->com, TDILITHIUM_COM_COEFFS },
            { "W", w_view, DILITHIUM_PK_COEFFS },
            { "Z", o->z, DILITHIUM_S_COEFFS },
            { "R", o->r, TDILITHIUM_R_COEFFS },
            { "DEC", dec, dec_n },
        };
        int ok = open_check_run(P, "DSign", cd->attempt, items, 5);
        free(dec);
        if (ok != 1) {
            P->terminal = ok < 0 ? TERM_CHANNEL_ERROR : TERM_OPEN_CHECK_FAILED;
            return -1;
        }
    }

    phase_begin(P, PH_VERIFY);
    int rc = -1;
    int encoded = mldsa44_encode_signature(cd->c_tilde, o->z, o->hint, P->sig);
    P->verify_ok = encoded && mldsa44_verify(P->pk, P->message, P->sig);
    sha3_256(P->sig_hash, P->sig, MLDSA_SIGNATURE_BYTES);
    P->stats.hint_ones = o->check.hint_ones;
    P->stats.accept_attempt = cd->attempt + 1;
    audit_cs2(P, cd, o);

    /* 两方各自组装、各自验证，最后交换 (verify, SHA3(sig)) 确认输出一致 */
    {
        uint8_t msg[36], peer[36];
        msg[0] = (uint8_t)P->verify_ok; msg[1] = msg[2] = msg[3] = 0;
        memcpy(msg + 4, P->sig_hash, 32);
        if (channel_exchange_fixed(&P->ch, TAG_FINAL, msg, peer, sizeof(msg)) != 0) {
            P->terminal = TERM_CHANNEL_ERROR;
            goto out;
        }
        if (!P->verify_ok) {
            P->terminal = TERM_VERIFY_FAILED;
        } else if (peer[0] != 1 || memcmp(peer + 4, P->sig_hash, 32) != 0) {
            plog(P, "对方的签名摘要或验证结果与本方不一致，fail-closed");
            P->terminal = TERM_PEER_DISAGREE;
        } else {
            P->terminal = TERM_SUCCESS;
            rc = 0;
        }
    }
    plog(P, "Verify：标准 %s 验证 %s；两方签名摘要%s",
         MLDSA_LEVEL_NAME, P->verify_ok ? "ACCEPT" : "REJECT",
         P->terminal == TERM_SUCCESS ? "一致" : "不一致或未确认");
out:
    phase_end(P, PH_VERIFY);
    return rc;
}

int sign_run(Party *P) {
    const int K = P->cfg.batch_size;
    Candidate *cands = calloc((size_t)K, sizeof(Candidate));
    Opened *opened = calloc(1, sizeof(Opened));
    SecureRandom rng;
    memset(&rng, 0, sizeof(rng));
    int rc = -1;
    if (!cands || !opened || secure_random_init(&rng, "tpm2-sign-nonce", P->sid, sizeof(P->sid)) != 0) goto out;

    plog(P, "DSign 开始：batch K=%d，pool L=%d（%s），open_check=%s",
         K, P->cfg.pool_size, pool_mode_name(P->cfg.pool_mode), open_check_mode_name(P->cfg.open_check));
    for (int a = 0;; a += K) {
        if (dcf_pool_ensure(P, a, K) != 0) goto out;
        P->stats.batches++;
        for (int p = 0; p < K; p++) {
            if (attempt_local(P, &cands[p], a + p, &rng) != 0) goto out;
        }
        if (dcf_rejects_batch(P, cands, K) != 0) goto out;
        for (int p = 0; p < K; p++) {
            if (!cands[p].dcf_accept) continue;
            int ok = open_and_check(P, &cands[p], opened);
            if (ok < 0) goto out;
            if (ok == 1) { rc = finalize(P, &cands[p], opened); goto out; }
        }
        plog(P, "批次 [%d,%d] 无可接受候选，进入下一批", a + 1, a + K);
        for (int p = 0; p < K; p++) {
            secure_bzero(cands[p].z_share, sizeof(cands[p].z_share));
            secure_bzero(cands[p].r_share, sizeof(cands[p].r_share));
        }
    }
out:
    secure_random_destroy(&rng);
    if (cands) secure_bzero(cands, (size_t)K * sizeof(Candidate));
    if (opened) secure_bzero(opened, sizeof(*opened));
    free(cands);
    free(opened);
    if (rc != 0 && P->terminal == TERM_NONE) P->terminal = TERM_CHANNEL_ERROR;
    return rc;
}
