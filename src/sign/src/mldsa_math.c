/*
 * mldsa_math.c —— ML-DSA 代数工具：挑战乘法、A·s、高低位分解、Algorithm 7 检查、
 * 阈值审计承诺 com，以及 DKG 中用到的 A_b 承诺与 t_b 计算。
 *
 * 这些函数是纯函数，两个参与方调用的是同一份代码，因此只要输入一致输出必然一致——
 * 这是后面“打开一致性检查”能够成立的前提。
 * 标注 mm_ 前缀的实现移植自原工程 threshold_sign.c / dilithium_dkg.c，算法未改动。
 */
#include "mldsa_math.h"

#include "fips202.h"
#include "ntt.h"
#include "secure_random.h"

#include <string.h>

#define TDILITHIUM_PARAM_TAG_A1 "TDILITHIUM-A1"
#define TDILITHIUM_PARAM_TAG_A2 "TDILITHIUM-A2"

void mm_poly_mul_challenge_acc(DilithiumCoeff acc[DILITHIUM_N],
                                          const DilithiumCoeff c[DILITHIUM_N],
                                          const DilithiumCoeff b[DILITHIUM_N]) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        int32_t ci = dilithium_mod_q_to_centered(c[i]);
        if (ci == 0) {
            continue;
        }
        for (int j = 0; j < DILITHIUM_N; j++) {
            int idx = i + j;
            int64_t prod = (int64_t)ci * (int64_t)b[j];
            if (idx >= DILITHIUM_N) {
                idx -= DILITHIUM_N;
                prod = -prod;
            }
            acc[idx] = dilithium_mod_q((int64_t)acc[idx] + prod);
        }
    }
}


static void derive_commitment_poly(uint64_t public_A_digest,
                                   const char *tag,
                                   int row,
                                   int col,
                                   DilithiumCoeff out[DILITHIUM_N]) {
    unsigned char seed[64];
    unsigned char buf[DILITHIUM_N * 4];
    size_t tag_len = strlen(tag);

    memset(seed, 0, sizeof(seed));
    memcpy(seed, tag, tag_len < 24 ? tag_len : 24);
    for (int i = 0; i < 8; i++) {
        seed[24 + i] = (unsigned char)((public_A_digest >> (8 * i)) & 0xffU);
    }
    seed[32] = (unsigned char)row;
    seed[33] = (unsigned char)col;

    shake256(buf, sizeof(buf), seed, sizeof(seed));
    for (int i = 0; i < DILITHIUM_N; i++) {
        uint32_t x = ((uint32_t)buf[4 * i]) |
                     ((uint32_t)buf[4 * i + 1] << 8) |
                     ((uint32_t)buf[4 * i + 2] << 16) |
                     ((uint32_t)buf[4 * i + 3] << 24);
        out[i] = (DilithiumCoeff)(x % DILITHIUM_Q);
    }
}


int mm_vector_norm_below(const DilithiumCoeff *v, int n, int bound) {
    for (int i = 0; i < n; i++) {
        int32_t centered = dilithium_mod_q_to_centered(v[i]);
        if (centered <= -bound || centered >= bound) {
            return 0;
        }
    }
    return 1;
}


static int32_t centered_mod_alpha(int32_t x, int32_t alpha) {
    int32_t r = x % alpha;
    if (r < 0) r += alpha;
    if (r > alpha / 2) r -= alpha;
    return r;
}

static void decompose_gamma2(DilithiumCoeff a, int32_t *a1, int32_t *a0) {
    int32_t r = dilithium_mod_q(a);
    int32_t alpha = 2 * TDILITHIUM_GAMMA2;
    int32_t r0 = centered_mod_alpha(r, alpha);
    int32_t high_src = r - r0;
    if (high_src == DILITHIUM_Q - 1) {
        *a1 = 0;
        *a0 = r0 - 1;
    } else {
        *a1 = high_src / alpha;
        *a0 = r0;
    }
}

DilithiumCoeff mm_lowbits(DilithiumCoeff a) {
    int32_t a1 = 0, a0 = 0;
    decompose_gamma2(a, &a1, &a0);
    (void)a1;
    return dilithium_centered_to_mod_q(a0);
}

int32_t mm_highbits(DilithiumCoeff a) {
    int32_t a1 = 0, a0 = 0;
    decompose_gamma2(a, &a1, &a0);
    (void)a0;
    return a1;
}

static DilithiumCoeff power2round_t0(DilithiumCoeff a) {
    int32_t r = dilithium_mod_q(a);
    int32_t t1 = (r + (1 << (TDILITHIUM_D - 1)) - 1) >> TDILITHIUM_D;
    int32_t t0 = r - (t1 << TDILITHIUM_D);
    return dilithium_centered_to_mod_q(t0);
}

void mm_A_mul_svec(const DilithiumCoeff public_A_ntt[DILITHIUM_A_COEFFS],
                               const DilithiumCoeff z_s[DILITHIUM_S_COEFFS],
                               DilithiumCoeff out[DILITHIUM_PK_COEFFS]) {
    DilithiumCoeff z_ntt[DILITHIUM_S_COEFFS];
    for (int col = 0; col < DILITHIUM_L; col++) {
        memcpy(&z_ntt[col * DILITHIUM_N], &z_s[col * DILITHIUM_N],
               sizeof(DilithiumCoeff) * DILITHIUM_N);
        dilithium_poly_ntt(&z_ntt[col * DILITHIUM_N]);
    }

    memset(out, 0, sizeof(DilithiumCoeff) * DILITHIUM_PK_COEFFS);
    for (int row = 0; row < DILITHIUM_K; row++) {
        DilithiumCoeff *dst = &out[row * DILITHIUM_N];
        for (int col = 0; col < DILITHIUM_L; col++) {
            dilithium_poly_pointwise_acc(dst,
                                         &public_A_ntt[(row * DILITHIUM_L + col) * DILITHIUM_N],
                                         &z_ntt[col * DILITHIUM_N]);
        }
        dilithium_poly_reduce32(dst);
        dilithium_poly_invntt(dst);
    }
}

static void compute_mldsa_w_minus_cs2(const DilithiumCoeff public_A_ntt[DILITHIUM_A_COEFFS],
                                      const DilithiumCoeff public_t[DILITHIUM_PK_COEFFS],
                                      const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                                      const DilithiumCoeff c[DILITHIUM_N],
                                      DilithiumCoeff out[DILITHIUM_PK_COEFFS]) {
    DilithiumCoeff ct[DILITHIUM_N];
    mm_A_mul_svec(public_A_ntt, z, out);
    for (int row = 0; row < DILITHIUM_K; row++) {
        memset(ct, 0, sizeof(ct));
        mm_poly_mul_challenge_acc(ct, c, &public_t[row * DILITHIUM_N]);
        for (int j = 0; j < DILITHIUM_N; j++) {
            out[row * DILITHIUM_N + j] = dilithium_mod_q((int64_t)out[row * DILITHIUM_N + j] - ct[j]);
        }
    }
}

static int make_hint_bit(DilithiumCoeff z, DilithiumCoeff r) {
    int32_t high_r = mm_highbits(r);
    DilithiumCoeff rz = dilithium_mod_q((int64_t)r + z);
    int32_t high_rz = mm_highbits(rz);
    return high_r != high_rz;
}

int mm_algorithm7_checks(const DilithiumCoeff public_A_ntt[DILITHIUM_A_COEFFS],
                                   const DilithiumCoeff public_t[DILITHIUM_PK_COEFFS],
                                   const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                                   const DilithiumCoeff c[DILITHIUM_N],
                                   DilithiumCoeff out_r0[DILITHIUM_PK_COEFFS],
                                   DilithiumCoeff out_ct0[DILITHIUM_PK_COEFFS],
                                   DilithiumCoeff out_hint[DILITHIUM_PK_COEFFS],
                                   MldsaAttemptCheck *check) {
    DilithiumCoeff w_minus_cs2[DILITHIUM_PK_COEFFS];
    DilithiumCoeff ct0_poly[DILITHIUM_N];

    memset(check, 0, sizeof(*check));
    check->z_ok = mm_vector_norm_below(z, DILITHIUM_S_COEFFS, TDILITHIUM_Z_BOUND);

    compute_mldsa_w_minus_cs2(public_A_ntt, public_t, z, c, w_minus_cs2);
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        out_r0[i] = mm_lowbits(w_minus_cs2[i]);
    }
    check->r0_ok = mm_vector_norm_below(out_r0, DILITHIUM_PK_COEFFS, TDILITHIUM_R0_BOUND);

    for (int row = 0; row < DILITHIUM_K; row++) {
        DilithiumCoeff t0[DILITHIUM_N];
        for (int j = 0; j < DILITHIUM_N; j++) {
            t0[j] = power2round_t0(public_t[row * DILITHIUM_N + j]);
        }
        memset(ct0_poly, 0, sizeof(ct0_poly));
        mm_poly_mul_challenge_acc(ct0_poly, c, t0);
        for (int j = 0; j < DILITHIUM_N; j++) {
            out_ct0[row * DILITHIUM_N + j] = ct0_poly[j];
        }
    }
    check->ct0_ok = mm_vector_norm_below(out_ct0, DILITHIUM_PK_COEFFS, TDILITHIUM_GAMMA2);

    int ones = 0;
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        DilithiumCoeff minus_ct0 = dilithium_mod_q(-(int64_t)out_ct0[i]);
        DilithiumCoeff r_plus_ct0 = dilithium_mod_q((int64_t)w_minus_cs2[i] + out_ct0[i]);
        int bit = make_hint_bit(minus_ct0, r_plus_ct0);
        out_hint[i] = bit ? 1 : 0;
        ones += bit;
    }
    check->hint_ones = ones;
    check->hint_ok = ones <= TDILITHIUM_OMEGA;
    check->r0_digest = field_digest_coeffs(out_r0, DILITHIUM_PK_COEFFS);
    check->ct0_digest = field_digest_coeffs(out_ct0, DILITHIUM_PK_COEFFS);
    check->hint_digest = field_digest_coeffs(out_hint, DILITHIUM_PK_COEFFS);
    return check->z_ok && check->r0_ok && check->ct0_ok && check->hint_ok;
}

void mm_commit_public_A(const unsigned char salt[DKG_COMMITMENT_SALT_BYTES],
                                   const DilithiumCoeff A[DILITHIUM_A_COEFFS],
                                   unsigned char out[DKG_COMMITMENT_BYTES]) {
    keccak_state st;
    static const unsigned char domain[] = "threshold-mldsa-dkg-A-commit-v2";
    shake256_init(&st);
    shake256_absorb(&st, domain, sizeof(domain) - 1);
    shake256_absorb(&st, salt, DKG_COMMITMENT_SALT_BYTES);
    for (int i = 0; i < DILITHIUM_A_COEFFS; i++) {
        uint32_t x = (uint32_t)dilithium_mod_q(A[i]);
        unsigned char b[4] = {
            (unsigned char)x, (unsigned char)(x >> 8),
            (unsigned char)(x >> 16), (unsigned char)(x >> 24)
        };
        shake256_absorb(&st, b, sizeof(b));
    }
    shake256_finalize(&st);
    shake256_squeeze(out, DKG_COMMITMENT_BYTES, &st);
    secure_bzero(&st, sizeof(st));
}

void mm_compute_t_share(const DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS],
                                           const DilithiumCoeff s_vec[DILITHIUM_S_COEFFS],
                                           const DilithiumCoeff e_vec[DILITHIUM_E_COEFFS],
                                           DilithiumCoeff out_t[DILITHIUM_PK_COEFFS]) {
    DilithiumCoeff s_ntt[DILITHIUM_S_COEFFS];
    for (int col = 0; col < DILITHIUM_L; col++) {
        memcpy(&s_ntt[col * DILITHIUM_N], &s_vec[col * DILITHIUM_N],
               sizeof(DilithiumCoeff) * DILITHIUM_N);
        dilithium_poly_ntt(&s_ntt[col * DILITHIUM_N]);
    }

    memset(out_t, 0, sizeof(DilithiumCoeff) * DILITHIUM_PK_COEFFS);

    for (int row = 0; row < DILITHIUM_K; row++) {
        DilithiumCoeff *t_poly = &out_t[row * DILITHIUM_N];

        for (int col = 0; col < DILITHIUM_L; col++) {
            dilithium_poly_pointwise_acc(t_poly,
                                         &A_ntt[(row * DILITHIUM_L + col) * DILITHIUM_N],
                                         &s_ntt[col * DILITHIUM_N]);
        }
        dilithium_poly_reduce32(t_poly);
        dilithium_poly_invntt(t_poly);

        const DilithiumCoeff *e_poly = &e_vec[row * DILITHIUM_N];
        for (int j = 0; j < DILITHIUM_N; j++) {
            t_poly[j] = dilithium_mod_q((int64_t)t_poly[j] + e_poly[j]);
        }
    }
}


/* ------------------------------------------------------------------ */
/* 阈值审计承诺 com = [I|A'] r + [0|A''] r + [0; w]                     */
/* ------------------------------------------------------------------ */

void mm_commit_cache_init(CommitCache *cache, uint64_t public_A_digest) {
    DilithiumCoeff tmp[DILITHIUM_N];
    int width = TDILITHIUM_K2 - TDILITHIUM_K1;
    for (int row = 0; row < TDILITHIUM_K1; row++) {
        for (int col = TDILITHIUM_K1; col < TDILITHIUM_K2; col++) {
            int idx = row * width + (col - TDILITHIUM_K1);
            derive_commitment_poly(public_A_digest, TDILITHIUM_PARAM_TAG_A1, row, col, tmp);
            memcpy(cache->a1_ntt[idx], tmp, sizeof(tmp));
            dilithium_poly_ntt(cache->a1_ntt[idx]);
        }
    }
    for (int row = 0; row < TDILITHIUM_K3; row++) {
        for (int col = TDILITHIUM_K1; col < TDILITHIUM_K2; col++) {
            int idx = row * width + (col - TDILITHIUM_K1);
            derive_commitment_poly(public_A_digest, TDILITHIUM_PARAM_TAG_A2, row, col, tmp);
            memcpy(cache->a2_ntt[idx], tmp, sizeof(tmp));
            dilithium_poly_ntt(cache->a2_ntt[idx]);
        }
    }
    cache->ready = 1;
}

void mm_commitment(const CommitCache *cache,
                   const DilithiumCoeff r[TDILITHIUM_R_COEFFS],
                   const DilithiumCoeff w[DILITHIUM_PK_COEFFS],
                   DilithiumCoeff out_com[TDILITHIUM_COM_COEFFS]) {
    int width = TDILITHIUM_K2 - TDILITHIUM_K1;
    DilithiumCoeff r_ntt[TDILITHIUM_K2 - TDILITHIUM_K1][DILITHIUM_N];
    for (int col = TDILITHIUM_K1; col < TDILITHIUM_K2; col++) {
        memcpy(r_ntt[col - TDILITHIUM_K1], &r[col * DILITHIUM_N], sizeof(DilithiumCoeff) * DILITHIUM_N);
        dilithium_poly_ntt(r_ntt[col - TDILITHIUM_K1]);
    }
    memset(out_com, 0, sizeof(DilithiumCoeff) * TDILITHIUM_COM_COEFFS);
    for (int row = 0; row < TDILITHIUM_K1; row++) {
        DilithiumCoeff *dst = &out_com[row * DILITHIUM_N];
        for (int col = TDILITHIUM_K1; col < TDILITHIUM_K2; col++) {
            int idx = row * width + (col - TDILITHIUM_K1);
            dilithium_poly_pointwise_acc(dst, cache->a1_ntt[idx], r_ntt[col - TDILITHIUM_K1]);
        }
        dilithium_poly_reduce32(dst);
        dilithium_poly_invntt(dst);
        for (int j = 0; j < DILITHIUM_N; j++) {
            dst[j] = dilithium_mod_q((int64_t)dst[j] + r[row * DILITHIUM_N + j]);
        }
    }
    for (int row = 0; row < TDILITHIUM_K3; row++) {
        DilithiumCoeff *dst = &out_com[(TDILITHIUM_K1 + row) * DILITHIUM_N];
        for (int col = TDILITHIUM_K1; col < TDILITHIUM_K2; col++) {
            int idx = row * width + (col - TDILITHIUM_K1);
            dilithium_poly_pointwise_acc(dst, cache->a2_ntt[idx], r_ntt[col - TDILITHIUM_K1]);
        }
        dilithium_poly_reduce32(dst);
        dilithium_poly_invntt(dst);
    }
    for (int row = 0; row < DILITHIUM_K; row++) {
        DilithiumCoeff *dst = &out_com[(TDILITHIUM_K1 + DILITHIUM_L + row) * DILITHIUM_N];
        for (int j = 0; j < DILITHIUM_N; j++) {
            dst[j] = dilithium_mod_q((int64_t)dst[j] + w[row * DILITHIUM_N + j]);
        }
    }
}

void mm_expand_A_ntt(const DilithiumCoeff A[DILITHIUM_A_COEFFS], DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS]) {
    for (int p = 0; p < DILITHIUM_A_COEFFS / DILITHIUM_N; p++) {
        memcpy(&A_ntt[p * DILITHIUM_N], &A[p * DILITHIUM_N], sizeof(DilithiumCoeff) * DILITHIUM_N);
        dilithium_poly_ntt(&A_ntt[p * DILITHIUM_N]);
    }
}

int mm_build_decision_vector(const DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS],
                             const DilithiumCoeff t[DILITHIUM_PK_COEFFS],
                             const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                             const DilithiumCoeff c[DILITHIUM_N],
                             int attempt, int dcf_accept,
                             DilithiumCoeff out[MM_DECISION_COEFFS]) {
    DilithiumCoeff r0[DILITHIUM_PK_COEFFS], ct0[DILITHIUM_PK_COEFFS], hint[DILITHIUM_PK_COEFFS];
    MldsaAttemptCheck check;
    int ok = mm_algorithm7_checks(A_ntt, t, z, c, r0, ct0, hint, &check);
    int idx = 0;
    out[idx++] = (DilithiumCoeff)(attempt + 1);
    out[idx++] = (DilithiumCoeff)(dcf_accept ? 1 : 0);
    out[idx++] = (DilithiumCoeff)(ok ? 1 : 0);
    out[idx++] = (DilithiumCoeff)(check.z_ok ? 1 : 0);
    out[idx++] = (DilithiumCoeff)(check.r0_ok ? 1 : 0);
    out[idx++] = (DilithiumCoeff)(check.ct0_ok ? 1 : 0);
    out[idx++] = (DilithiumCoeff)(check.hint_ok ? 1 : 0);
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) out[idx++] = dilithium_mod_q(r0[i]);
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) out[idx++] = dilithium_mod_q(ct0[i]);
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) out[idx++] = dilithium_mod_q(hint[i]);
    return idx;
}
