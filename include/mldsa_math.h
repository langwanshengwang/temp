/*
 * mldsa_math.h —— ML-DSA 代数工具（纯函数，不访问网络与协议状态）。
 */
#ifndef MLDSA_MATH_H
#define MLDSA_MATH_H

#include "common.h"
#include "field.h"

#include <stdint.h>

typedef struct {
    int z_ok;
    int r0_ok;
    int ct0_ok;
    int hint_ok;
    int hint_ones;
    uint64_t r0_digest;
    uint64_t ct0_digest;
    uint64_t hint_digest;
} MldsaAttemptCheck;

/* 审计承诺矩阵 A^(1), A^(2) 的 NTT 缓存（由 digest(A) 确定性展开）。 */
typedef struct {
    int ready;
    DilithiumCoeff a1_ntt[TDILITHIUM_COMMIT_A1_POLYS][DILITHIUM_N];
    DilithiumCoeff a2_ntt[TDILITHIUM_COMMIT_A2_POLYS][DILITHIUM_N];
} CommitCache;

/* 决策向量长度：7 个标志 + r0 || c*t0 || h。 */
#define MM_DECISION_COEFFS (7 + 3 * DILITHIUM_PK_COEFFS)

void mm_poly_mul_challenge_acc(DilithiumCoeff acc[DILITHIUM_N],
                               const DilithiumCoeff c[DILITHIUM_N],
                               const DilithiumCoeff b[DILITHIUM_N]);
void mm_A_mul_svec(const DilithiumCoeff public_A_ntt[DILITHIUM_A_COEFFS],
                   const DilithiumCoeff z_s[DILITHIUM_S_COEFFS],
                   DilithiumCoeff out[DILITHIUM_PK_COEFFS]);
void mm_expand_A_ntt(const DilithiumCoeff A[DILITHIUM_A_COEFFS], DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS]);

int mm_vector_norm_below(const DilithiumCoeff *v, int n, int bound);
DilithiumCoeff mm_lowbits(DilithiumCoeff a);
int32_t mm_highbits(DilithiumCoeff a);

/* FIPS 204 Algorithm 7 中签名方侧的全部拒绝条件，并顺带算出 hint。 */
int mm_algorithm7_checks(const DilithiumCoeff public_A_ntt[DILITHIUM_A_COEFFS],
                         const DilithiumCoeff public_t[DILITHIUM_PK_COEFFS],
                         const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                         const DilithiumCoeff c[DILITHIUM_N],
                         DilithiumCoeff out_r0[DILITHIUM_PK_COEFFS],
                         DilithiumCoeff out_ct0[DILITHIUM_PK_COEFFS],
                         DilithiumCoeff out_hint[DILITHIUM_PK_COEFFS],
                         MldsaAttemptCheck *check);

/* 由本方视图重算 RejectS 决策向量，返回写入长度。 */
int mm_build_decision_vector(const DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS],
                             const DilithiumCoeff t[DILITHIUM_PK_COEFFS],
                             const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                             const DilithiumCoeff c[DILITHIUM_N],
                             int attempt, int dcf_accept,
                             DilithiumCoeff out[MM_DECISION_COEFFS]);

void mm_commit_cache_init(CommitCache *cache, uint64_t public_A_digest);
void mm_commitment(const CommitCache *cache,
                   const DilithiumCoeff r[TDILITHIUM_R_COEFFS],
                   const DilithiumCoeff w[DILITHIUM_PK_COEFFS],
                   DilithiumCoeff out_com[TDILITHIUM_COM_COEFFS]);

/* DKG：对 A_b 的 SHAKE256 承诺；t_b = A s1_b + s2_b。 */
void mm_commit_public_A(const unsigned char salt[DKG_COMMITMENT_SALT_BYTES],
                        const DilithiumCoeff A[DILITHIUM_A_COEFFS],
                        unsigned char out[DKG_COMMITMENT_BYTES]);
void mm_compute_t_share(const DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS],
                        const DilithiumCoeff s_vec[DILITHIUM_S_COEFFS],
                        const DilithiumCoeff e_vec[DILITHIUM_E_COEFFS],
                        DilithiumCoeff out_t[DILITHIUM_PK_COEFFS]);

#endif
