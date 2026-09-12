/*
 * common.h —— 全工程共享的 ML-DSA 参数与基本类型（仅参数，不含任何协议状态）。
 *
 * 本工程是 2-of-2 门限 ML-DSA：两个对称参与方 P0、P1，没有协调方，
 * 也没有独立的 FSS 比较服务器——P_b 同时承担 DFSS 比较协议中的 C_b 角色。
 * 协议状态定义在 party.h；这里只放编译期常量，供 NTT、FIPS 202、ML-DSA 编码
 * 以及 src/dcf 下的 DFSS 适配器共同使用。
 */
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

/* 参与方数量与阈值：固定 2-of-2。Shamir 求值点 x_b = b + 1。 */
#define TWOPC_PARTY_COUNT 2
#define MAX_MEMBERS TWOPC_PARTY_COUNT

#ifndef MLDSA_MODE
#define MLDSA_MODE 44
#endif

#define DILITHIUM_N 256
#define DILITHIUM_Q 8380417
#define DILITHIUM_PUBLIC_SEED_BYTES 32
#define DKG_COMMITMENT_BYTES 32
#define DKG_COMMITMENT_SALT_BYTES 32

#if MLDSA_MODE == 44
#define MLDSA_LEVEL_NAME "ML-DSA-44"
#define DILITHIUM_K 4
#define DILITHIUM_L 4
#define DILITHIUM_ETA 2
#define TDILITHIUM_TAU 39
#define TDILITHIUM_GAMMA1 (1 << 17)
#define TDILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 88)
#define TDILITHIUM_OMEGA 80
#define MLDSA_CTILDE_BYTES 32
#define MLDSA_PUBLICKEY_BYTES 1312
#define MLDSA_SIGNATURE_BYTES 2420
#define MLDSA_Z_BITS 18
#define MLDSA_W1_BITS 6
#elif MLDSA_MODE == 65
#define MLDSA_LEVEL_NAME "ML-DSA-65"
#define DILITHIUM_K 6
#define DILITHIUM_L 5
#define DILITHIUM_ETA 4
#define TDILITHIUM_TAU 49
#define TDILITHIUM_GAMMA1 (1 << 19)
#define TDILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
#define TDILITHIUM_OMEGA 55
#define MLDSA_CTILDE_BYTES 48
#define MLDSA_PUBLICKEY_BYTES 1952
#define MLDSA_SIGNATURE_BYTES 3309
#define MLDSA_Z_BITS 20
#define MLDSA_W1_BITS 4
#elif MLDSA_MODE == 87
#define MLDSA_LEVEL_NAME "ML-DSA-87"
#define DILITHIUM_K 8
#define DILITHIUM_L 7
#define DILITHIUM_ETA 2
#define TDILITHIUM_TAU 60
#define TDILITHIUM_GAMMA1 (1 << 19)
#define TDILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
#define TDILITHIUM_OMEGA 75
#define MLDSA_CTILDE_BYTES 64
#define MLDSA_PUBLICKEY_BYTES 2592
#define MLDSA_SIGNATURE_BYTES 4627
#define MLDSA_Z_BITS 20
#define MLDSA_W1_BITS 4
#else
#error "MLDSA_MODE must be one of 44, 65, 87"
#endif

#define DILITHIUM_S_COEFFS (DILITHIUM_L * DILITHIUM_N)
#define DILITHIUM_E_COEFFS (DILITHIUM_K * DILITHIUM_N)
#define DILITHIUM_SK_POLYVEC_COUNT (DILITHIUM_L + DILITHIUM_K)
#define DILITHIUM_SK_COEFFS (DILITHIUM_SK_POLYVEC_COUNT * DILITHIUM_N)
#define DILITHIUM_PK_COEFFS (DILITHIUM_K * DILITHIUM_N)
#define DILITHIUM_A_COEFFS (DILITHIUM_K * DILITHIUM_L * DILITHIUM_N)
#define TDILITHIUM_GAMMA TDILITHIUM_GAMMA1
#define TDILITHIUM_BETA (TDILITHIUM_TAU * DILITHIUM_ETA)
#define TDILITHIUM_Z_BOUND (TDILITHIUM_GAMMA1 - TDILITHIUM_BETA)
#define TDILITHIUM_R0_BOUND (TDILITHIUM_GAMMA2 - TDILITHIUM_BETA)
#define TDILITHIUM_D 13

/* Historical names remain aliases so source code can be compiled per profile. */
#define MLDSA44_RHO_BYTES 32
#define MLDSA44_CTILDE_BYTES MLDSA_CTILDE_BYTES
#define MLDSA44_PUBLICKEY_BYTES MLDSA_PUBLICKEY_BYTES
#define MLDSA44_SIGNATURE_BYTES MLDSA_SIGNATURE_BYTES

/*
 * Parameters used by the Tang et al. modified Fiat-Shamir signature layer.
 * We keep the Dilithium-II ring dimension and q, and add the commitment
 * dimensions from Table 4 of the paper: (k1,k2)=(3,5).  The implementation
 * omits ShareRefresh but implements DKeyGen, DSign and Verify.
 */
#define TDILITHIUM_K1 3
#define TDILITHIUM_K2 5
#define TDILITHIUM_K3 (DILITHIUM_L + DILITHIUM_K)
#define TDILITHIUM_R_COEFFS (TDILITHIUM_K2 * DILITHIUM_N)
#define TDILITHIUM_COM_POLY_COUNT (TDILITHIUM_K1 + TDILITHIUM_K3)
#define TDILITHIUM_COM_COEFFS (TDILITHIUM_COM_POLY_COUNT * DILITHIUM_N)
/* A^(1) 的非 identity 多项式数与 A^(2) 的多项式数，用于 NTT 缓存。 */
#define TDILITHIUM_COMMIT_A1_POLYS (TDILITHIUM_K1 * (TDILITHIUM_K2 - TDILITHIUM_K1))
#define TDILITHIUM_COMMIT_A2_POLYS (TDILITHIUM_K3 * (TDILITHIUM_K2 - TDILITHIUM_K1))
/* 一次 DCF 批处理最多容纳的候选数 K（DFSS 适配器 ABI 也使用此上限）。 */
#define TDILITHIUM_DCF_BATCH_MAX 8

/* 模 q 系数统一用 int32_t 存放，规范表示为 [0,q)。 */
typedef int32_t DilithiumCoeff;

/* 严格打开一致性检查的压缩行数 m：单次误判概率约 q^{-m}。 */
#define OPEN_CHECK_ROWS 16

#endif
