#ifndef DCF_DEALERLESS_BACKEND_H
#define DCF_DEALERLESS_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#include "common.h"

/*
 * Real dealerless semi-honest DCF backend ABI.
 *
 * The built-in research_reference code is an ideal-functionality adapter.  A
 * production/semi-honest experiment that wants to claim concrete dealerless DCF
 * must link a backend that implements the functions below with OT/VOLE/MPC/FSS
 * key-generation.  The ABI is intentionally party-local: C_b receives only its
 * own key material and local mask shares.  It must never receive K_{1-b}, r_{1-b}
 * or a reconstructed comparison point.
 *
 * The weak stub in src/dcf_dealerless_backend.c returns “unavailable”.  Link a
 * strong implementation from an audited backend to enable security_profile=
 * secure_external.
 */

#define DCF_DEALERLESS_BACKEND_ABI_VERSION 4u

/* ABI v4：结构体大小与 ML-DSA 参数集无关，按最大参数集（ML-DSA-87: L+K=15）定长，
 * 这样一份 libdfss_sign_adapter 可同时服务 44/65/87 三套协议实现；实际长度由 coeff_count 给出。 */
#define DCF_MAX_SK_COEFFS ((7 + 8) * 256)
#if DILITHIUM_SK_COEFFS > DCF_MAX_SK_COEFFS
#error "DCF_MAX_SK_COEFFS too small for this ML-DSA parameter set"
#endif

typedef struct {
    uint32_t abi_version;
    int helper_index;       /* 0 for C0, 1 for C1 */
    int self_node_id;
    int peer_node_id;
    char self_ip[64];
    int self_port;
    char peer_ip[64];
    int peer_port;
    /* Dedicated DFSS/EzPC base ports.  The DFSS stack also uses base+3,
     * base+50 and base+100, so these must not overlap sign protocol ports. */
    int self_dfss_port;
    int peer_dfss_port;
    int requester_id;
    int session_id;
    int coeff_count;
    int bound_B;
    int pool_item;
    int rejection_round;
} DcfDealerlessKeygenCtx;

typedef struct {
    uint32_t abi_version;
    int helper_index;
    int requester_id;
    int session_id;
    int coeff_count;
    int bound_B;
    int pool_item;
    int rejection_round;
    int worker_threads;        /* 0=由运行时决定，>0 为 OpenMP 并行线程数 */
    int candidates;            /* 候选数 K；key_bytes 含 K 个 token，public_u 为 K×coeff_count */
    const unsigned char *key_bytes; /* K 个 opaque party-local token，每个 key_len 字节 */
    size_t key_len;            /* 单个 token 长度 */
    const uint32_t *public_u;       /* K×coeff_count 个公开 u=x+r */
} DcfDealerlessEvalCtx;

typedef struct {
    unsigned char *key_bytes;       /* malloc-compatible opaque K_b; caller frees */
    size_t key_len;
    uint32_t local_mask_shares[DCF_MAX_SK_COEFFS]; /* private r_b[j]，前 coeff_count 项有效 */
    uint64_t key_digest;
    uint64_t local_mask_digest;
    uint64_t transcript_digest;
    uint64_t keygen_time_us;
} DcfDealerlessKeyShare;

#ifdef __cplusplus
extern "C" {
#endif

int dcf_dealerless_backend_available(void);
const char *dcf_dealerless_backend_name(void);

int dcf_dealerless_backend_keygen_share(const DcfDealerlessKeygenCtx *ctx,
                                        DcfDealerlessKeyShare *out);

/* Writes ctx->candidates additive failure shares and per-candidate digests.
 * key_bytes contains ctx->candidates opaque tokens, each key_len bytes. */
int dcf_dealerless_backend_eval_failure_shares(const DcfDealerlessEvalCtx *ctx,
                                               uint32_t *failure_shares,
                                               uint64_t *eval_digests);

void dcf_dealerless_backend_free_key_share(DcfDealerlessKeyShare *share);

#ifdef __cplusplus
}
#endif

#endif
