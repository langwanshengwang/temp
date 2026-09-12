/*
 * candidate.h —— 一次签名尝试（候选）的本地状态。
 */
#ifndef CANDIDATE_H
#define CANDIDATE_H

#include "party.h"

typedef struct Candidate {
    int attempt;                                   /* 0-based；同时是所用 DCF 池项编号 */
    DilithiumCoeff com[TDILITHIUM_COM_COEFFS];     /* 双方一致的公开量 */
    DilithiumCoeff w[DILITHIUM_PK_COEFFS];
    DilithiumCoeff c[DILITHIUM_N];
    unsigned char c_tilde[MLDSA_CTILDE_BYTES];
    DilithiumCoeff z_share[DILITHIUM_S_COEFFS];    /* 本方私有 */
    DilithiumCoeff r_share[TDILITHIUM_R_COEFFS];
    uint32_t phi_self;
    uint32_t phi_peer;
    int dcf_accept;
} Candidate;

#endif
