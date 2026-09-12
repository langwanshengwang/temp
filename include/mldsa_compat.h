#ifndef MLDSA_COMPAT_H
#define MLDSA_COMPAT_H

#include "common.h"

#include <stddef.h>
#include <stdint.h>

/* Compatibility function names are retained; values follow MLDSA_MODE. */
#define MLDSA_T1_PACKED_BYTES ((DILITHIUM_PK_COEFFS * 10) / 8)
#define MLDSA_Z_PACKED_BYTES ((DILITHIUM_S_COEFFS * MLDSA_Z_BITS) / 8)
#define MLDSA_HINT_PACKED_BYTES (TDILITHIUM_OMEGA + DILITHIUM_K)
#define MLDSA_W1_PACKED_BYTES ((DILITHIUM_PK_COEFFS * MLDSA_W1_BITS) / 8)
#define MLDSA_W1_MODULUS ((DILITHIUM_Q - 1) / (2 * TDILITHIUM_GAMMA2))
#define MLDSA44_T1_PACKED_BYTES MLDSA_T1_PACKED_BYTES
#define MLDSA44_Z_PACKED_BYTES MLDSA_Z_PACKED_BYTES
#define MLDSA44_HINT_PACKED_BYTES MLDSA_HINT_PACKED_BYTES
#define MLDSA44_W1_PACKED_BYTES MLDSA_W1_PACKED_BYTES

void mldsa44_derive_rho_from_transcript(const DilithiumCoeff transcript_A[DILITHIUM_A_COEFFS],
                                         int session_id,
                                         const int online_ids[MAX_MEMBERS],
                                         int online_count,
                                         unsigned char rho[MLDSA44_RHO_BYTES]);

void mldsa44_expand_matrix_from_rho(const unsigned char rho[MLDSA44_RHO_BYTES],
                                    DilithiumCoeff out_A[DILITHIUM_A_COEFFS]);

void mldsa44_encode_public_key_from_t(const unsigned char rho[MLDSA44_RHO_BYTES],
                                      const DilithiumCoeff public_t[DILITHIUM_PK_COEFFS],
                                      unsigned char pk[MLDSA44_PUBLICKEY_BYTES]);

int mldsa44_decode_public_key(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                              unsigned char rho[MLDSA44_RHO_BYTES],
                              DilithiumCoeff out_t1[DILITHIUM_PK_COEFFS]);

void mldsa44_extract_w_from_compat_commitment(const DilithiumCoeff com[TDILITHIUM_COM_COEFFS],
                                              DilithiumCoeff out_w[DILITHIUM_PK_COEFFS]);

void mldsa44_challenge_from_public_key_message_w(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                                                 const char *message,
                                                 const DilithiumCoeff w[DILITHIUM_PK_COEFFS],
                                                 DilithiumCoeff out_c[DILITHIUM_N],
                                                 unsigned char out_c_tilde[MLDSA44_CTILDE_BYTES]);

int mldsa44_encode_signature(const unsigned char c_tilde[MLDSA44_CTILDE_BYTES],
                             const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                             const DilithiumCoeff hint[DILITHIUM_PK_COEFFS],
                             unsigned char sig[MLDSA44_SIGNATURE_BYTES]);

int mldsa44_verify(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                   const char *message,
                   const unsigned char sig[MLDSA44_SIGNATURE_BYTES]);

uint64_t mldsa44_digest_bytes(const unsigned char *buf, size_t len);

#endif
