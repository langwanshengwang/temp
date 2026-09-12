#include "mldsa_compat.h"

#include "field.h"
#include "fips202.h"
#include "ntt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MLDSA44_TR_BYTES 64
#define MLDSA44_MU_BYTES 64
#define MLDSA44_SAMPLE_BUF_BYTES 4096
#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL

static void store32_le(unsigned char out[4], uint32_t x) {
    out[0] = (unsigned char)(x & 0xffU);
    out[1] = (unsigned char)((x >> 8) & 0xffU);
    out[2] = (unsigned char)((x >> 16) & 0xffU);
    out[3] = (unsigned char)((x >> 24) & 0xffU);
}

static void absorb_coeffs_shake256(keccak_state *st, const DilithiumCoeff *v, int n) {
    unsigned char b[4];
    for (int i = 0; i < n; i++) {
        store32_le(b, (uint32_t)dilithium_mod_q(v[i]));
        shake256_absorb(st, b, sizeof(b));
    }
}

uint64_t mldsa44_digest_bytes(const unsigned char *buf, size_t len) {
    uint64_t h = FNV_OFFSET;
    if (!buf) return h;
    for (size_t i = 0; i < len; i++) {
        h ^= buf[i];
        h *= FNV_PRIME;
    }
    return h;
}

static void bitpack_set(unsigned char *out, size_t *bitpos, uint32_t v, unsigned int bits) {
    for (unsigned int b = 0; b < bits; b++) {
        if ((v >> b) & 1U) {
            out[*bitpos >> 3] |= (unsigned char)(1U << (*bitpos & 7U));
        }
        (*bitpos)++;
    }
}

static uint32_t bitpack_get(const unsigned char *in, size_t *bitpos, unsigned int bits) {
    uint32_t v = 0;
    for (unsigned int b = 0; b < bits; b++) {
        v |= (uint32_t)((in[*bitpos >> 3] >> (*bitpos & 7U)) & 1U) << b;
        (*bitpos)++;
    }
    return v;
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

static int32_t highbits_gamma2(DilithiumCoeff a) {
    int32_t a1 = 0, a0 = 0;
    decompose_gamma2(a, &a1, &a0);
    (void)a0;
    return a1;
}

static int32_t power2round_t1(DilithiumCoeff a) {
    int32_t r = dilithium_mod_q(a);
    return (r + (1 << (TDILITHIUM_D - 1)) - 1) >> TDILITHIUM_D;
}

static int vector_norm_is_below(const DilithiumCoeff *v, int n, int bound) {
    for (int i = 0; i < n; i++) {
        int32_t centered = dilithium_mod_q_to_centered(v[i]);
        if (centered <= -bound || centered >= bound) {
            return 0;
        }
    }
    return 1;
}

static void poly_mul_acc(DilithiumCoeff acc[DILITHIUM_N],
                         const DilithiumCoeff a[DILITHIUM_N],
                         const DilithiumCoeff b[DILITHIUM_N]) {
    dilithium_poly_mul_acc(acc, a, b);
}

static void poly_mul_sparse_challenge_acc(DilithiumCoeff acc[DILITHIUM_N],
                                          const DilithiumCoeff c[DILITHIUM_N],
                                          const DilithiumCoeff b[DILITHIUM_N]) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        int32_t ci = dilithium_mod_q_to_centered(c[i]);
        if (ci == 0) continue;
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

static const DilithiumCoeff *A_poly(const DilithiumCoeff A[DILITHIUM_A_COEFFS], int row, int col) {
    return &A[(row * DILITHIUM_L + col) * DILITHIUM_N];
}

static void compute_A_mul_svec(const DilithiumCoeff A[DILITHIUM_A_COEFFS],
                               const DilithiumCoeff z_s[DILITHIUM_S_COEFFS],
                               DilithiumCoeff out[DILITHIUM_PK_COEFFS]) {
    memset(out, 0, sizeof(DilithiumCoeff) * DILITHIUM_PK_COEFFS);
    for (int row = 0; row < DILITHIUM_K; row++) {
        DilithiumCoeff *dst = &out[row * DILITHIUM_N];
        for (int col = 0; col < DILITHIUM_L; col++) {
            poly_mul_acc(dst, A_poly(A, row, col), &z_s[col * DILITHIUM_N]);
        }
    }
}

static int use_hint_bit(int h, DilithiumCoeff r) {
    int32_t r1 = 0, r0 = 0;
    decompose_gamma2(r, &r1, &r0);
    if (!h) return r1;
    if (r0 > 0) return (r1 == MLDSA_W1_MODULUS - 1) ? 0 : r1 + 1;
    return (r1 == 0) ? MLDSA_W1_MODULUS - 1 : r1 - 1;
}

static void pack_t1(const DilithiumCoeff public_t[DILITHIUM_PK_COEFFS], unsigned char out[MLDSA44_T1_PACKED_BYTES]) {
    memset(out, 0, MLDSA44_T1_PACKED_BYTES);
    size_t bitpos = 0;
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        bitpack_set(out, &bitpos, (uint32_t)power2round_t1(public_t[i]), 10);
    }
}

static int unpack_t1(const unsigned char in[MLDSA44_T1_PACKED_BYTES], DilithiumCoeff out_t1[DILITHIUM_PK_COEFFS]) {
    size_t bitpos = 0;
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        uint32_t v = bitpack_get(in, &bitpos, 10);
        if (v > 1023U) return 0;
        out_t1[i] = (DilithiumCoeff)v;
    }
    return 1;
}

static int pack_z(const DilithiumCoeff z[DILITHIUM_S_COEFFS], unsigned char out[MLDSA44_Z_PACKED_BYTES]) {
    memset(out, 0, MLDSA44_Z_PACKED_BYTES);
    size_t bitpos = 0;
    for (int i = 0; i < DILITHIUM_S_COEFFS; i++) {
        int32_t zi = dilithium_mod_q_to_centered(z[i]);
        if (zi < -TDILITHIUM_GAMMA1 + 1 || zi > TDILITHIUM_GAMMA1) return 0;
        uint32_t enc = (uint32_t)(TDILITHIUM_GAMMA1 - zi);
        if (enc > (uint32_t)(2 * TDILITHIUM_GAMMA1 - 1)) return 0;
        bitpack_set(out, &bitpos, enc, MLDSA_Z_BITS);
    }
    return 1;
}

static int unpack_z(const unsigned char in[MLDSA44_Z_PACKED_BYTES], DilithiumCoeff out_z[DILITHIUM_S_COEFFS]) {
    size_t bitpos = 0;
    for (int i = 0; i < DILITHIUM_S_COEFFS; i++) {
        uint32_t enc = bitpack_get(in, &bitpos, MLDSA_Z_BITS);
        if (enc > (uint32_t)(2 * TDILITHIUM_GAMMA1 - 1)) return 0;
        int32_t zi = TDILITHIUM_GAMMA1 - (int32_t)enc;
        out_z[i] = dilithium_centered_to_mod_q(zi);
    }
    return 1;
}

static void pack_w1(const DilithiumCoeff w[DILITHIUM_PK_COEFFS], unsigned char out[MLDSA44_W1_PACKED_BYTES]) {
    memset(out, 0, MLDSA44_W1_PACKED_BYTES);
    size_t bitpos = 0;
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        uint32_t v = (uint32_t)highbits_gamma2(w[i]);
        bitpack_set(out, &bitpos, v, MLDSA_W1_BITS);
    }
}

static void pack_w1_from_highbits(const DilithiumCoeff w1[DILITHIUM_PK_COEFFS], unsigned char out[MLDSA44_W1_PACKED_BYTES]) {
    memset(out, 0, MLDSA44_W1_PACKED_BYTES);
    size_t bitpos = 0;
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        bitpack_set(out, &bitpos, (uint32_t)w1[i], MLDSA_W1_BITS);
    }
}

static int pack_hint(const DilithiumCoeff hint[DILITHIUM_PK_COEFFS], unsigned char out[MLDSA44_HINT_PACKED_BYTES]) {
    memset(out, 0, MLDSA44_HINT_PACKED_BYTES);
    unsigned int pos = 0;
    for (int row = 0; row < DILITHIUM_K; row++) {
        for (int j = 0; j < DILITHIUM_N; j++) {
            if (hint[row * DILITHIUM_N + j]) {
                if (pos >= TDILITHIUM_OMEGA) return 0;
                out[pos++] = (unsigned char)j;
            }
        }
        out[TDILITHIUM_OMEGA + row] = (unsigned char)pos;
    }
    return 1;
}

static int unpack_hint(const unsigned char in[MLDSA44_HINT_PACKED_BYTES], DilithiumCoeff out_hint[DILITHIUM_PK_COEFFS]) {
    memset(out_hint, 0, sizeof(DilithiumCoeff) * DILITHIUM_PK_COEFFS);
    unsigned int pos = 0;
    for (int row = 0; row < DILITHIUM_K; row++) {
        unsigned int end = in[TDILITHIUM_OMEGA + row];
        if (end < pos || end > TDILITHIUM_OMEGA) return 0;
        for (unsigned int j = pos; j < end; j++) {
            if (j > pos && in[j] <= in[j - 1]) return 0;
            out_hint[row * DILITHIUM_N + in[j]] = 1;
        }
        pos = end;
    }
    for (unsigned int j = pos; j < TDILITHIUM_OMEGA; j++) {
        if (in[j] != 0) return 0;
    }
    return 1;
}

void mldsa44_derive_rho_from_transcript(const DilithiumCoeff transcript_A[DILITHIUM_A_COEFFS],
                                         int session_id,
                                         const int online_ids[MAX_MEMBERS],
                                         int online_count,
                                         unsigned char rho[MLDSA44_RHO_BYTES]) {
    static const unsigned char domain[] = "threshold-mldsa-profiled-rho-v1";
    keccak_state st;
    unsigned char b[4];
    shake256_init(&st);
    shake256_absorb(&st, domain, sizeof(domain) - 1);
    store32_le(b, (uint32_t)session_id);
    shake256_absorb(&st, b, sizeof(b));
    store32_le(b, (uint32_t)online_count);
    shake256_absorb(&st, b, sizeof(b));
    for (int i = 0; i < online_count && i < MAX_MEMBERS; i++) {
        store32_le(b, (uint32_t)online_ids[i]);
        shake256_absorb(&st, b, sizeof(b));
    }
    absorb_coeffs_shake256(&st, transcript_A, DILITHIUM_A_COEFFS);
    shake256_finalize(&st);
    shake256_squeeze(rho, MLDSA44_RHO_BYTES, &st);
}

void mldsa44_expand_matrix_from_rho(const unsigned char rho[MLDSA44_RHO_BYTES],
                                    DilithiumCoeff out_A[DILITHIUM_A_COEFFS]) {
    unsigned char seed[MLDSA44_RHO_BYTES + 2];
    memcpy(seed, rho, MLDSA44_RHO_BYTES);
    for (int row = 0; row < DILITHIUM_K; row++) {
        for (int col = 0; col < DILITHIUM_L; col++) {
            seed[MLDSA44_RHO_BYTES] = (unsigned char)col;
            seed[MLDSA44_RHO_BYTES + 1] = (unsigned char)row;
            keccak_state st;
            unsigned char buf[MLDSA44_SAMPLE_BUF_BYTES];
            int filled = 0;
            shake128_init(&st);
            shake128_absorb(&st, seed, sizeof(seed));
            shake128_finalize(&st);
            while (filled < DILITHIUM_N) {
                shake128_squeeze(buf, sizeof(buf), &st);
                size_t pos = 0;
                while (pos + 3 <= sizeof(buf) && filled < DILITHIUM_N) {
                    uint32_t t = (uint32_t)buf[pos] | ((uint32_t)buf[pos + 1] << 8) | (((uint32_t)buf[pos + 2] & 0x7fU) << 16);
                    pos += 3;
                    if (t < DILITHIUM_Q) {
                        out_A[(row * DILITHIUM_L + col) * DILITHIUM_N + filled++] = (DilithiumCoeff)t;
                    }
                }
            }
        }
    }
}

void mldsa44_encode_public_key_from_t(const unsigned char rho[MLDSA44_RHO_BYTES],
                                      const DilithiumCoeff public_t[DILITHIUM_PK_COEFFS],
                                      unsigned char pk[MLDSA44_PUBLICKEY_BYTES]) {
    memcpy(pk, rho, MLDSA44_RHO_BYTES);
    pack_t1(public_t, pk + MLDSA44_RHO_BYTES);
}

int mldsa44_decode_public_key(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                              unsigned char rho[MLDSA44_RHO_BYTES],
                              DilithiumCoeff out_t1[DILITHIUM_PK_COEFFS]) {
    memcpy(rho, pk, MLDSA44_RHO_BYTES);
    return unpack_t1(pk + MLDSA44_RHO_BYTES, out_t1);
}

void mldsa44_extract_w_from_compat_commitment(const DilithiumCoeff com[TDILITHIUM_COM_COEFFS],
                                              DilithiumCoeff out_w[DILITHIUM_PK_COEFFS]) {
    memcpy(out_w,
           &com[(TDILITHIUM_K1 + DILITHIUM_L) * DILITHIUM_N],
           sizeof(DilithiumCoeff) * DILITHIUM_PK_COEFFS);
}

static void sample_in_ball(const unsigned char c_tilde[MLDSA44_CTILDE_BYTES], DilithiumCoeff out_c[DILITHIUM_N]) {
    unsigned char buf[1024];
    memset(out_c, 0, sizeof(DilithiumCoeff) * DILITHIUM_N);
    shake256(buf, sizeof(buf), c_tilde, MLDSA44_CTILDE_BYTES);
    uint64_t signs = 0;
    for (int i = 0; i < 8; i++) signs |= ((uint64_t)buf[i]) << (8 * i);
    int pos = 8;
    for (int i = DILITHIUM_N - TDILITHIUM_TAU; i < DILITHIUM_N; i++) {
        unsigned int b = 0;
        do {
            if (pos >= (int)sizeof(buf)) {
                unsigned char more[64];
                unsigned char ctr = (unsigned char)i;
                keccak_state st;
                shake256_init(&st);
                shake256_absorb(&st, c_tilde, MLDSA44_CTILDE_BYTES);
                shake256_absorb(&st, &ctr, 1);
                shake256_finalize(&st);
                shake256_squeeze(more, sizeof(more), &st);
                b = more[(unsigned int)i % sizeof(more)];
            } else {
                b = buf[pos++];
            }
        } while (b > (unsigned int)i);
        out_c[i] = out_c[b];
        out_c[b] = (signs & 1U) ? dilithium_centered_to_mod_q(-1) : dilithium_centered_to_mod_q(1);
        signs >>= 1;
    }
}

static void compute_tr_mu(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                          const char *message,
                          unsigned char mu[MLDSA44_MU_BYTES]) {
    unsigned char tr[MLDSA44_TR_BYTES];
    unsigned char m_prefix[2] = {0, 0};
    size_t msg_len = message ? strlen(message) : 0;
    shake256(tr, sizeof(tr), pk, MLDSA44_PUBLICKEY_BYTES);
    keccak_state st;
    shake256_init(&st);
    shake256_absorb(&st, tr, sizeof(tr));
    shake256_absorb(&st, m_prefix, sizeof(m_prefix));
    if (msg_len) shake256_absorb(&st, (const unsigned char *)message, msg_len);
    shake256_finalize(&st);
    shake256_squeeze(mu, MLDSA44_MU_BYTES, &st);
}

void mldsa44_challenge_from_public_key_message_w(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                                                 const char *message,
                                                 const DilithiumCoeff w[DILITHIUM_PK_COEFFS],
                                                 DilithiumCoeff out_c[DILITHIUM_N],
                                                 unsigned char out_c_tilde[MLDSA44_CTILDE_BYTES]) {
    unsigned char mu[MLDSA44_MU_BYTES];
    unsigned char w1[MLDSA44_W1_PACKED_BYTES];
    compute_tr_mu(pk, message, mu);
    pack_w1(w, w1);
    keccak_state st;
    shake256_init(&st);
    shake256_absorb(&st, mu, sizeof(mu));
    shake256_absorb(&st, w1, sizeof(w1));
    shake256_finalize(&st);
    shake256_squeeze(out_c_tilde, MLDSA44_CTILDE_BYTES, &st);
    sample_in_ball(out_c_tilde, out_c);
}

int mldsa44_encode_signature(const unsigned char c_tilde[MLDSA44_CTILDE_BYTES],
                             const DilithiumCoeff z[DILITHIUM_S_COEFFS],
                             const DilithiumCoeff hint[DILITHIUM_PK_COEFFS],
                             unsigned char sig[MLDSA44_SIGNATURE_BYTES]) {
    memcpy(sig, c_tilde, MLDSA44_CTILDE_BYTES);
    if (!pack_z(z, sig + MLDSA44_CTILDE_BYTES)) return 0;
    if (!pack_hint(hint, sig + MLDSA44_CTILDE_BYTES + MLDSA44_Z_PACKED_BYTES)) return 0;
    return 1;
}

int mldsa44_verify(const unsigned char pk[MLDSA44_PUBLICKEY_BYTES],
                   const char *message,
                   const unsigned char sig[MLDSA44_SIGNATURE_BYTES]) {
    unsigned char rho[MLDSA44_RHO_BYTES];
    DilithiumCoeff t1[DILITHIUM_PK_COEFFS];
    DilithiumCoeff A[DILITHIUM_A_COEFFS];
    DilithiumCoeff z[DILITHIUM_S_COEFFS];
    DilithiumCoeff c[DILITHIUM_N];
    DilithiumCoeff h[DILITHIUM_PK_COEFFS];
    DilithiumCoeff w[DILITHIUM_PK_COEFFS];
    DilithiumCoeff ct[DILITHIUM_N];
    DilithiumCoeff w1[DILITHIUM_PK_COEFFS];
    unsigned char mu[MLDSA44_MU_BYTES];
    unsigned char packed_w1[MLDSA44_W1_PACKED_BYTES];
    unsigned char expected[MLDSA44_CTILDE_BYTES];

    if (!mldsa44_decode_public_key(pk, rho, t1)) return 0;
    if (!unpack_z(sig + MLDSA44_CTILDE_BYTES, z)) return 0;
    if (!unpack_hint(sig + MLDSA44_CTILDE_BYTES + MLDSA44_Z_PACKED_BYTES, h)) return 0;
    if (!vector_norm_is_below(z, DILITHIUM_S_COEFFS, TDILITHIUM_Z_BOUND)) return 0;

    sample_in_ball(sig, c);
    mldsa44_expand_matrix_from_rho(rho, A);
    compute_A_mul_svec(A, z, w);
    for (int row = 0; row < DILITHIUM_K; row++) {
        memset(ct, 0, sizeof(ct));
        DilithiumCoeff t1_shift[DILITHIUM_N];
        for (int j = 0; j < DILITHIUM_N; j++) {
            t1_shift[j] = dilithium_mod_q((int64_t)t1[row * DILITHIUM_N + j] << TDILITHIUM_D);
        }
        poly_mul_sparse_challenge_acc(ct, c, t1_shift);
        for (int j = 0; j < DILITHIUM_N; j++) {
            w[row * DILITHIUM_N + j] = dilithium_mod_q((int64_t)w[row * DILITHIUM_N + j] - ct[j]);
        }
    }
    for (int i = 0; i < DILITHIUM_PK_COEFFS; i++) {
        w1[i] = (DilithiumCoeff)use_hint_bit(h[i] != 0, w[i]);
    }
    compute_tr_mu(pk, message, mu);
    pack_w1_from_highbits(w1, packed_w1);
    keccak_state st;
    shake256_init(&st);
    shake256_absorb(&st, mu, sizeof(mu));
    shake256_absorb(&st, packed_w1, sizeof(packed_w1));
    shake256_finalize(&st);
    shake256_squeeze(expected, sizeof(expected), &st);
    return memcmp(expected, sig, MLDSA44_CTILDE_BYTES) == 0;
}
