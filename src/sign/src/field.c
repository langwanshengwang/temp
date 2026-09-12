/*
 * field.c —— 模 q 基本运算、24 比特打包与日志摘要。
 */
#include "field.h"

#define FNV_OFFSET 1469598103934665603ULL
#define FNV_PRIME 1099511628211ULL

DilithiumCoeff dilithium_mod_q(int64_t x) {
    int64_t r = x % DILITHIUM_Q;
    if (r < 0) r += DILITHIUM_Q;
    return (DilithiumCoeff)r;
}

DilithiumCoeff dilithium_centered_to_mod_q(int32_t x) {
    return dilithium_mod_q((int64_t)x);
}

int32_t dilithium_mod_q_to_centered(DilithiumCoeff x) {
    int32_t r = (int32_t)dilithium_mod_q(x);
    if (r > DILITHIUM_Q / 2) r -= DILITHIUM_Q;
    return r;
}

uint64_t field_digest_bytes(const unsigned char *buf, size_t len) {
    uint64_t h = FNV_OFFSET;
    for (size_t i = 0; buf && i < len; i++) { h ^= buf[i]; h *= FNV_PRIME; }
    return h;
}

uint64_t field_digest_coeffs(const DilithiumCoeff *v, int n) {
    uint64_t h = FNV_OFFSET;
    for (int i = 0; i < n; i++) {
        uint32_t x = (uint32_t)v[i];
        for (int k = 0; k < 4; k++) { h ^= (unsigned char)(x & 0xffU); h *= FNV_PRIME; x >>= 8; }
    }
    return h;
}

size_t field_pack24_len(int count) { return (size_t)count * 3u; }

void field_pack24(unsigned char *out, const DilithiumCoeff *v, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t x = (uint32_t)dilithium_mod_q(v[i]);
        out[3 * i] = (unsigned char)(x & 0xff);
        out[3 * i + 1] = (unsigned char)((x >> 8) & 0xff);
        out[3 * i + 2] = (unsigned char)((x >> 16) & 0xff);
    }
}

int field_unpack24(DilithiumCoeff *v, const unsigned char *in, int count) {
    for (int i = 0; i < count; i++) {
        uint32_t x = (uint32_t)in[3 * i] | ((uint32_t)in[3 * i + 1] << 8) | ((uint32_t)in[3 * i + 2] << 16);
        if (x >= (uint32_t)DILITHIUM_Q) return -1;
        v[i] = (DilithiumCoeff)x;
    }
    return 0;
}

void field_add_vec(DilithiumCoeff *dst, const DilithiumCoeff *a, const DilithiumCoeff *b, int n) {
    for (int i = 0; i < n; i++) dst[i] = dilithium_mod_q((int64_t)a[i] + b[i]);
}
