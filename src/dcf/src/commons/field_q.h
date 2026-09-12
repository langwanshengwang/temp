#pragma once

// ---------------------------------------------------------------------------
// ML-DSA / Dilithium prime field helpers.
//
//   q = 8380417 = 2^23 - 2^13 + 1   (prime, NTT-friendly)
//
// Two kinds of bit-lengths are relevant:
//   kShareBits = 23    canonical Z_q share in [0, q)
//   kLiftBits  = 24    no-wrap lift: 2q < 2^24, so x0+x1 never wraps mod 2^24
//
// The 24-bit no-wrap lift is used by comparison_zq.*:
// since 2q < 2^24, two Z_q shares zero-extended to 24 bits never wrap
// mod 2^24, allowing the field comparison to be expressed as a two-interval
// ring MIC ([0,t) ∪ [q,q+t)) without online Millionaire or B2A.
// ---------------------------------------------------------------------------

#include <cstdint>

namespace dfss {
namespace fieldq {

// The ML-DSA modulus.
constexpr uint64_t kQ = 8380417ULL;

// Canonical Z_q share is in [0, q), and q < 2^23.
constexpr int kShareBits = 23;

// Lift two Z_q shares into a 24-bit ring. Since 2q < 2^24,
// x0 + x1 never wraps in Z_{2^24}.
constexpr int kLiftBits = 24;

constexpr uint64_t kLiftDomain = 1ULL << kLiftBits;

static_assert(kQ < (1ULL << kShareBits), "q must fit in 23 bits");
static_assert(2 * kQ < kLiftDomain, "2q must fit in 24 bits");

// Reduce an arbitrary 64-bit value into the canonical range [0, q).
inline uint64_t reduceQ(uint64_t v) { return v % kQ; }

// (a + b) mod q, assuming a, b already in [0, q).
inline uint64_t addModQ(uint64_t a, uint64_t b) {
    uint64_t s = a + b;
    return s >= kQ ? s - kQ : s;
}

// (a - b) mod q, assuming a, b already in [0, q).
inline uint64_t subModQ(uint64_t a, uint64_t b) {
    return a >= b ? a - b : a + kQ - b;
}

// -a mod q, assuming a in [0, q).
inline uint64_t negModQ(uint64_t a) { return a == 0 ? 0 : kQ - a; }

}  // namespace fieldq
}  // namespace dfss
