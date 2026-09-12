#pragma once

// ---------------------------------------------------------------------------
// Value-correct DCF/MIC-based comparison over Z_q, q = 8380417.
//
// This is NOT the original ring benchmark itself.  It is a Z_q extension that
// reuses the already-implemented 24-bit ring MIC/DCF machinery.
//
// Given additive Z_q shares x0, x1 in [0,q), define S = x0 + x1.
// Since 2q < 2^24, S does not wrap in the 24-bit ring. Therefore:
//
//   S = x       if x0 + x1 < q
//   S = x + q   otherwise
//
// Hence for a public threshold t in [0,q]:
//
//   x < t  iff  S in [0,t) union [q,q+t)
//
// The protocol:
//   1. Treat each 23-bit canonical Z_q share as a 24-bit ring share.
//   2. Use one 24-bit MIC key.
//   3. Evaluate two public intervals [0,t) and [q,q+t).
//   4. Add/XOR the two interval outputs.
//
// No online Millionaire, no B2A — the offline phase generates a standard
// 24-bit iDPF key via the existing dealerless DPF/iDPF machinery, and the
// online cost is one masked opening plus local AES evaluations, matching
// the ring path's structure.
//
// Key constraints:
//   - Each key is one-time-use (the random mask rho is freshly sampled).
//   - Two-party semi-honest model with public threshold.
// ---------------------------------------------------------------------------

#include "commons/keypack.h"
#include "commons/types.h"

namespace dfss {

// Offline key generation. Bin is fixed to fieldq::kLiftBits (24).
ComparisonBitKeyPack comparisonBitZqOffline(int party_id);
ComparisonKeyPack comparisonZqOffline(int party_id, int Bout,
                                      GroupElement payload);

// Online evaluation. `input` carries Z_q shares (input.bitsize must equal 23;
// input.value in [0, q)). `threshold` is public in [0, q].
BooleanElement comparisonBitZq(int party_id, GroupElement input,
                               uint64_t threshold,
                               const ComparisonBitKeyPack& key);

GroupElement comparisonZq(int party_id, GroupElement input, uint64_t threshold,
                          const ComparisonKeyPack& key);

}  // namespace dfss
