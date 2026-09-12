#pragma once

#include "commons/types.h"
#include "commons/keypack.h"

namespace dfss {

MICKeyPack micOffline(int party_id, int Bin, int Bout, GroupElement payload);

// Batched MIC key generation for targets that have already been
// Boolean-decomposed. `alpha_bits` holds `count` MSB-first rows.
std::vector<MICKeyPack> micOfflineBatchFromBits(
    int party_id, int Bin, int Bout, const BooleanElement* alpha_bits,
    const GroupElement* payloads, int count);

// Evaluate Phi(u) = payload * 1{rho < u} at a public endpoint without
// communication. `endpoint` lies in [0, 2^Bin].
GroupElement micPrefixEvalPublic(int party_id, uint64_t endpoint,
                                 const MICKeyPack& key);

// Evaluate two adjacent public prefix endpoints in one shared tree walk.
// `endpoint` must lie in [0, 2^Bin); on return `prefix` is Phi(endpoint)
// and `next_prefix` is Phi(endpoint + 1).  This is an evaluation-only
// optimization: it consumes no preprocessing and sends no messages.
void micPrefixEvalPublicAdjacent(int party_id, uint64_t endpoint,
                                 const MICKeyPack& key,
                                 GroupElement* prefix,
                                 GroupElement* next_prefix);

void mic(int party_id, GroupElement input, const PublicInterval* intervals,
         int interval_count, GroupElement* output, const MICKeyPack& key);

MICBooleanKeyPack micBooleanOffline(int party_id, int Bin);

void micBoolean(int party_id, GroupElement input,
                const PublicInterval* intervals, int interval_count,
                BooleanElement* output, const MICBooleanKeyPack& key);

// ---- Fast special-case paths (no dynamic allocation) --------------------
// Ring: single interval [0, threshold).  Works for any Bin < 32.
GroupElement micSingleIntervalFast(int party_id, GroupElement input,
                                   uint64_t threshold, const MICKeyPack& key);
BooleanElement micSingleIntervalBooleanFast(int party_id, GroupElement input,
                                            uint64_t threshold,
                                            const MICBooleanKeyPack& key);

// Field Z_q: two intervals [0, t) U [q, q+t) on 24-bit domain.
// input.bitsize must be 24 (the already-lifted share).
GroupElement micTwoIntervalZqFast(int party_id, GroupElement input,
                                  uint64_t threshold, const MICKeyPack& key);
BooleanElement micTwoIntervalZqBooleanFast(int party_id, GroupElement input,
                                           uint64_t threshold,
                                           const MICBooleanKeyPack& key);

// ---- Batch MIC: high-dimensional with single batch reconstruct -----------
//
// These functions take arrays of input shares, delta values (already
// reconstructed), and keys.  They perform local DCF/MIC evaluation on
// every dimension WITHOUT additional network communication.
//
// Cost: d × local AES/PrefixEval + zero socket round-trips.
//
// Precondition:
//   delta_values[i] has already been reconstructed from
//   input_shares[i] - key_list[i].rho_share via a single batched call.

void micSingleIntervalBatchFast(
    int party_id,
    GroupElement* output,
    const uint64_t* delta_values,
    const MICKeyPack* const* key_ptrs,
    const uint64_t* thresholds,
    int dim);

void micTwoIntervalZqBatchFast(
    int party_id,
    GroupElement* output,
    const uint64_t* delta_values,
    const MICKeyPack* const* key_ptrs,
    const uint64_t* thresholds,
    int dim);

}  // namespace dfss
