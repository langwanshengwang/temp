#pragma once
// ---------------------------------------------------------------------------
// Scheme 3: Hierarchical high/low split for high-dim Z_q DCF comparison
//
//   The high/low identity is evaluated on Boolean shares of a random 24-bit
//   mask, not on arithmetic input shares. This preserves carries and makes
//   the split a valid implementation of the lifted Z_q comparison.
//
// CLI: --bench highdim_comparison --bin 24 --high-bits 14 [--low-bits 10]
//      low_bits defaults to Bin - high_bits
// ---------------------------------------------------------------------------
#include <cstdint>
#include <vector>
#include "commons/keypack.h"
#include "commons/types.h"

namespace dfss {

struct HighDimExecutionOptions {
    bool endpoint_batched = true;
    bool or_batched = true;
};

HighDimScheme3KeyPack highDimScheme3Offline(
    int party_id, int dim, int Bin, int high_bits, int low_bits,
    const std::vector<uint64_t>& thresholds,
    const HighDimExecutionOptions& options = {});

GroupElement highDimScheme3Online(
    int party_id, const std::vector<GroupElement>& input_shares,
    const HighDimScheme3KeyPack& key);

std::vector<GroupElement> highDimScheme3OnlineBatch(
    int party_id,
    const std::vector<std::vector<GroupElement>>& input_shares,
    const std::vector<const HighDimScheme3KeyPack*>& keys);


HighDimMonolithicKeyPack highDimMonolithicOffline(
    int party_id, int dim, int Bin,
    const std::vector<uint64_t>& thresholds,
    const HighDimExecutionOptions& options = {});

GroupElement highDimMonolithicOnline(
    int party_id, const std::vector<GroupElement>& input_shares,
    const HighDimMonolithicKeyPack& key);

std::vector<GroupElement> highDimMonolithicOnlineBatch(
    int party_id,
    const std::vector<std::vector<GroupElement>>& input_shares,
    const std::vector<const HighDimMonolithicKeyPack*>& keys);

}  // namespace dfss
