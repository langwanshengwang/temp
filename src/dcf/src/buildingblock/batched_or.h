#pragma once
#include <vector>

#include "commons/keypack.h"
#include "commons/types.h"

namespace dfss {

// batched=false changes only scheduling, never the exact OR predicate.
BatchedORMaterial batchedOrOffline(int party_id, int dim, int Bout,
                                   bool batched = true);
GroupElement batchedOrOnline(int party_id, const GroupElement* input,
                             const BatchedORMaterial& mat,
                             bool batched = true);
std::vector<GroupElement> batchedOrOnlineBatch(
    int party_id, const GroupElement* flattened_input,
    const std::vector<const BatchedORMaterial*>& materials,
    bool batched = true);
GroupElement batchedOrFull(int party_id, const GroupElement* input, int dim, int Bout);

}  // namespace dfss
