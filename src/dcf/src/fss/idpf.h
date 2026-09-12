#pragma once

#include <vector>

#include "commons/types.h"
#include "commons/group_element.h"
#include "commons/keypack.h"

namespace dfss {

// iDPF key generation with Boolean-shared target bits supplied by the caller.
// iDPF uses the ordinary pseudorandom GGM, not correlated GGM. (stable)
DPFKeyPack keyGeniDPF(int party_id, int Bin, int Bout,
                      const BooleanElement* alpha_bits,
                      const GroupElement* beta_per_level);

// Generate `count` independent iDPF keys in level-major batches. Targets are
// Boolean-shared, MSB-first rows of `Bin` bits. The construction is identical
// to keyGeniDPF, but all COTs and openings at a level are batched.
std::vector<DPFKeyPack> keyGeniDPFBatch(
    int party_id, int Bin, int Bout, const BooleanElement* alpha_bits,
    const GroupElement* beta_per_key, int count);

DPFKeyPack keyGeniDPFBit(int party_id, int Bin,
                         const BooleanElement* alpha_bits);

std::vector<GroupElement> evaliDPF(int party_id, GroupElement public_x,
                                   const DPFKeyPack& key);

}  // namespace dfss
