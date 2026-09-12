#include "buildingblock/comparison_zq.h"

#include <cstdint>
#include <stdexcept>
#include <string>

#include "buildingblock/mic.h"
#include "commons/field_q.h"
#include "mpc/api.h"

namespace dfss {

namespace {

using fieldq::kLiftBits;
using fieldq::kQ;
using fieldq::kShareBits;

void validateFieldThreshold(uint64_t threshold, const char* caller) {
    if (threshold > kQ) {
        throw std::invalid_argument(std::string(caller) +
                                    " threshold must be in [0,q]");
    }
}

void validateFieldInput(const GroupElement& input, const char* caller) {
    if (input.bitsize != kShareBits) {
        throw std::invalid_argument(std::string(caller) +
                                    " input.bitsize must be 23 for Z_q shares");
    }
    if (input.value >= kQ) {
        throw std::invalid_argument(std::string(caller) +
                                    " input share must be canonical in [0,q)");
    }
}

void validateZqKey(const ComparisonKeyPack& key, const char* caller) {
    if (key.Bin != kLiftBits || key.MICKey.Bin != kLiftBits) {
        throw std::invalid_argument(std::string(caller) +
                                    " requires a 24-bit lifted MIC key");
    }
}

void validateZqBitKey(const ComparisonBitKeyPack& key, const char* caller) {
    if (key.Bin != kLiftBits || key.MICKey.Bin != kLiftBits) {
        throw std::invalid_argument(std::string(caller) +
                                    " requires a 24-bit lifted MIC key");
    }
}

}  // namespace

// ---- offline ---------------------------------------------------------------

ComparisonBitKeyPack comparisonBitZqOffline(int party_id) {
    ComparisonBitKeyPack key;
    key.Bin = kLiftBits;  // 24-bit iDPF tree
    key.MICKey = micBooleanOffline(party_id, kLiftBits);
    return key;
}

ComparisonKeyPack comparisonZqOffline(int party_id, int Bout,
                                      GroupElement payload) {
    if (payload.bitsize != Bout) {
        throw std::invalid_argument("comparisonZqOffline payload bit mismatch");
    }
    ComparisonKeyPack key;
    key.Bin = kLiftBits;
    key.Bout = Bout;
    key.MICKey = micOffline(party_id, kLiftBits, Bout, payload);
    return key;
}

// ---- online ----------------------------------------------------------------

BooleanElement comparisonBitZq(int party_id, GroupElement input,
                               uint64_t threshold,
                               const ComparisonBitKeyPack& key) {
    validateFieldInput(input, "comparisonBitZq");
    validateFieldThreshold(threshold, "comparisonBitZq");
    validateZqBitKey(key, "comparisonBitZq");

    if (threshold == 0) return 0;
    if (threshold == kQ)
        return static_cast<BooleanElement>(party_id == SERVER);

    // Zero-extend the 23-bit Z_q share to 24 bits.
    GroupElement lifted(input.value, kLiftBits);

    // Use the optimized two-interval MIC fast path.
    // Internally evaluates [0, threshold) and [kQ, kQ+threshold)
    // and XORs the results.
    return micTwoIntervalZqBooleanFast(party_id, lifted, threshold,
                                       key.MICKey);
}

GroupElement comparisonZq(int party_id, GroupElement input, uint64_t threshold,
                          const ComparisonKeyPack& key) {
    validateFieldInput(input, "comparisonZq");
    validateFieldThreshold(threshold, "comparisonZq");
    validateZqKey(key, "comparisonZq");

    if (threshold == 0) return GroupElement(0, key.Bout);
    if (threshold == kQ) return key.MICKey.payload_share;

    // Zero-extend the 23-bit Z_q share to 24 bits.
    GroupElement lifted(input.value, kLiftBits);

    // Use the optimized two-interval MIC fast path.
    // Internally evaluates [0, threshold) and [kQ, kQ+threshold)
    // and adds the results.
    return micTwoIntervalZqFast(party_id, lifted, threshold, key.MICKey);
}

}  // namespace dfss
