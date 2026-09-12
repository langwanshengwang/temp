#include "buildingblock/highdim_comparison.h"

#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "buildingblock/batched_or.h"
#include "buildingblock/mic.h"
#include "commons/field_q.h"
#include "mpc/api.h"
#include "mpc/secure_ops.h"

namespace dfss {
namespace {

using fieldq::kLiftBits;
using fieldq::kQ;
using fieldq::kShareBits;

constexpr int kEndpointCount = 4;

using ProfileClock = std::chrono::steady_clock;

struct ProfileCheckpoint {
    ProfileClock::time_point time;
    uint64_t sent = 0;
    uint64_t received = 0;
};

bool highDimProfileEnabled() {
    const char* setting = std::getenv("DFSS_HIGHDIM_PROFILE");
    return setting != nullptr && setting[0] != '\0' && setting[0] != '0';
}

ProfileCheckpoint takeProfileCheckpoint() {
    return {ProfileClock::now(), peer->bytesSent, peer->bytesReceived};
}

void emitProfileStage(int party_id, const char* phase, const char* stage,
                      const ProfileCheckpoint& before) {
    const ProfileCheckpoint after = takeProfileCheckpoint();
    const uint64_t elapsed_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            after.time - before.time).count());
    std::cerr << "DFSS_HIGHDIM_PROFILE,party="
              << (party_id == SERVER ? "server" : "client")
              << ",phase=" << phase
              << ",stage=" << stage
              << ",time_us=" << elapsed_us
              << ",sent_B=" << (after.sent - before.sent)
              << ",recv_B=" << (after.received - before.received) << '\n';
}

GroupElement publicOneShare(int party_id, int bits) {
    return GroupElement(party_id == SERVER ? 1 : 0, bits);
}

uint64_t shiftedEndpoint(uint64_t endpoint, uint64_t delta,
                         uint64_t domain) {
    return (endpoint + domain - delta) % domain;
}

void validateInputShare(const GroupElement& share) {
    if (share.bitsize != kShareBits || share.value >= kQ) {
        throw std::invalid_argument(
            "highDimScheme3Online requires canonical 23-bit Z_q shares");
    }
}

}  // namespace

// The random target is first sampled as a packed 24-bit arithmetic share and
// decomposed once.  Only then do we split its *Boolean* representation into
// high/low paths.  Splitting input arithmetic shares directly is incorrect:
// the independent low-share addition can carry into the high slice.
HighDimScheme3KeyPack highDimScheme3Offline(
    int party_id, int dim, int Bin, int high_bits, int low_bits,
    const std::vector<uint64_t>& thresholds,
    const HighDimExecutionOptions& options) {
    if (dim <= 0 || Bin != kLiftBits || high_bits <= 0 || low_bits <= 0 ||
        high_bits + low_bits != Bin) {
        throw std::invalid_argument(
            "highDimScheme3Offline requires a 24-bit high/low split");
    }
    if (static_cast<int>(thresholds.size()) != dim) {
        throw std::invalid_argument("highDimScheme3Offline: threshold size mismatch");
    }
    for (uint64_t threshold : thresholds) {
        if (threshold > kQ) {
            throw std::invalid_argument(
                "highDimScheme3Offline: threshold must lie in [0,q]");
        }
    }

    HighDimScheme3KeyPack key;
    key.dim = dim;
    key.Bin = Bin;
    key.Bout = 32;
    key.high_bits = high_bits;
    key.low_bits = low_bits;
    key.thresholds = thresholds;
    key.endpoint_batched = options.endpoint_batched;
    key.or_batched = options.or_batched;

    key.rho_shares.resize(dim, GroupElement(0, Bin));
    auto rng = secure_prng();
    for (int i = 0; i < dim; ++i) {
        key.rho_shares[i] = GroupElement(rng.get<uint64_t>(), Bin);
    }

    const bool profile = highDimProfileEnabled();
    ProfileCheckpoint checkpoint;
    if (profile) checkpoint = takeProfileCheckpoint();

    std::vector<BooleanElement> packed_bits(dim * Bin);
    BitDecBatch(party_id, key.rho_shares.data(), dim, Bin,
                packed_bits.data(), peer);
    if (profile) {
        emitProfileStage(party_id, "offline", "bitdec", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    std::vector<BooleanElement> high_bits_shared(dim * high_bits);
    std::vector<BooleanElement> low_bits_shared(dim * low_bits);
    for (int lane = 0; lane < dim; ++lane) {
        for (int bit = 0; bit < high_bits; ++bit) {
            high_bits_shared[lane * high_bits + bit] =
                packed_bits[lane * Bin + bit];
        }
        for (int bit = 0; bit < low_bits; ++bit) {
            low_bits_shared[lane * low_bits + bit] =
                packed_bits[lane * Bin + high_bits + bit];
        }
    }

    std::vector<GroupElement> payloads(dim, publicOneShare(party_id, key.Bout));
    key.high_prefix_keys = micOfflineBatchFromBits(
        party_id, high_bits, key.Bout, high_bits_shared.data(),
        payloads.data(), dim);
    if (profile) {
        emitProfileStage(party_id, "offline", "high_idpf_keygen", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    key.low_prefix_keys = micOfflineBatchFromBits(
        party_id, low_bits, key.Bout, low_bits_shared.data(),
        payloads.data(), dim);
    if (profile) {
        emitProfileStage(party_id, "offline", "low_idpf_keygen", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    // Phi_H(u_H+1)-Phi_H(u_H) must be multiplied with Phi_L(u_L) at each of
    // the four lifted Z_q interval endpoints.
    const int products = kEndpointCount * dim;
    key.product_a.resize(products, GroupElement(0, key.Bout));
    key.product_b.resize(products, GroupElement(0, key.Bout));
    key.product_c.resize(products, GroupElement(0, key.Bout));
    if (key.endpoint_batched) {
        beaver_mult_offline(party_id, key.product_a.data(),
                            key.product_b.data(), key.product_c.data(),
                            peer, products);
    } else {
        for (int index = 0; index < products; ++index) {
            beaver_mult_offline(party_id, &key.product_a[index],
                                &key.product_b[index], &key.product_c[index],
                                peer, 1);
        }
    }
    if (profile) {
        emitProfileStage(party_id, "offline", "beaver_material", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    key.or_material = batchedOrOffline(party_id, dim, key.Bout,
                                       key.or_batched);
    if (profile) {
        emitProfileStage(party_id, "offline", "secret_or_material", checkpoint);
    }
    return key;
}

GroupElement highDimScheme3Online(
    int party_id, const std::vector<GroupElement>& input_shares,
    const HighDimScheme3KeyPack& key) {
    const int dim = key.dim;
    const int h = key.high_bits;
    const int b = key.low_bits;
    const int Bout = key.Bout;
    const uint64_t domain = uint64_t(1) << key.Bin;
    const uint64_t low_mask = (uint64_t(1) << b) - 1;
    if (key.Bin != kLiftBits || h <= 0 || b <= 0 || h + b != key.Bin ||
        static_cast<int>(input_shares.size()) != dim ||
        static_cast<int>(key.rho_shares.size()) != dim ||
        static_cast<int>(key.high_prefix_keys.size()) != dim ||
        static_cast<int>(key.low_prefix_keys.size()) != dim ||
        static_cast<int>(key.thresholds.size()) != dim ||
        static_cast<int>(key.product_a.size()) != kEndpointCount * dim ||
        static_cast<int>(key.product_b.size()) != kEndpointCount * dim ||
        static_cast<int>(key.product_c.size()) != kEndpointCount * dim) {
        throw std::invalid_argument("highDimScheme3Online: malformed key or input");
    }

    // One packed opening masks the complete input sum; it reveals no more
    // about the Z_q input than the one-time random rho.
    std::vector<GroupElement> delta(dim, GroupElement(0, key.Bin));
    for (int i = 0; i < dim; ++i) {
        validateInputShare(input_shares[i]);
        delta[i] = GroupElement(input_shares[i].value, key.Bin) -
                   key.rho_shares[i];
    }
    const bool profile = highDimProfileEnabled();
    ProfileCheckpoint checkpoint;
    if (profile) checkpoint = takeProfileCheckpoint();
    reconstruct(dim, delta.data(), key.Bin);
    if (profile) {
        emitProfileStage(party_id, "online", "open_masked_delta", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    const int products = kEndpointCount * dim;
    std::vector<GroupElement> base(products, GroupElement(0, Bout));
    std::vector<GroupElement> equality(products, GroupElement(0, Bout));
    std::vector<GroupElement> low_prefix(products, GroupElement(0, Bout));
    std::vector<uint64_t> shifted(products);

#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (int lane = 0; lane < dim; ++lane) {
        const uint64_t threshold = key.thresholds[lane];
        const std::array<uint64_t, kEndpointCount> endpoints = {
            0, threshold, kQ, kQ + threshold};
        for (int endpoint_index = 0; endpoint_index < kEndpointCount;
             ++endpoint_index) {
            const int index = endpoint_index * dim + lane;
            const uint64_t u = shiftedEndpoint(endpoints[endpoint_index],
                                                delta[lane].value, domain);
            shifted[index] = u;
            const uint64_t u_high = u >> b;
            const uint64_t u_low = u & low_mask;
            GroupElement p_high(0, Bout);
            GroupElement p_high_next(0, Bout);
            micPrefixEvalPublicAdjacent(
                party_id, u_high, key.high_prefix_keys[lane], &p_high,
                &p_high_next);
            base[index] = p_high;
            equality[index] = p_high_next - p_high;
            low_prefix[index] = micPrefixEvalPublic(
                party_id, u_low, key.low_prefix_keys[lane]);
        }
    }
    if (profile) {
        emitProfileStage(party_id, "online", "local_prefix_eval", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    std::vector<GroupElement> product(products, GroupElement(0, Bout));
    if (key.endpoint_batched) {
        beaver_mult_online(party_id, equality.data(), low_prefix.data(),
                           key.product_a.data(), key.product_b.data(),
                           key.product_c.data(), product.data(), products, peer);
    } else {
        for (int index = 0; index < products; ++index) {
            beaver_mult_online(party_id, &equality[index], &low_prefix[index],
                               &key.product_a[index], &key.product_b[index],
                               &key.product_c[index], &product[index], 1, peer);
        }
    }
    if (profile) {
        emitProfileStage(party_id, "online", "beaver_products", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    for (int i = 0; i < products; ++i) product[i] = product[i] + base[i];

    const GroupElement one = publicOneShare(party_id, Bout);
    std::vector<GroupElement> failure(dim, GroupElement(0, Bout));
#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (int lane = 0; lane < dim; ++lane) {
        const uint64_t threshold = key.thresholds[lane];
        GroupElement accept(0, Bout);
        if (threshold == 0) {
            accept = GroupElement(0, Bout);
        } else if (threshold == kQ) {
            accept = one;
        } else {
            auto interval = [&](int left_index, int right_index) {
                const GroupElement& left = product[left_index * dim + lane];
                const GroupElement& right = product[right_index * dim + lane];
                return shifted[left_index * dim + lane] <
                       shifted[right_index * dim + lane]
                    ? right - left
                    : one - left + right;
            };
            accept = interval(0, 1) + interval(2, 3);
        }
        failure[lane] = one - accept;
    }
    GroupElement result = batchedOrOnline(party_id, failure.data(),
                                          key.or_material, key.or_batched);
    if (profile) {
        emitProfileStage(party_id, "online", "secret_or_tree", checkpoint);
    }
    return result;
}


std::vector<GroupElement> highDimScheme3OnlineBatch(
    int party_id,
    const std::vector<std::vector<GroupElement>>& input_shares,
    const std::vector<const HighDimScheme3KeyPack*>& keys) {
    const int candidates = static_cast<int>(keys.size());
    if (candidates <= 0 || static_cast<int>(input_shares.size()) != candidates ||
        keys[0] == nullptr) {
        throw std::invalid_argument(
            "highDimScheme3OnlineBatch: invalid arguments");
    }
    const int dim = keys[0]->dim;
    const int Bin = keys[0]->Bin;
    const int h = keys[0]->high_bits;
    const int b = keys[0]->low_bits;
    const int Bout = keys[0]->Bout;
    const uint64_t domain = uint64_t(1) << Bin;
    const uint64_t low_mask = (uint64_t(1) << b) - 1;
    const int lanes = candidates * dim;
    const int products_per_candidate = kEndpointCount * dim;
    const int products = candidates * products_per_candidate;

    std::vector<GroupElement> delta(lanes, GroupElement(0, Bin));
    for (int candidate = 0; candidate < candidates; ++candidate) {
        const HighDimScheme3KeyPack* key = keys[candidate];
        if (key == nullptr || key->dim != dim || key->Bin != kLiftBits ||
            key->Bout != Bout || key->high_bits != h || key->low_bits != b ||
            h <= 0 || b <= 0 || h + b != Bin ||
            static_cast<int>(input_shares[candidate].size()) != dim ||
            static_cast<int>(key->rho_shares.size()) != dim ||
            static_cast<int>(key->high_prefix_keys.size()) != dim ||
            static_cast<int>(key->low_prefix_keys.size()) != dim ||
            static_cast<int>(key->thresholds.size()) != dim ||
            static_cast<int>(key->product_a.size()) != products_per_candidate ||
            static_cast<int>(key->product_b.size()) != products_per_candidate ||
            static_cast<int>(key->product_c.size()) != products_per_candidate) {
            throw std::invalid_argument(
                "highDimScheme3OnlineBatch: inconsistent key or input");
        }
        for (int lane = 0; lane < dim; ++lane) {
            validateInputShare(input_shares[candidate][lane]);
            const int flat = candidate * dim + lane;
            delta[flat] = GroupElement(input_shares[candidate][lane].value,
                                       Bin) - key->rho_shares[lane];
        }
    }

    const bool profile = highDimProfileEnabled();
    ProfileCheckpoint checkpoint;
    if (profile) checkpoint = takeProfileCheckpoint();
    reconstruct(lanes, delta.data(), Bin);
    if (profile) {
        emitProfileStage(party_id, "online_batch", "open_masked_delta",
                         checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    std::vector<GroupElement> base(products, GroupElement(0, Bout));
    std::vector<GroupElement> equality(products, GroupElement(0, Bout));
    std::vector<GroupElement> low_prefix(products, GroupElement(0, Bout));
    std::vector<GroupElement> triple_a(products, GroupElement(0, Bout));
    std::vector<GroupElement> triple_b(products, GroupElement(0, Bout));
    std::vector<GroupElement> triple_c(products, GroupElement(0, Bout));
    std::vector<uint64_t> shifted(products);

#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (int flat_lane = 0; flat_lane < lanes; ++flat_lane) {
        const int candidate = flat_lane / dim;
        const int lane = flat_lane % dim;
        const HighDimScheme3KeyPack& key = *keys[candidate];
        const uint64_t threshold = key.thresholds[lane];
        const std::array<uint64_t, kEndpointCount> endpoints = {
            0, threshold, kQ, kQ + threshold};
        for (int endpoint_index = 0; endpoint_index < kEndpointCount;
             ++endpoint_index) {
            const int local_product = endpoint_index * dim + lane;
            const int product = candidate * products_per_candidate +
                                local_product;
            const uint64_t u = shiftedEndpoint(endpoints[endpoint_index],
                                                delta[flat_lane].value,
                                                domain);
            shifted[product] = u;
            const uint64_t u_high = u >> b;
            const uint64_t u_low = u & low_mask;
            GroupElement p_high(0, Bout);
            GroupElement p_high_next(0, Bout);
            micPrefixEvalPublicAdjacent(
                party_id, u_high, key.high_prefix_keys[lane], &p_high,
                &p_high_next);
            base[product] = p_high;
            equality[product] = p_high_next - p_high;
            low_prefix[product] = micPrefixEvalPublic(
                party_id, u_low, key.low_prefix_keys[lane]);
            triple_a[product] = key.product_a[local_product];
            triple_b[product] = key.product_b[local_product];
            triple_c[product] = key.product_c[local_product];
        }
    }
    if (profile) {
        emitProfileStage(party_id, "online_batch", "local_prefix_eval",
                         checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    std::vector<GroupElement> product(products, GroupElement(0, Bout));
    beaver_mult_online(party_id, equality.data(), low_prefix.data(),
                       triple_a.data(), triple_b.data(), triple_c.data(),
                       product.data(), products, peer);
    if (profile) {
        emitProfileStage(party_id, "online_batch", "beaver_products",
                         checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    for (int index = 0; index < products; ++index) {
        product[index] = product[index] + base[index];
    }

    const GroupElement one = publicOneShare(party_id, Bout);
    std::vector<GroupElement> failure(lanes, GroupElement(0, Bout));
#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
    for (int flat_lane = 0; flat_lane < lanes; ++flat_lane) {
        const int candidate = flat_lane / dim;
        const int lane = flat_lane % dim;
        const HighDimScheme3KeyPack& key = *keys[candidate];
        const int base_index = candidate * products_per_candidate;
        const uint64_t threshold = key.thresholds[lane];
        GroupElement accept(0, Bout);
        if (threshold == kQ) {
            accept = one;
        } else if (threshold != 0) {
            auto interval = [&](int left_index, int right_index) {
                const int left_pos = base_index + left_index * dim + lane;
                const int right_pos = base_index + right_index * dim + lane;
                return shifted[left_pos] < shifted[right_pos]
                    ? product[right_pos] - product[left_pos]
                    : one - product[left_pos] + product[right_pos];
            };
            accept = interval(0, 1) + interval(2, 3);
        }
        failure[flat_lane] = one - accept;
    }

    std::vector<const BatchedORMaterial*> or_materials(candidates);
    for (int candidate = 0; candidate < candidates; ++candidate) {
        or_materials[candidate] = &keys[candidate]->or_material;
    }
    std::vector<GroupElement> results = batchedOrOnlineBatch(
        party_id, failure.data(), or_materials, true);
    if (profile) {
        emitProfileStage(party_id, "online_batch", "secret_or_tree",
                         checkpoint);
    }
    return results;
}

// Full-depth reference path for the Table XI ablation. Inputs, lifted Z_q
// predicate, and exact OR match the hierarchical path; only the key shape
// changes to one 24-bit MIC/iDPF key per lane.
HighDimMonolithicKeyPack highDimMonolithicOffline(
    int party_id, int dim, int Bin, const std::vector<uint64_t>& thresholds,
    const HighDimExecutionOptions& options) {
    if (dim <= 0 || Bin != kLiftBits ||
        static_cast<int>(thresholds.size()) != dim) {
        throw std::invalid_argument("highDimMonolithicOffline: invalid dimensions");
    }
    for (uint64_t threshold : thresholds) {
        if (threshold > kQ) {
            throw std::invalid_argument(
                "highDimMonolithicOffline: threshold outside [0,q]");
        }
    }
    HighDimMonolithicKeyPack key;
    key.dim = dim; key.Bin = Bin; key.Bout = 32;
    key.thresholds = thresholds; key.or_batched = options.or_batched;
    const bool profile = highDimProfileEnabled();
    ProfileCheckpoint checkpoint;
    if (profile) checkpoint = takeProfileCheckpoint();

    // Generate every full-depth 24-bit target in one BitDec/iDPF batch.
    std::vector<GroupElement> rho_shares(dim, GroupElement(0, Bin));
    auto rng = secure_prng();
    for (int lane = 0; lane < dim; ++lane) {
        rho_shares[lane] = GroupElement(rng.get<uint64_t>(), Bin);
    }
    std::vector<BooleanElement> rho_bits(dim * Bin);
    BitDecBatch(party_id, rho_shares.data(), dim, Bin, rho_bits.data(), peer);
    std::vector<GroupElement> payloads(
        dim, publicOneShare(party_id, key.Bout));
    key.prefix_keys = micOfflineBatchFromBits(
        party_id, Bin, key.Bout, rho_bits.data(), payloads.data(), dim);
    for (int lane = 0; lane < dim; ++lane) {
        key.prefix_keys[lane].rho_share = rho_shares[lane];
    }
    if (profile) {
        emitProfileStage(party_id, "offline", "monolithic_idpf_keygen", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    key.or_material = batchedOrOffline(party_id, dim, key.Bout, key.or_batched);
    if (profile) emitProfileStage(party_id, "offline", "secret_or_material", checkpoint);
    return key;
}

GroupElement highDimMonolithicOnline(
    int party_id, const std::vector<GroupElement>& input_shares,
    const HighDimMonolithicKeyPack& key) {
    const int dim = key.dim;
    if (key.Bin != kLiftBits || dim <= 0 ||
        static_cast<int>(input_shares.size()) != dim ||
        static_cast<int>(key.prefix_keys.size()) != dim ||
        static_cast<int>(key.thresholds.size()) != dim) {
        throw std::invalid_argument("highDimMonolithicOnline: malformed key or input");
    }
    std::vector<GroupElement> delta(dim, GroupElement(0, key.Bin));
    std::vector<const MICKeyPack*> keys(dim);
    for (int lane = 0; lane < dim; ++lane) {
        validateInputShare(input_shares[lane]);
        delta[lane] = GroupElement(input_shares[lane].value, key.Bin) -
                      key.prefix_keys[lane].rho_share;
        keys[lane] = &key.prefix_keys[lane];
    }
    const bool profile = highDimProfileEnabled();
    ProfileCheckpoint checkpoint;
    if (profile) checkpoint = takeProfileCheckpoint();
    reconstruct(dim, delta.data(), key.Bin);
    if (profile) {
        emitProfileStage(party_id, "online", "open_masked_delta", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    std::vector<uint64_t> deltas(dim);
    for (int lane = 0; lane < dim; ++lane) deltas[lane] = delta[lane].value;
    std::vector<GroupElement> accept(dim, GroupElement(0, key.Bout));
    micTwoIntervalZqBatchFast(party_id, accept.data(), deltas.data(),
                              keys.data(), key.thresholds.data(), dim);
    if (profile) {
        emitProfileStage(party_id, "online", "local_prefix_eval", checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    const GroupElement one = publicOneShare(party_id, key.Bout);
    std::vector<GroupElement> failure(dim, GroupElement(0, key.Bout));
    for (int lane = 0; lane < dim; ++lane) failure[lane] = one - accept[lane];
    GroupElement result = batchedOrOnline(party_id, failure.data(),
                                          key.or_material, key.or_batched);
    if (profile) emitProfileStage(party_id, "online", "secret_or_tree", checkpoint);
    return result;
}

std::vector<GroupElement> highDimMonolithicOnlineBatch(
    int party_id,
    const std::vector<std::vector<GroupElement>>& input_shares,
    const std::vector<const HighDimMonolithicKeyPack*>& keys) {
    const int candidates = static_cast<int>(keys.size());
    if (candidates <= 0 || static_cast<int>(input_shares.size()) != candidates ||
        keys[0] == nullptr) {
        throw std::invalid_argument(
            "highDimMonolithicOnlineBatch: invalid arguments");
    }
    const int dim = keys[0]->dim;
    const int Bin = keys[0]->Bin;
    const int Bout = keys[0]->Bout;
    const int lanes = candidates * dim;
    std::vector<GroupElement> delta(lanes, GroupElement(0, Bin));
    std::vector<const MICKeyPack*> prefix_keys(lanes);
    std::vector<uint64_t> thresholds(lanes);
    for (int candidate = 0; candidate < candidates; ++candidate) {
        const HighDimMonolithicKeyPack* key = keys[candidate];
        if (key == nullptr || key->dim != dim || key->Bin != kLiftBits ||
            key->Bout != Bout ||
            static_cast<int>(input_shares[candidate].size()) != dim ||
            static_cast<int>(key->prefix_keys.size()) != dim ||
            static_cast<int>(key->thresholds.size()) != dim) {
            throw std::invalid_argument(
                "highDimMonolithicOnlineBatch: inconsistent key or input");
        }
        for (int lane = 0; lane < dim; ++lane) {
            validateInputShare(input_shares[candidate][lane]);
            const int flat = candidate * dim + lane;
            delta[flat] = GroupElement(input_shares[candidate][lane].value,
                                       Bin) - key->prefix_keys[lane].rho_share;
            prefix_keys[flat] = &key->prefix_keys[lane];
            thresholds[flat] = key->thresholds[lane];
        }
    }

    const bool profile = highDimProfileEnabled();
    ProfileCheckpoint checkpoint;
    if (profile) checkpoint = takeProfileCheckpoint();
    reconstruct(lanes, delta.data(), Bin);
    if (profile) {
        emitProfileStage(party_id, "online_batch", "open_masked_delta",
                         checkpoint);
        checkpoint = takeProfileCheckpoint();
    }
    std::vector<uint64_t> deltas(lanes);
    for (int lane = 0; lane < lanes; ++lane) deltas[lane] = delta[lane].value;
    std::vector<GroupElement> accept(lanes, GroupElement(0, Bout));
    micTwoIntervalZqBatchFast(party_id, accept.data(), deltas.data(),
                              prefix_keys.data(), thresholds.data(), lanes);
    if (profile) {
        emitProfileStage(party_id, "online_batch", "local_prefix_eval",
                         checkpoint);
        checkpoint = takeProfileCheckpoint();
    }

    const GroupElement one = publicOneShare(party_id, Bout);
    std::vector<GroupElement> failure(lanes, GroupElement(0, Bout));
    for (int lane = 0; lane < lanes; ++lane) {
        failure[lane] = one - accept[lane];
    }
    std::vector<const BatchedORMaterial*> or_materials(candidates);
    for (int candidate = 0; candidate < candidates; ++candidate) {
        or_materials[candidate] = &keys[candidate]->or_material;
    }
    std::vector<GroupElement> results = batchedOrOnlineBatch(
        party_id, failure.data(), or_materials, true);
    if (profile) {
        emitProfileStage(party_id, "online_batch", "secret_or_tree",
                         checkpoint);
    }
    return results;
}

}  // namespace dfss
