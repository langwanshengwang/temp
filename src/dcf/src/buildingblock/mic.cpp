#include "buildingblock/mic.h"

#include <algorithm>
#include <stdexcept>
#include <sys/socket.h>
#include <unordered_map>
#include <vector>

#include "mpc/api.h"
#include "fss/idpf.h"
#include "fss/fss_wrapper.h"
#include "fss/internal/ggm.h"
#include "fss/internal/payload_conversion.h"

namespace dfss {

namespace {

uint64_t prefixStateKey(int level, uint64_t prefix) {
    return (static_cast<uint64_t>(level) << 32) | prefix;
}

BooleanElement publicBooleanShare(int party_id, BooleanElement value) {
    return party_id == SERVER ? static_cast<BooleanElement>(value & 1) : 0;
}

BooleanElement blockLsb(const osuCrypto::block& input) {
    return _mm_cvtsi128_si64x(input) & 1;
}

GroupElement evalPrefixPayload(int party_id, const DPFKeyPack& key,
                               const GroupElement& root_payload_cw,
                               int prefix_level, osuCrypto::block node,
                               BooleanElement control_bit) {
    const osuCrypto::block label =
        internal::setBlockLsb(node, static_cast<osuCrypto::u8>(control_bit));
    const uint64_t converted_value =
        internal::convertPayload_iDPF(key.Bout, label);
    GroupElement converted(converted_value, key.Bout);
    const GroupElement& cw =
        prefix_level == 0 ? root_payload_cw : key.g[prefix_level - 1];
    GroupElement local_output =
        converted + cw * static_cast<uint64_t>(control_bit);
    return party_id == SERVER ? local_output : -local_output;
}

struct PrefixEvalState {
    osuCrypto::block node = osuCrypto::ZeroBlock;
    BooleanElement control_bit = 0;
    GroupElement prefix_sum;
    int sign_count = 0;
    BooleanElement previous_direction = 0;
};

struct PrefixEvalBitState {
    osuCrypto::block node = osuCrypto::ZeroBlock;
    BooleanElement control_bit = 0;
    BooleanElement prefix_xor = 0;
    BooleanElement previous_direction = 0;
};

std::unordered_map<uint64_t, GroupElement> evalPrefixBoundaries(
    int party_id, const DPFKeyPack& key, const GroupElement& root_payload_cw,
    GroupElement payload_share, const std::vector<uint64_t>& endpoints) {
    if (key.Bin >= 32) {
        throw std::invalid_argument("MIC prefix evaluation supports Bin < 32");
    }
    const int n = key.Bin;
    const uint64_t domain = uint64_t(1) << n;
    std::vector<uint64_t> sorted = endpoints;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::unordered_map<uint64_t, PrefixEvalState> memo;
    PrefixEvalState root;
    root.node = key.k[0];
    root.control_bit = static_cast<BooleanElement>(party_id - SERVER);
    root.prefix_sum = GroupElement(0, key.Bout);
    memo[prefixStateKey(0, 0)] = root;

    std::unordered_map<uint64_t, GroupElement> result;
    osuCrypto::AES aes;
    // Endpoints are prefix boundaries. For endpoint t, traverse to t-1 and
    // aggregate the iDPF prefix outputs encountered by the binary path.
    for (uint64_t endpoint : sorted) {
        if (endpoint == 0) {
            result[endpoint] = GroupElement(0, key.Bout);
            continue;
        }
        if (endpoint == domain) {
            result[endpoint] = payload_share;
            continue;
        }
        if (endpoint > domain) {
            throw std::invalid_argument("MIC endpoint outside domain");
        }

        const uint64_t phi = endpoint - 1;
        int cached_level = 0;
        uint64_t cached_prefix = 0;
        for (int level = n; level >= 0; level--) {
            const uint64_t prefix =
                level == 0 ? 0 : (phi >> (n - level));
            if (memo.find(prefixStateKey(level, prefix)) != memo.end()) {
                cached_level = level;
                cached_prefix = prefix;
                break;
            }
        }

        PrefixEvalState state = memo[prefixStateKey(cached_level,
                                                    cached_prefix)];
        for (int level = cached_level; level < n; level++) {
            const BooleanElement direction =
                static_cast<BooleanElement>((phi >> (n - 1 - level)) & 1);
            if (direction != state.previous_direction) {
                GroupElement prefix_output = evalPrefixPayload(
                    party_id, key, root_payload_cw, level, state.node,
                    state.control_bit);
                state.prefix_sum =
                    (state.sign_count % 2 == 0)
                        ? state.prefix_sum + prefix_output
                        : state.prefix_sum - prefix_output;
                state.sign_count++;
            }

            // The path direction is public after opening the one-time mask,
            // so expanding the unused GGM child is pure redundant work.
            aes.setKey(state.node);
            const osuCrypto::block child = aes.ecbEncBlock(
                direction == 0 ? osuCrypto::ZeroBlock : osuCrypto::OneBlock);
            const osuCrypto::block level_cw = key.k[level + 1];
            const BooleanElement level_tau = key.v[2 * level + direction];
            if (state.control_bit == static_cast<BooleanElement>(1)) {
                state.node = child ^ level_cw;
                state.control_bit = blockLsb(child) ^ level_tau;
            } else {
                state.node = child;
                state.control_bit = blockLsb(child);
            }
            state.previous_direction = direction;

            const uint64_t next_prefix =
                level + 1 == 0 ? 0 : (phi >> (n - (level + 1)));
            memo[prefixStateKey(level + 1, next_prefix)] = state;
        }

        if ((phi & 1) == 0) {
            GroupElement leaf_output = evalPrefixPayload(
                party_id, key, root_payload_cw, n, state.node,
                state.control_bit);
            state.prefix_sum =
                (state.sign_count % 2 == 0)
                    ? state.prefix_sum + leaf_output
                    : state.prefix_sum - leaf_output;
        }
        result[endpoint] = state.prefix_sum;
    }
    return result;
}

std::unordered_map<uint64_t, BooleanElement> evalPrefixBoundariesBoolean(
    int party_id, const DPFKeyPack& key,
    const std::vector<uint64_t>& endpoints) {
    if (key.Bin >= 32) {
        throw std::invalid_argument(
            "MIC Boolean prefix evaluation supports Bin < 32");
    }
    const int n = key.Bin;
    const uint64_t domain = uint64_t(1) << n;
    std::vector<uint64_t> sorted = endpoints;
    std::sort(sorted.begin(), sorted.end());
    sorted.erase(std::unique(sorted.begin(), sorted.end()), sorted.end());

    std::unordered_map<uint64_t, PrefixEvalBitState> memo;
    PrefixEvalBitState root;
    root.node = key.k[0];
    root.control_bit = static_cast<BooleanElement>(party_id - SERVER);
    root.prefix_xor = 0;
    memo[prefixStateKey(0, 0)] = root;

    std::unordered_map<uint64_t, BooleanElement> result;
    osuCrypto::AES aes;
    for (uint64_t endpoint : sorted) {
        if (endpoint == 0) {
            result[endpoint] = 0;
            continue;
        }
        if (endpoint == domain) {
            result[endpoint] = publicBooleanShare(party_id, 1);
            continue;
        }
        if (endpoint > domain) {
            throw std::invalid_argument("MIC Boolean endpoint outside domain");
        }

        const uint64_t phi = endpoint - 1;
        int cached_level = 0;
        uint64_t cached_prefix = 0;
        for (int level = n; level >= 0; level--) {
            const uint64_t prefix =
                level == 0 ? 0 : (phi >> (n - level));
            if (memo.find(prefixStateKey(level, prefix)) != memo.end()) {
                cached_level = level;
                cached_prefix = prefix;
                break;
            }
        }

        PrefixEvalBitState state =
            memo[prefixStateKey(cached_level, cached_prefix)];
        for (int level = cached_level; level < n; level++) {
            const BooleanElement direction =
                static_cast<BooleanElement>((phi >> (n - 1 - level)) & 1);
            if (direction != state.previous_direction) {
                state.prefix_xor ^= state.control_bit;
            }

            aes.setKey(state.node);
            const osuCrypto::block child = aes.ecbEncBlock(
                direction == 0 ? osuCrypto::ZeroBlock : osuCrypto::OneBlock);
            const osuCrypto::block level_cw = key.k[level + 1];
            const BooleanElement level_tau = key.v[2 * level + direction];
            if (state.control_bit == static_cast<BooleanElement>(1)) {
                state.node = child ^ level_cw;
                state.control_bit = blockLsb(child) ^ level_tau;
            } else {
                state.node = child;
                state.control_bit = blockLsb(child);
            }
            state.previous_direction = direction;

            const uint64_t next_prefix =
                level + 1 == 0 ? 0 : (phi >> (n - (level + 1)));
            memo[prefixStateKey(level + 1, next_prefix)] = state;
        }

        if ((phi & 1) == 0) {
            state.prefix_xor ^= state.control_bit;
        }
        result[endpoint] = static_cast<BooleanElement>(state.prefix_xor & 1);
    }
    return result;
}

void micWithDeltaValue(int party_id, uint64_t delta_value,
                       const PublicInterval* intervals, int interval_count,
                       GroupElement* output, const MICKeyPack& key) {
    if (key.Bin <= 0 || key.Bin >= 32) {
        throw std::invalid_argument("mic requires 0 < Bin < 32");
    }
    const uint64_t domain = uint64_t(1) << key.Bin;
    delta_value %= domain;

    std::vector<uint64_t> shifted_left(interval_count, 0);
    std::vector<uint64_t> shifted_right(interval_count, 0);
    std::vector<uint64_t> lengths(interval_count, 0);
    std::vector<uint64_t> endpoints;

    for (int i = 0; i < interval_count; i++) {
        if (intervals[i].left > intervals[i].right ||
            intervals[i].right > domain) {
            throw std::invalid_argument(
                "mic interval must satisfy 0 <= left <= right <= 2^Bin");
        }
        const uint64_t length = intervals[i].right - intervals[i].left;
        lengths[i] = length;
        if (length == 0 || length == domain) {
            continue;
        }
        shifted_left[i] = (intervals[i].left + domain - delta_value) % domain;
        shifted_right[i] =
            (intervals[i].right % domain + domain - delta_value) % domain;
        endpoints.push_back(shifted_left[i]);
        endpoints.push_back(shifted_right[i]);
    }

    std::unordered_map<uint64_t, GroupElement> prefix_values =
        evalPrefixBoundaries(party_id, key.iDPFKey, key.root_payload_cw,
                             key.payload_share, endpoints);

    for (int i = 0; i < interval_count; i++) {
        if (lengths[i] == 0) {
            output[i] = GroupElement(0, key.Bout);
        } else if (lengths[i] == domain) {
            output[i] = key.payload_share;
        } else if (shifted_left[i] < shifted_right[i]) {
            output[i] =
                prefix_values[shifted_right[i]] - prefix_values[shifted_left[i]];
        } else {
            output[i] = key.payload_share - prefix_values[shifted_left[i]] +
                        prefix_values[shifted_right[i]];
        }
    }
}

void micBooleanWithDeltaValue(int party_id, uint64_t delta_value,
                              const PublicInterval* intervals,
                              int interval_count, BooleanElement* output,
                              const MICBooleanKeyPack& key) {
    if (key.Bin <= 0 || key.Bin >= 32) {
        throw std::invalid_argument("mic_boolean requires 0 < Bin < 32");
    }
    const uint64_t domain = uint64_t(1) << key.Bin;
    delta_value %= domain;

    std::vector<uint64_t> shifted_left(interval_count, 0);
    std::vector<uint64_t> shifted_right(interval_count, 0);
    std::vector<uint64_t> lengths(interval_count, 0);
    std::vector<uint64_t> endpoints;

    for (int i = 0; i < interval_count; i++) {
        if (intervals[i].left > intervals[i].right ||
            intervals[i].right > domain) {
            throw std::invalid_argument(
                "mic_boolean interval must satisfy 0 <= left <= right <= 2^Bin");
        }
        const uint64_t length = intervals[i].right - intervals[i].left;
        lengths[i] = length;
        if (length == 0 || length == domain) {
            continue;
        }
        shifted_left[i] = (intervals[i].left + domain - delta_value) % domain;
        shifted_right[i] =
            (intervals[i].right % domain + domain - delta_value) % domain;
        endpoints.push_back(shifted_left[i]);
        endpoints.push_back(shifted_right[i]);
    }

    std::unordered_map<uint64_t, BooleanElement> prefix_values =
        evalPrefixBoundariesBoolean(party_id, key.iDPFKey, endpoints);

    for (int i = 0; i < interval_count; i++) {
        if (lengths[i] == 0) {
            output[i] = 0;
        } else if (lengths[i] == domain) {
            output[i] = publicBooleanShare(party_id, 1);
        } else if (shifted_left[i] < shifted_right[i]) {
            output[i] = static_cast<BooleanElement>(
                prefix_values[shifted_right[i]] ^ prefix_values[shifted_left[i]]);
        } else {
            output[i] = static_cast<BooleanElement>(
                publicBooleanShare(party_id, 1) ^
                prefix_values[shifted_left[i]] ^
                prefix_values[shifted_right[i]]);
        }
    }
}

}  // namespace

MICKeyPack micOffline(int party_id, int Bin, int Bout, GroupElement payload) {
    if (Bin <= 0 || Bin >= 32) {
        throw std::invalid_argument("micOffline requires 0 < Bin < 32");
    }
    if (payload.bitsize != Bout) {
        throw std::invalid_argument("micOffline payload bitsize must equal Bout");
    }

    std::vector<GroupElement> level_payloads(Bin);
    for (int i = 0; i < Bin; i++) {
        level_payloads[i] = payload;
    }
    GroupElement rho_share;
    DPFKeyPack idpf_key =
        wrapper::keyGenRandomiDPF(party_id, Bin, level_payloads.data(),
                                  &rho_share);

    const osuCrypto::block root_label = internal::setBlockLsb(
        idpf_key.k[0], static_cast<osuCrypto::u8>(party_id - SERVER));
    const uint64_t root_converted_value =
        internal::convertPayload_iDPF(Bout, root_label);
    GroupElement root_converted(root_converted_value, Bout);
    GroupElement root_cw_share =
        -payload + (party_id == SERVER ? root_converted : -root_converted);
    reconstruct(&root_cw_share);

    MICKeyPack key;
    key.Bin = Bin;
    key.Bout = Bout;
    key.rho_share = rho_share;
    key.payload_share = payload;
    key.root_payload_cw = root_cw_share;
    key.iDPFKey = idpf_key;
    return key;
}

std::vector<MICKeyPack> micOfflineBatchFromBits(
    int party_id, int Bin, int Bout, const BooleanElement* alpha_bits,
    const GroupElement* payloads, int count) {
    if (Bin <= 0 || Bin >= 32 || Bout <= 0 || count <= 0 ||
        alpha_bits == nullptr || payloads == nullptr) {
        throw std::invalid_argument("micOfflineBatchFromBits: invalid inputs");
    }
    for (int i = 0; i < count; ++i) {
        if (payloads[i].bitsize != Bout) {
            throw std::invalid_argument(
                "micOfflineBatchFromBits payload bitsize must equal Bout");
        }
    }

    std::vector<DPFKeyPack> idpf_keys = keyGeniDPFBatch(
        party_id, Bin, Bout, alpha_bits, payloads, count);
    std::vector<GroupElement> root_cw(count, GroupElement(0, Bout));
    for (int i = 0; i < count; ++i) {
        const osuCrypto::block root_label = internal::setBlockLsb(
            idpf_keys[i].k[0], static_cast<osuCrypto::u8>(party_id - SERVER));
        const GroupElement root_converted(
            internal::convertPayload_iDPF(Bout, root_label), Bout);
        root_cw[i] = -payloads[i] +
            (party_id == SERVER ? root_converted : -root_converted);
    }
    reconstruct(count, root_cw.data(), Bout);

    std::vector<MICKeyPack> keys(count);
    for (int i = 0; i < count; ++i) {
        keys[i].Bin = Bin;
        keys[i].Bout = Bout;
        keys[i].rho_share = GroupElement(0, Bin);
        keys[i].payload_share = payloads[i];
        keys[i].root_payload_cw = root_cw[i];
        keys[i].iDPFKey = idpf_keys[i];
    }
    return keys;
}

void mic(int party_id, GroupElement input, const PublicInterval* intervals,
         int interval_count, GroupElement* output, const MICKeyPack& key) {
    if (input.bitsize != key.Bin) {
        throw std::invalid_argument("mic input bitsize must match key.Bin");
    }

    GroupElement delta = input - key.rho_share;
    reconstruct(1, &delta, key.Bin);
    micWithDeltaValue(party_id, delta.value, intervals, interval_count, output,
                      key);
}

MICBooleanKeyPack micBooleanOffline(int party_id, int Bin) {
    if (Bin <= 0 || Bin >= 32) {
        throw std::invalid_argument("micBooleanOffline requires 0 < Bin < 32");
    }

    GroupElement rho_share;
    DPFKeyPack idpf_key =
        wrapper::keyGenRandomiDPF(party_id, Bin, &rho_share);

    MICBooleanKeyPack key;
    key.Bin = Bin;
    key.rho_share = rho_share;
    key.iDPFKey = idpf_key;
    return key;
}

void micBoolean(int party_id, GroupElement input,
                const PublicInterval* intervals, int interval_count,
                BooleanElement* output, const MICBooleanKeyPack& key) {
    if (input.bitsize != key.Bin) {
        throw std::invalid_argument(
            "micBoolean input bitsize must match key.Bin");
    }

    GroupElement delta = input - key.rho_share;
    reconstruct(1, &delta, key.Bin);
    micBooleanWithDeltaValue(party_id, delta.value, intervals, interval_count,
                             output, key);
}

// ========================================================================
//  Fast special-case evaluators — zero dynamic allocation, direct tree walk
// ========================================================================

namespace {

// ---- Inline single-share opening (no vector allocation) -------------------

uint64_t openOneShare(uint64_t share_val, int bits) {
    const uint64_t mask = (bits >= 64) ? ~0ULL : ((1ULL << bits) - 1);
    uint32_t snd = static_cast<uint32_t>(share_val & mask);
    uint32_t rcv = 0;
    send(peer->sendsocket, &snd, sizeof(snd), 0);
    recv(peer->recvsocket, &rcv, sizeof(rcv), MSG_WAITALL);
    peer->bytesSent += sizeof(snd);
    peer->bytesReceived += sizeof(rcv);
    peer->rounds += 2;  // 1 send + 1 recv, matching send/recv_batched_input
    numRounds += 1;
    return (share_val + rcv) & mask;
}

// ---- Helper: evaluate a single prefix F(phi) for Boolean MIC -------------
// phi = endpoint - 1, must satisfy 0 <= phi < domain.

BooleanElement evalOnePrefixBit(int party_id, const DPFKeyPack& key, uint64_t phi) {
    const int n = key.Bin;
    osuCrypto::block node = key.k[0];
    BooleanElement cb = static_cast<BooleanElement>(party_id - SERVER);
    BooleanElement pxor = 0;
    BooleanElement prev = 0;

    osuCrypto::AES aes;
    for (int lev = 0; lev < n; lev++) {
        const BooleanElement dir = (phi >> (n - 1 - lev)) & 1;
        if (dir != prev) pxor ^= cb;

        aes.setKey(node);
        const osuCrypto::block child = aes.ecbEncBlock(
            dir == 0 ? osuCrypto::ZeroBlock : osuCrypto::OneBlock);
        const osuCrypto::block cw = key.k[lev + 1];
        const BooleanElement tau = key.v[2 * lev + dir];
        if (cb == static_cast<BooleanElement>(1)) {
            node = child ^ cw;
            cb = blockLsb(child) ^ tau;
        } else {
            node = child;
            cb = blockLsb(child);
        }
        prev = dir;
    }
    if ((phi & 1) == 0) pxor ^= cb;
    return static_cast<BooleanElement>(pxor & 1);
}

// ---- Helper: evaluate a single prefix F(phi) for arithmetic MIC ----------

GroupElement evalOnePrefixArith(int party_id, const DPFKeyPack& key,
                                const GroupElement& root_payload_cw,
                                int n, uint64_t phi) {
    osuCrypto::block node = key.k[0];
    BooleanElement cb = static_cast<BooleanElement>(party_id - SERVER);
    GroupElement psum(0, key.Bout);
    int sign_cnt = 0;
    BooleanElement prev = 0;

    osuCrypto::AES aes;
    for (int lev = 0; lev < n; lev++) {
        const BooleanElement dir = (phi >> (n - 1 - lev)) & 1;
        if (dir != prev) {
            GroupElement po = evalPrefixPayload(party_id, key, root_payload_cw,
                                                lev, node, cb);
            psum = (sign_cnt % 2 == 0) ? psum + po : psum - po;
            sign_cnt++;
        }

        aes.setKey(node);
        const osuCrypto::block child = aes.ecbEncBlock(
            dir == 0 ? osuCrypto::ZeroBlock : osuCrypto::OneBlock);
        const osuCrypto::block cw = key.k[lev + 1];
        const BooleanElement tau = key.v[2 * lev + dir];
        if (cb == static_cast<BooleanElement>(1)) {
            node = child ^ cw;
            cb = blockLsb(child) ^ tau;
        } else {
            node = child;
            cb = blockLsb(child);
        }
        prev = dir;
    }
    if ((phi & 1) == 0) {
        GroupElement lo = evalPrefixPayload(party_id, key, root_payload_cw,
                                            n, node, cb);
        psum = (sign_cnt % 2 == 0) ? psum + lo : psum - lo;
    }
    return psum;
}

// Continue an arithmetic prefix walk from a previously cached GGM state.
// `trace[level]`, when requested, receives the state after the first `level`
// path bits.  It lets two adjacent endpoints reuse their common GGM prefix
// without a map/allocation on the online path.
PrefixEvalState walkPrefixArith(int party_id, const DPFKeyPack& key,
                                const GroupElement& root_payload_cw,
                                int n, uint64_t phi, int start_level,
                                PrefixEvalState state,
                                PrefixEvalState* trace) {
    osuCrypto::AES aes;
    for (int level = start_level; level < n; ++level) {
        const BooleanElement direction =
            static_cast<BooleanElement>((phi >> (n - 1 - level)) & 1);
        if (direction != state.previous_direction) {
            const GroupElement prefix_output = evalPrefixPayload(
                party_id, key, root_payload_cw, level, state.node,
                state.control_bit);
            state.prefix_sum = (state.sign_count % 2 == 0)
                ? state.prefix_sum + prefix_output
                : state.prefix_sum - prefix_output;
            state.sign_count++;
        }

        aes.setKey(state.node);
        const osuCrypto::block child = aes.ecbEncBlock(
            direction == 0 ? osuCrypto::ZeroBlock : osuCrypto::OneBlock);
        const osuCrypto::block level_cw = key.k[level + 1];
        const BooleanElement level_tau = key.v[2 * level + direction];
        if (state.control_bit == static_cast<BooleanElement>(1)) {
            state.node = child ^ level_cw;
            state.control_bit = blockLsb(child) ^ level_tau;
        } else {
            state.node = child;
            state.control_bit = blockLsb(child);
        }
        state.previous_direction = direction;
        if (trace != nullptr) trace[level + 1] = state;
    }
    return state;
}

GroupElement finishPrefixArith(int party_id, const DPFKeyPack& key,
                               const GroupElement& root_payload_cw, int n,
                               uint64_t phi, PrefixEvalState state) {
    if ((phi & 1) == 0) {
        const GroupElement leaf_output = evalPrefixPayload(
            party_id, key, root_payload_cw, n, state.node,
            state.control_bit);
        state.prefix_sum = (state.sign_count % 2 == 0)
            ? state.prefix_sum + leaf_output
            : state.prefix_sum - leaf_output;
    }
    return state.prefix_sum;
}

void evalAdjacentPrefixArith(int party_id, uint64_t endpoint,
                             const MICKeyPack& key, GroupElement* prefix,
                             GroupElement* next_prefix) {
    const int n = key.Bin;
    const uint64_t domain = uint64_t(1) << n;
    if (endpoint >= domain) {
        throw std::invalid_argument(
            "adjacent MIC prefix endpoint must lie below the domain");
    }

    PrefixEvalState root;
    root.node = key.iDPFKey.k[0];
    root.control_bit = static_cast<BooleanElement>(party_id - SERVER);
    root.prefix_sum = GroupElement(0, key.Bout);

    // Bin is constrained to < 32 by MIC, so the root plus 31 path states
    // always fit in this fixed stack array.
    PrefixEvalState trace[32];
    trace[0] = root;
    if (endpoint == 0) {
        *prefix = GroupElement(0, key.Bout);
    } else {
        const uint64_t phi = endpoint - 1;
        const PrefixEvalState terminal = walkPrefixArith(
            party_id, key.iDPFKey, key.root_payload_cw, n, phi, 0, root,
            trace);
        *prefix = finishPrefixArith(party_id, key.iDPFKey,
                                    key.root_payload_cw, n, phi, terminal);
    }

    if (endpoint + 1 == domain) {
        *next_prefix = key.payload_share;
        return;
    }

    // For endpoint>0, the two paths are endpoint-1 and endpoint. Reuse all
    // leading bits they share; consecutive values differ only in a short
    // suffix (two levels on average), not in a second full h-level walk.
    const uint64_t next_phi = endpoint;
    int shared_levels = 0;
    if (endpoint != 0) {
        const uint64_t current_phi = endpoint - 1;
        while (shared_levels < n &&
               ((current_phi >> (n - 1 - shared_levels)) & 1) ==
                   ((next_phi >> (n - 1 - shared_levels)) & 1)) {
            ++shared_levels;
        }
    }
    const PrefixEvalState terminal = walkPrefixArith(
        party_id, key.iDPFKey, key.root_payload_cw, n, next_phi,
        shared_levels, trace[shared_levels], nullptr);
    *next_prefix = finishPrefixArith(party_id, key.iDPFKey,
                                     key.root_payload_cw, n, next_phi,
                                     terminal);
}

// ---- Sort + dedup ≤ K uint64_t values in-place. Returns new count. -------

int sortDedup(uint64_t* arr, int count) {
    for (int i = 1; i < count; i++) {
        const uint64_t key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key) { arr[j + 1] = arr[j]; j--; }
        arr[j + 1] = key;
    }
    if (count <= 1) return count;
    int out = 1;
    for (int i = 1; i < count; i++)
        if (arr[i] != arr[out - 1]) arr[out++] = arr[i];
    return out;
}

}  // namespace

// ---- Public fast-path wrappers -------------------------------------------

BooleanElement micSingleIntervalBooleanFast(int party_id, GroupElement input,
                                            uint64_t threshold,
                                            const MICBooleanKeyPack& key) {
    if (input.bitsize != key.Bin || key.Bin <= 0 || key.Bin >= 32)
        throw std::invalid_argument("micSingleIntervalBooleanFast: bad input");
    const uint64_t domain = uint64_t(1) << key.Bin;
    if (threshold == 0) return 0;
    if (threshold == domain) return publicBooleanShare(party_id, 1);

    // Inline opening — no vector allocation.
    const uint64_t d = openOneShare((input - key.rho_share).value, key.Bin);
    const uint64_t L = (domain - d) % domain;
    const uint64_t R = (threshold + domain - d) % domain;

    BooleanElement val_L = (L == 0) ? static_cast<BooleanElement>(0)
                         : (L == domain) ? publicBooleanShare(party_id, 1)
                         : evalOnePrefixBit(party_id, key.iDPFKey, L - 1);

    BooleanElement val_R = (R == 0) ? static_cast<BooleanElement>(0)
                         : (R == domain) ? publicBooleanShare(party_id, 1)
                         : evalOnePrefixBit(party_id, key.iDPFKey, R - 1);

    if (L < R) return static_cast<BooleanElement>(val_R ^ val_L);
    return static_cast<BooleanElement>(publicBooleanShare(party_id, 1) ^ val_L ^ val_R);
}

BooleanElement micTwoIntervalZqBooleanFast(int party_id, GroupElement input,
                                           uint64_t threshold,
                                           const MICBooleanKeyPack& key) {
    if (input.bitsize != key.Bin || key.Bin <= 0 || key.Bin >= 32)
        throw std::invalid_argument("micTwoIntervalZqBooleanFast: bad input");
    const uint64_t domain = uint64_t(1) << key.Bin;
    constexpr uint64_t kQ = 8380417ULL;

    const uint64_t d = openOneShare((input - key.rho_share).value, key.Bin);

    auto epVal = [&](uint64_t v) -> BooleanElement {
        const uint64_t ep = (v + domain - d) % domain;
        if (ep == 0) return 0;
        if (ep == domain) return publicBooleanShare(party_id, 1);
        return evalOnePrefixBit(party_id, key.iDPFKey, ep - 1);
    };

    auto intervalBit = [&](uint64_t L, uint64_t R, uint64_t len) {
        if (len == 0) return static_cast<BooleanElement>(0);
        if (len == domain) return publicBooleanShare(party_id, 1);
        const uint64_t eL = (L + domain - d) % domain;
        const uint64_t eR = (R + domain - d) % domain;
        BooleanElement vL = (eL == 0) ? static_cast<BooleanElement>(0)
                          : (eL == domain) ? publicBooleanShare(party_id, 1)
                          : evalOnePrefixBit(party_id, key.iDPFKey, eL - 1);
        BooleanElement vR = (eR == 0) ? static_cast<BooleanElement>(0)
                          : (eR == domain) ? publicBooleanShare(party_id, 1)
                          : evalOnePrefixBit(party_id, key.iDPFKey, eR - 1);
        if (eL < eR) return static_cast<BooleanElement>(vR ^ vL);
        return static_cast<BooleanElement>(publicBooleanShare(party_id, 1) ^ vL ^ vR);
    };

    return static_cast<BooleanElement>(
        intervalBit(0, threshold, threshold) ^
        intervalBit(kQ, kQ + threshold, threshold));
}

// ---- Arithmetic wrappers (kept for API completeness, same direct-walk
//      structure but not the primary optimization target) -------------------

GroupElement micSingleIntervalFast(int party_id, GroupElement input,
                                   uint64_t threshold,
                                   const MICKeyPack& key) {
    if (input.bitsize != key.Bin || key.Bin <= 0 || key.Bin >= 32)
        throw std::invalid_argument("micSingleIntervalFast: bad input");
    const uint64_t domain = uint64_t(1) << key.Bin;
    if (threshold == 0) return GroupElement(0, key.Bout);
    if (threshold == domain) return key.payload_share;

    const uint64_t d = openOneShare((input - key.rho_share).value, key.Bin);
    const uint64_t L = (domain - d) % domain;
    const uint64_t R = (threshold + domain - d) % domain;

    const int n = key.Bin;
    auto epVal = [&](uint64_t ep) -> GroupElement {
        if (ep == 0) return GroupElement(0, key.Bout);
        if (ep == domain) return key.payload_share;
        return evalOnePrefixArith(party_id, key.iDPFKey, key.root_payload_cw,
                                  n, ep - 1);
    };

    GroupElement vL = epVal(L), vR = epVal(R);
    if (L < R) return vR - vL;
    return key.payload_share - vL + vR;
}

GroupElement micTwoIntervalZqFast(int party_id, GroupElement input,
                                  uint64_t threshold,
                                  const MICKeyPack& key) {
    if (input.bitsize != key.Bin || key.Bin <= 0 || key.Bin >= 32)
        throw std::invalid_argument("micTwoIntervalZqFast: bad input");
    const uint64_t domain = uint64_t(1) << key.Bin;
    constexpr uint64_t kQ = 8380417ULL;

    const uint64_t d = openOneShare((input - key.rho_share).value, key.Bin);
    const int n = key.Bin;

    auto epVal = [&](uint64_t ep) -> GroupElement {
        if (ep == 0) return GroupElement(0, key.Bout);
        if (ep == domain) return key.payload_share;
        return evalOnePrefixArith(party_id, key.iDPFKey, key.root_payload_cw,
                                  n, ep - 1);
    };

    auto intervalArith = [&](uint64_t L, uint64_t R, uint64_t len) {
        if (len == 0) return GroupElement(0, key.Bout);
        if (len == domain) return key.payload_share;
        const uint64_t eL = (L + domain - d) % domain;
        const uint64_t eR = (R + domain - d) % domain;
        GroupElement vL = epVal(eL), vR = epVal(eR);
        if (eL < eR) return vR - vL;
        return key.payload_share - vL + vR;
    };

    return intervalArith(0, threshold, threshold) +
           intervalArith(kQ, kQ + threshold, threshold);
}

GroupElement micPrefixEvalPublic(int party_id, uint64_t endpoint,
                                 const MICKeyPack& key) {
    if (key.Bin <= 0 || key.Bin >= 32) {
        throw std::invalid_argument("micPrefixEvalPublic: invalid key");
    }
    const uint64_t domain = uint64_t(1) << key.Bin;
    if (endpoint > domain) {
        throw std::invalid_argument(
            "micPrefixEvalPublic: endpoint outside domain");
    }
    if (endpoint == 0) return GroupElement(0, key.Bout);
    if (endpoint == domain) return key.payload_share;
    return evalOnePrefixArith(party_id, key.iDPFKey, key.root_payload_cw,
                              key.Bin, endpoint - 1);
}

void micPrefixEvalPublicAdjacent(int party_id, uint64_t endpoint,
                                 const MICKeyPack& key,
                                 GroupElement* prefix,
                                 GroupElement* next_prefix) {
    if (prefix == nullptr || next_prefix == nullptr || key.Bin <= 0 ||
        key.Bin >= 32) {
        throw std::invalid_argument(
            "micPrefixEvalPublicAdjacent: invalid argument or key");
    }
    evalAdjacentPrefixArith(party_id, endpoint, key, prefix, next_prefix);
}

// ========================================================================
//  Batch MIC: single batch reconstruct, then local eval for all dimensions
// ========================================================================

void micSingleIntervalBatchFast(
    int party_id,
    GroupElement* output,
    const uint64_t* delta_values,
    const MICKeyPack* const* key_ptrs,
    const uint64_t* thresholds,
    int dim) {

    for (int i = 0; i < dim; i++) {
        const MICKeyPack& mk = *key_ptrs[i];
        const int Bin = mk.Bin;
        const int Bout = mk.Bout;
        const uint64_t domain = uint64_t(1) << Bin;
        const uint64_t threshold = thresholds[i];
        const uint64_t d = delta_values[i] % domain;

        if (threshold == 0) {
            output[i] = GroupElement(0, Bout);
            continue;
        }
        if (threshold == domain) {
            output[i] = mk.payload_share;
            continue;
        }

        const uint64_t L = (domain - d) % domain;
        const uint64_t R = (threshold + domain - d) % domain;
        const int n = Bin;

        auto epVal = [&](uint64_t ep) -> GroupElement {
            if (ep == 0) return GroupElement(0, Bout);
            if (ep == domain) return mk.payload_share;
            return evalOnePrefixArith(party_id, mk.iDPFKey,
                                      mk.root_payload_cw,
                                      n, ep - 1);
        };

        GroupElement vL = epVal(L), vR = epVal(R);
        if (L < R) {
            output[i] = vR - vL;
        } else {
            output[i] = mk.payload_share - vL + vR;
        }
    }
}

void micTwoIntervalZqBatchFast(
    int party_id,
    GroupElement* output,
    const uint64_t* delta_values,
    const MICKeyPack* const* key_ptrs,
    const uint64_t* thresholds,
    int dim) {

    constexpr uint64_t kQ = 8380417ULL;
    constexpr int kLiftBits = 24;
    constexpr uint64_t kLiftDomain = 1ULL << kLiftBits;

    for (int i = 0; i < dim; i++) {
        const MICKeyPack& mk = *key_ptrs[i];
        const int Bout = mk.Bout;
        const uint64_t threshold = thresholds[i];
        const uint64_t d = delta_values[i] % kLiftDomain;
        const int n = kLiftBits;

        if (threshold == 0) {
            output[i] = GroupElement(0, Bout);
            continue;
        }
        if (threshold == kQ) {
            output[i] = mk.payload_share;
            continue;
        }

        auto epVal = [&](uint64_t ep) -> GroupElement {
            if (ep == 0) return GroupElement(0, Bout);
            if (ep == kLiftDomain) return mk.payload_share;
            return evalOnePrefixArith(party_id, mk.iDPFKey,
                                      mk.root_payload_cw,
                                      n, ep - 1);
        };

        auto intervalArith = [&](uint64_t L, uint64_t R, uint64_t len) {
            if (len == 0) return GroupElement(0, Bout);
            if (len == kLiftDomain) return mk.payload_share;
            const uint64_t eL = (L + kLiftDomain - d) % kLiftDomain;
            const uint64_t eR = (R + kLiftDomain - d) % kLiftDomain;
            GroupElement vL = epVal(eL), vR = epVal(eR);
            if (eL < eR) return vR - vL;
            return mk.payload_share - vL + vR;
        };

        output[i] = intervalArith(0, threshold, threshold) +
                    intervalArith(kQ, kQ + threshold, threshold);
    }
}

}  // namespace dfss
