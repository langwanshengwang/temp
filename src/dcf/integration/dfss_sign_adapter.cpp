// Adapter between the threshold-signing C ABI and the supplied EzPC/DFSS
// high/low comparison implementation.  One adapter instance lives inside
// each DCF helper process; it never serialises or transfers the peer's key.

#include "dcf_dealerless_backend.h"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "buildingblock/highdim_comparison.h"
#include "commons/field_q.h"
#include "mpc/comms.h"

#ifdef _OPENMP
#include <omp.h>
#endif

// The upstream DFSS sources deliberately leave executable-wide runtime state
// to their benchmark main().  The signing adapter is that executable owner.
int party = 0;
int port = 0;
int32_t bitlength = 32;
osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
Peer* client = nullptr;
Peer* server = nullptr;
Dealer* dealer = nullptr;
Peer* peer = nullptr;

namespace {

constexpr uint32_t kTokenMagic = 0x44534653U;  // "DSFS"
constexpr uint32_t kTokenVersion = 1U;

struct OpaqueToken {
    uint32_t magic;
    uint32_t version;
    uint64_t handle;
    uint64_t context_tag;
    uint64_t integrity_tag;
};

static_assert(sizeof(OpaqueToken) == 32, "unexpected opaque token layout");

struct BackendRecord {
    uint64_t context_tag = 0;
    std::vector<uint32_t> local_masks;
    bool monolithic = false;
    std::unique_ptr<HighDimScheme3KeyPack> hierarchical_key;
    std::unique_ptr<HighDimMonolithicKeyPack> monolithic_key;
};

std::mutex g_backend_mutex;
std::unordered_map<uint64_t, BackendRecord> g_records;
uint64_t g_handle_counter = 0;
uint64_t g_process_cookie = 0;
int g_peer_port = 0;
int g_peer_party = 0;

int configure_worker_threads(int requested, int lanes) {
#ifdef _OPENMP
    /* omp_get_max_threads() honors OMP_NUM_THREADS; without that environment
     * override it normally tracks the process-visible CPU set. */
    int selected = requested > 0 ? requested : omp_get_max_threads();
    if (selected <= 0) selected = 1;
    if (lanes > 0 && selected > lanes) selected = lanes;
    omp_set_dynamic(0);
    omp_set_num_threads(selected);
    return selected;
#else
    (void)requested;
    (void)lanes;
    return 1;
#endif
}

uint64_t mix64(uint64_t x) {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

uint64_t mix_tag(uint64_t state, uint64_t value) {
    return mix64(state ^ mix64(value + 0x9e3779b97f4a7c15ULL));
}

uint64_t keygen_context_tag(const DcfDealerlessKeygenCtx& ctx) {
    uint64_t tag = 0x444653532d435458ULL;  // "DFSS-CTX"
    tag = mix_tag(tag, ctx.abi_version);
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.helper_index));
    /* EvalCtx deliberately contains only protocol-public context. Keep
     * this tag identical to eval_context_tag(); self/peer IDs are
     * transport metadata, not part of the opaque-key identity. */
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.requester_id));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.session_id));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.coeff_count));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.bound_B));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.pool_item));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.rejection_round));
    return tag;
}

uint64_t eval_context_tag(const DcfDealerlessEvalCtx& ctx) {
    uint64_t tag = 0x444653532d435458ULL;
    tag = mix_tag(tag, ctx.abi_version);
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.helper_index));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.requester_id));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.session_id));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.coeff_count));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.bound_B));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.pool_item));
    tag = mix_tag(tag, static_cast<uint32_t>(ctx.rejection_round));
    return tag;
}

uint64_t token_integrity(uint64_t handle, uint64_t context_tag) {
    return mix_tag(mix_tag(g_process_cookie, handle), context_tag);
}

uint64_t mask_digest(int helper_index, const std::vector<uint32_t>& masks) {
    uint64_t tag = mix_tag(0x444653532d4d4153ULL,
                           static_cast<uint32_t>(helper_index));
    for (size_t i = 0; i < masks.size(); ++i) {
        tag = mix_tag(tag, (static_cast<uint64_t>(i) << 32) | masks[i]);
    }
    return tag;
}

uint64_t public_input_digest(const uint32_t* values, int count) {
    uint64_t tag = 0x444653532d455641ULL;  // "DFSS-EVA"
    for (int i = 0; i < count; ++i) {
        tag = mix_tag(tag, (static_cast<uint64_t>(i) << 32) | values[i]);
    }
    return tag;
}

bool monolithic_mode_enabled() {
    const char* mode = std::getenv("DFSS_MIC_MODE");
    if (mode == nullptr || mode[0] == '\0' ||
        std::strcmp(mode, "hierarchical") == 0 ||
        std::strcmp(mode, "highlow") == 0) {
        return false;
    }
    if (std::strcmp(mode, "monolithic") == 0 ||
        std::strcmp(mode, "24bit") == 0) {
        return true;
    }
    throw std::invalid_argument(
        "DFSS_MIC_MODE must be hierarchical/highlow or monolithic/24bit");
}

uint64_t next_handle() {
    if (g_process_cookie == 0) {
        g_process_cookie = mix64(secure_prng().get<uint64_t>());
        if (g_process_cookie == 0) g_process_cookie = 1;
    }
    ++g_handle_counter;
    const uint64_t candidate = mix_tag(g_process_cookie, g_handle_counter);
    return candidate == 0 ? g_handle_counter : candidate;
}

bool valid_keygen_context(const DcfDealerlessKeygenCtx* ctx) {
    if (ctx == nullptr || ctx->abi_version != DCF_DEALERLESS_BACKEND_ABI_VERSION) return false;
    if (ctx->helper_index != 0 && ctx->helper_index != 1) return false;
    if (ctx->coeff_count <= 0 || ctx->coeff_count > DCF_MAX_SK_COEFFS) return false;
    if (ctx->bound_B <= 0 || 2ULL * static_cast<uint64_t>(ctx->bound_B) >= dfss::fieldq::kQ) return false;
    if (ctx->self_dfss_port <= 0 || ctx->peer_dfss_port <= 0 || ctx->peer_ip[0] == '\0') return false;
    return true;
}

bool ensure_dfss_peer(const DcfDealerlessKeygenCtx& ctx) {
    const int wanted_party = ctx.helper_index == 0 ? SERVER : CLIENT;
    if (peer != nullptr) {
        return g_peer_party == wanted_party && g_peer_port == ctx.self_dfss_port;
    }

    party = wanted_party;
    port = ctx.self_dfss_port;
    if (party == SERVER) {
        client = waitForPeer(ctx.self_dfss_port);
        peer = client;
    } else {
        server = new Peer(ctx.peer_ip, ctx.peer_dfss_port);
        peer = server;
    }
    g_peer_party = wanted_party;
    g_peer_port = ctx.self_dfss_port;
    return peer != nullptr;
}

}  // namespace

extern "C" int dcf_dealerless_backend_available(void) {
    return 1;
}

extern "C" const char* dcf_dealerless_backend_name(void) {
    return "ezpc-dfss-batch-v2";
}

extern "C" int dcf_dealerless_backend_keygen_share(
    const DcfDealerlessKeygenCtx* ctx, DcfDealerlessKeyShare* out) {
    if (out != nullptr) std::memset(out, 0, sizeof(*out));
    if (!valid_keygen_context(ctx) || out == nullptr) return -1;

    try {
        std::lock_guard<std::mutex> lock(g_backend_mutex);
        if (!ensure_dfss_peer(*ctx)) return -1;

        const auto started = std::chrono::steady_clock::now();
        const uint64_t before_sent = peer->bytesSent;
        const uint64_t before_received = peer->bytesReceived;
        const uint64_t context_tag = keygen_context_tag(*ctx);

        BackendRecord record;
        record.context_tag = context_tag;
        record.local_masks.resize(static_cast<size_t>(ctx->coeff_count));
        auto rng = secure_prng();
        for (int lane = 0; lane < ctx->coeff_count; ++lane) {
            record.local_masks[static_cast<size_t>(lane)] =
                static_cast<uint32_t>(rng.get<uint64_t>() % dfss::fieldq::kQ);
        }

        // The signing layer masks x=z+B as u=x+r0+r1 (mod q).  At Eval each
        // helper supplies u-r_b as its DFSS input share, so the two shares
        // reconstruct x.  The high/low key consequently compares x < 2B.
        const std::vector<uint64_t> thresholds(
            static_cast<size_t>(ctx->coeff_count),
            2ULL * static_cast<uint64_t>(ctx->bound_B));
        dfss::HighDimExecutionOptions options;
        options.endpoint_batched = true;
        options.or_batched = true;
        record.monolithic = monolithic_mode_enabled();
        const auto offline_core_started = std::chrono::steady_clock::now();
        if (record.monolithic) {
            record.monolithic_key =
                std::make_unique<HighDimMonolithicKeyPack>(
                    dfss::highDimMonolithicOffline(
                        party, ctx->coeff_count, 24, thresholds, options));
        } else {
            record.hierarchical_key =
                std::make_unique<HighDimScheme3KeyPack>(
                    dfss::highDimScheme3Offline(
                        party, ctx->coeff_count, 24, 12, 12, thresholds,
                        options));
        }
        const double offline_core_ms = static_cast<double>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - offline_core_started).count()) / 1000.0;
        std::fprintf(stderr,
                     "[DFSS adapter C%d] DFSS_CORE_OFFLINE: session=%d item=%d core_offline_ms=%.3f dfss_sent_bytes=%llu dfss_recv_bytes=%llu lanes=%d bits=24 mic_mode=%s endpoint_batched=1 or_batched=1\n",
                     ctx->helper_index, ctx->session_id, ctx->pool_item + 1,
                     offline_core_ms,
                     static_cast<unsigned long long>(peer->bytesSent - before_sent),
                     static_cast<unsigned long long>(peer->bytesReceived - before_received),
                     ctx->coeff_count,
                     record.monolithic ? "monolithic" : "hierarchical");

        const uint64_t handle = next_handle();
        const OpaqueToken token{
            kTokenMagic, kTokenVersion, handle, context_tag,
            token_integrity(handle, context_tag)};
        g_records.emplace(handle, std::move(record));

        out->key_bytes = static_cast<unsigned char*>(std::malloc(sizeof(token)));
        if (out->key_bytes == nullptr) {
            g_records.erase(handle);
            return -1;
        }
        std::memcpy(out->key_bytes, &token, sizeof(token));
        out->key_len = sizeof(token);
        const auto& stored = g_records.at(handle);
        for (int lane = 0; lane < ctx->coeff_count; ++lane) {
            out->local_mask_shares[lane] = stored.local_masks[static_cast<size_t>(lane)];
        }
        out->key_digest = mix_tag(context_tag, token.integrity_tag);
        out->local_mask_digest = mask_digest(ctx->helper_index, stored.local_masks);
        out->transcript_digest = mix_tag(
            mix_tag(context_tag, peer->bytesSent - before_sent),
            peer->bytesReceived - before_received);
        out->keygen_time_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count());
        return 0;
    } catch (const std::exception&) {
        if (out != nullptr) {
            std::free(out->key_bytes);
            std::memset(out, 0, sizeof(*out));
        }
        return -1;
    }
}

#if 0  // ABI v2 single-candidate implementation retained for source archaeology.
extern "C" int dcf_dealerless_backend_eval_failure_share(
    const DcfDealerlessEvalCtx* ctx, uint32_t* failure_share,
    uint64_t* eval_digest) {
    if (failure_share != nullptr) *failure_share = UINT32_MAX;
    if (eval_digest != nullptr) *eval_digest = 0;
    if (ctx == nullptr || failure_share == nullptr || eval_digest == nullptr ||
        ctx->abi_version != DCF_DEALERLESS_BACKEND_ABI_VERSION ||
        (ctx->helper_index != 0 && ctx->helper_index != 1) ||
        ctx->coeff_count <= 0 || ctx->coeff_count > DCF_MAX_SK_COEFFS ||
        ctx->candidates <= 0 || ctx->candidates > DCF_MAX_SK_COEFFS ||
        ctx->bound_B <= 0 || ctx->key_bytes == nullptr ||
        ctx->key_len != sizeof(OpaqueToken) || ctx->public_u == nullptr) {
        return -1;
    }

    try {
        std::lock_guard<std::mutex> lock(g_backend_mutex);
        const int candidates = ctx->candidates > 0 ? ctx->candidates : 1;
        if (candidates != 1) {
            // 多候选需要 K 个 additive share 输出；当前 failure_share 是单个
            // uint32_t additive share，暂不支持。candidates 字段保留供后续
            // ABI 扩展为数组输出。
            std::fprintf(stderr,
                         "[DFSS adapter C%d] ONLINE: candidates=%d not supported by single-share ABI\n",
                         ctx->helper_index, candidates);
            return -1;
        }

        OpaqueToken token{};
        std::memcpy(&token, ctx->key_bytes, sizeof(token));
        const uint64_t context_tag = eval_context_tag(*ctx);
        if (token.magic != kTokenMagic || token.version != kTokenVersion ||
            token.context_tag != context_tag ||
            token.integrity_tag != token_integrity(token.handle, context_tag)) {
            std::fprintf(stderr,
                         "[DFSS adapter C%d] ONLINE_REJECT: opaque token/context mismatch\n",
                         ctx->helper_index);
            return -1;
        }
        auto record_it = g_records.find(token.handle);
        if (record_it == g_records.end() ||
            record_it->second.context_tag != context_tag ||
            record_it->second.key == nullptr ||
            record_it->second.local_masks.size() != static_cast<size_t>(ctx->coeff_count) ||
            peer == nullptr || party != (ctx->helper_index == 0 ? SERVER : CLIENT)) {
            return -1;
        }

        std::vector<GroupElement> input_shares;
        input_shares.reserve(static_cast<size_t>(ctx->coeff_count));
        for (int lane = 0; lane < ctx->coeff_count; ++lane) {
            const uint64_t u = ctx->public_u[lane];
            if (u >= dfss::fieldq::kQ) return -1;
            const uint64_t r = record_it->second.local_masks[static_cast<size_t>(lane)];
            const uint64_t share = ctx->helper_index == 0
                ? dfss::fieldq::subModQ(u, r)
                : dfss::fieldq::negModQ(r);
            input_shares.emplace_back(share, dfss::fieldq::kShareBits);
        }

        const uint64_t before_sent = peer->bytesSent;
        const uint64_t before_received = peer->bytesReceived;
#ifdef _OPENMP
        if (ctx->worker_threads > 0) {
            omp_set_num_threads(ctx->worker_threads);
        }
#endif
        const auto core_started = std::chrono::steady_clock::now();
        const GroupElement result = dfss::highDimScheme3Online(
            party, input_shares, *record_it->second.key);
        const double core_online_ms = static_cast<double>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - core_started).count()) / 1000.0;
        // This is the directly comparable DFSS benchmark quantity: one batched
        // highDimScheme3Online call over all ML-DSA coefficients for one helper.
        const uint64_t online_dfss_sent = peer->bytesSent - before_sent;
        const uint64_t online_dfss_received = peer->bytesReceived - before_received;
        std::fprintf(stderr,
                     "[DFSS adapter C%d] DFSS_CORE_ONLINE: session=%d item=%d core_online_ms=%.3f dfss_sent_bytes=%llu dfss_recv_bytes=%llu lanes=%d bits=24 high_bits=12 low_bits=12 endpoint_batched=1 or_batched=1\n",
                     ctx->helper_index, ctx->session_id, ctx->pool_item + 1,
                     core_online_ms,
                     static_cast<unsigned long long>(online_dfss_sent),
                     static_cast<unsigned long long>(online_dfss_received),
                     ctx->coeff_count);

        // highDimScheme3Online produces an additive OR share in Z_(2^32).
        // The sign layer combines the two external-backend shares in that
        // same ring and only checks whether the reconstructed bit is zero.
        *failure_share = static_cast<uint32_t>(result.value);
        *eval_digest = mix_tag(
            mix_tag(public_input_digest(ctx->public_u, ctx->coeff_count),
                    peer->bytesSent - before_sent),
            peer->bytesReceived - before_received);

        freeHighDimScheme3KeyPack(*record_it->second.key);
        g_records.erase(record_it);  // one-time DCF key: never evaluate twice
        return 0;
    } catch (const std::exception& exc) {
        std::fprintf(stderr, "[DFSS adapter] ONLINE_EXCEPTION: %s\n", exc.what());
        return -1;
    }
}
#endif

extern "C" int dcf_dealerless_backend_eval_failure_shares(
    const DcfDealerlessEvalCtx* ctx, uint32_t* failure_shares,
    uint64_t* eval_digests) {
    if (ctx != nullptr && failure_shares != nullptr && eval_digests != nullptr &&
        ctx->candidates > 0 && ctx->candidates <= TDILITHIUM_DCF_BATCH_MAX) {
        for (int candidate = 0; candidate < ctx->candidates; ++candidate) {
            failure_shares[candidate] = UINT32_MAX;
            eval_digests[candidate] = 0;
        }
    }
    if (ctx == nullptr || failure_shares == nullptr || eval_digests == nullptr ||
        ctx->abi_version != DCF_DEALERLESS_BACKEND_ABI_VERSION ||
        (ctx->helper_index != 0 && ctx->helper_index != 1) ||
        ctx->coeff_count <= 0 || ctx->coeff_count > DCF_MAX_SK_COEFFS ||
        ctx->candidates <= 0 || ctx->candidates > TDILITHIUM_DCF_BATCH_MAX ||
        ctx->bound_B <= 0 || ctx->key_bytes == nullptr ||
        ctx->key_len != sizeof(OpaqueToken) || ctx->public_u == nullptr) {
        return -1;
    }

    try {
        std::lock_guard<std::mutex> lock(g_backend_mutex);
        const int candidates = ctx->candidates;
        std::vector<uint64_t> handles(candidates);
        std::vector<BackendRecord*> records(candidates, nullptr);
        std::vector<std::vector<GroupElement>> input_shares(candidates);
        bool monolithic = false;

        for (int candidate = 0; candidate < candidates; ++candidate) {
            OpaqueToken token{};
            std::memcpy(&token,
                        ctx->key_bytes + static_cast<size_t>(candidate) *
                                             ctx->key_len,
                        sizeof(token));
            DcfDealerlessEvalCtx candidate_ctx = *ctx;
            candidate_ctx.pool_item += candidate;
            candidate_ctx.rejection_round += candidate;
            const uint64_t context_tag = eval_context_tag(candidate_ctx);
            if (token.magic != kTokenMagic || token.version != kTokenVersion ||
                token.context_tag != context_tag ||
                token.integrity_tag !=
                    token_integrity(token.handle, context_tag)) {
                std::fprintf(stderr,
                             "[DFSS adapter C%d] ONLINE_REJECT: candidate=%d token/context mismatch\n",
                             ctx->helper_index, candidate);
                return -1;
            }
            auto record_it = g_records.find(token.handle);
            if (record_it == g_records.end() ||
                record_it->second.context_tag != context_tag ||
                record_it->second.local_masks.size() !=
                    static_cast<size_t>(ctx->coeff_count) ||
                peer == nullptr ||
                party != (ctx->helper_index == 0 ? SERVER : CLIENT)) {
                return -1;
            }
            BackendRecord& record = record_it->second;
            if (candidate == 0) monolithic = record.monolithic;
            if (record.monolithic != monolithic ||
                (record.monolithic && record.monolithic_key == nullptr) ||
                (!record.monolithic && record.hierarchical_key == nullptr)) {
                std::fprintf(stderr,
                             "[DFSS adapter C%d] ONLINE_REJECT: mixed or incomplete MIC modes\n",
                             ctx->helper_index);
                return -1;
            }
            handles[candidate] = token.handle;
            records[candidate] = &record;
            input_shares[candidate].reserve(
                static_cast<size_t>(ctx->coeff_count));
            for (int lane = 0; lane < ctx->coeff_count; ++lane) {
                const int flat = candidate * ctx->coeff_count + lane;
                const uint64_t u = ctx->public_u[flat];
                if (u >= dfss::fieldq::kQ) return -1;
                const uint64_t r = record.local_masks[static_cast<size_t>(lane)];
                const uint64_t share = ctx->helper_index == 0
                    ? dfss::fieldq::subModQ(u, r)
                    : dfss::fieldq::negModQ(r);
                input_shares[candidate].emplace_back(
                    share, dfss::fieldq::kShareBits);
            }
        }

        const uint64_t before_sent = peer->bytesSent;
        const uint64_t before_received = peer->bytesReceived;
        const int selected_threads = configure_worker_threads(
            ctx->worker_threads, candidates * ctx->coeff_count);
        const auto core_started = std::chrono::steady_clock::now();
        std::vector<GroupElement> results;
        if (monolithic) {
            std::vector<const HighDimMonolithicKeyPack*> keys(candidates);
            for (int candidate = 0; candidate < candidates; ++candidate) {
                keys[candidate] = records[candidate]->monolithic_key.get();
            }
            results = dfss::highDimMonolithicOnlineBatch(
                party, input_shares, keys);
        } else {
            std::vector<const HighDimScheme3KeyPack*> keys(candidates);
            for (int candidate = 0; candidate < candidates; ++candidate) {
                keys[candidate] = records[candidate]->hierarchical_key.get();
            }
            results = dfss::highDimScheme3OnlineBatch(
                party, input_shares, keys);
        }
        const double core_online_ms = static_cast<double>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - core_started).count()) /
            1000.0;
        const uint64_t online_dfss_sent = peer->bytesSent - before_sent;
        const uint64_t online_dfss_received =
            peer->bytesReceived - before_received;
        std::fprintf(stderr,
                     "[DFSS adapter C%d] DFSS_CORE_ONLINE_BATCH: session=%d first_item=%d candidates=%d core_online_ms=%.3f dfss_sent_bytes=%llu dfss_recv_bytes=%llu lanes=%d threads=%d bits=24 mic_mode=%s endpoint_batched=1 or_batched=1\n",
                     ctx->helper_index, ctx->session_id, ctx->pool_item + 1,
                     candidates, core_online_ms,
                     static_cast<unsigned long long>(online_dfss_sent),
                     static_cast<unsigned long long>(online_dfss_received),
                     candidates * ctx->coeff_count, selected_threads,
                     monolithic ? "monolithic" : "hierarchical");

        for (int candidate = 0; candidate < candidates; ++candidate) {
            failure_shares[candidate] =
                static_cast<uint32_t>(results[candidate].value);
            eval_digests[candidate] = mix_tag(
                mix_tag(public_input_digest(
                            ctx->public_u + candidate * ctx->coeff_count,
                            ctx->coeff_count),
                        online_dfss_sent),
                mix_tag(online_dfss_received,
                        static_cast<uint32_t>(candidate)));
        }

        for (int candidate = 0; candidate < candidates; ++candidate) {
            BackendRecord& record = *records[candidate];
            if (record.monolithic) {
                freeHighDimMonolithicKeyPack(*record.monolithic_key);
            } else {
                freeHighDimScheme3KeyPack(*record.hierarchical_key);
            }
        }
        for (uint64_t handle : handles) g_records.erase(handle);
        return 0;
    } catch (const std::exception& exc) {
        std::fprintf(stderr, "[DFSS adapter] ONLINE_EXCEPTION: %s\n", exc.what());
        return -1;
    }
}

extern "C" void dcf_dealerless_backend_free_key_share(
    DcfDealerlessKeyShare* share) {
    if (share == nullptr) return;
    std::free(share->key_bytes);
    std::memset(share, 0, sizeof(*share));
}
