/*
 * party.h —— 一个参与方 P_b（b ∈ {0,1}）的全部协议状态。
 *
 * 角色说明：
 *   - P_b 是签名方：持有 DKG 得到的 Shamir 份额 sk^(b)，Shamir 求值点 x_b = b+1；
 *   - P_b 同时是 DFSS 比较协议中的 C_b：持有自己的一次性 DCF 密钥与掩码份额 rho_b；
 *   - 没有协调方：两方运行同一份代码，签名由两方各自独立组装、各自验证，
 *     最后交换签名摘要确认一致。
 */
#ifndef PARTY_H
#define PARTY_H

#include "channel.h"
#include "common.h"
#include "config.h"
#include "dcf_dealerless_backend.h"
#include "mldsa_math.h"

#include <stdint.h>

#define MAX_MESSAGE_BYTES 1024

typedef enum {
    PH_HANDSHAKE = 0,
    PH_DKG,
    PH_DCF_PREP,
    PH_SIGN_ATTEMPT,   /* 采样 y/r、承诺轮、挑战、z_b */
    PH_REJECTS,        /* 掩码交换 + DFSS 在线比较 + phi 打开 */
    PH_OPEN_ALG7,      /* 接受候选的 z/r 打开 + Algorithm 7 */
    PH_OPEN_CHECK,     /* 严格打开一致性检查 */
    PH_VERIFY,
    PH_COUNT
} PhaseId;

typedef struct {
    double ms;
    uint64_t rounds;
    uint64_t sent_bytes;
    uint64_t recv_bytes;
    int entries;
    double t0;
    uint64_t r0, s0, v0;
} PhaseMetric;

typedef enum {
    TERM_NONE = 0,
    TERM_SUCCESS,
    TERM_HANDSHAKE_FAILED,
    TERM_CHANNEL_ERROR,
    TERM_DKG_FAILED,
    TERM_DCF_ERROR,
    TERM_PREPROCESSING_EXHAUSTED,
    TERM_POOL_REFILL_FAILED,
    TERM_OPEN_CHECK_FAILED,
    TERM_VERIFY_FAILED,
    TERM_PEER_DISAGREE
} Terminal;

const char *terminal_name(Terminal t);

typedef struct {
    int attempts;
    int batches;
    int dcf_accepts;
    int dcf_rejects;             /* DCF 判拒：z 份额从未打开 */
    int opened_candidates;       /* DCF 通过后打开了 z 的候选数 */
    int alg7_rejects_after_open; /* 打开后才被 Algorithm 7 拒绝（z 已泄露给双方） */
    int alg7_z_fail, alg7_r0_fail, alg7_ct0_fail, alg7_hint_fail;
    int accept_attempt;          /* 1-based；0 表示无 */
    int pool_items_generated;
    int pool_segments;
    int pool_refills;
    int open_checks;
    int open_check_items;
    double dfss_keygen_ms;
    double dfss_eval_ms;
    int hint_ones;
    int cs2_audit_norm;          /* 由 (w, z, t) 算出的 ||c*s2||_inf，见文档安全边界一节 */
    int cs2_audit_small;
} SignStats;

typedef struct {
    int valid;
    unsigned char token[64];
    size_t token_len;
    DilithiumCoeff mask[DILITHIUM_S_COEFFS];   /* rho_b（本方私有掩码份额） */
} PoolItem;

typedef struct {
    PoolItem *items;
    int end;
    int capacity;
} DcfPool;

/* DFSS 后端接口：真实实现来自 libdfss_sign_adapter，自检时替换为进程内 mock。 */
typedef struct {
    const char *label;
    int (*available)(void);
    int (*keygen)(const DcfDealerlessKeygenCtx *ctx, DcfDealerlessKeyShare *out);
    int (*eval)(const DcfDealerlessEvalCtx *ctx, uint32_t *failure_shares, uint64_t *eval_digests);
    void (*free_share)(DcfDealerlessKeyShare *share);
} DcfBackendOps;

extern const DcfBackendOps DCF_BACKEND_DFSS;

typedef struct {
    NodeConfig cfg;
    const DcfBackendOps *dcf;
    Channel ch;
    int b;

    char message[MAX_MESSAGE_BYTES];
    uint8_t sid[32];
    int session_id;

    unsigned char rho[MLDSA44_RHO_BYTES];
    DilithiumCoeff A[DILITHIUM_A_COEFFS];
    DilithiumCoeff A_ntt[DILITHIUM_A_COEFFS];
    uint64_t A_digest;
    DilithiumCoeff t[DILITHIUM_PK_COEFFS];
    unsigned char pk[MLDSA_PUBLICKEY_BYTES];
    DilithiumCoeff sk_share[DILITHIUM_SK_COEFFS];
    CommitCache *commit;

    DcfPool pool;
    SignStats stats;
    PhaseMetric phase[PH_COUNT];
    Terminal terminal;

    unsigned char sig[MLDSA_SIGNATURE_BYTES];
    int verify_ok;
    uint8_t sig_hash[32];
    char out_dir[512];
    int fault_inject;   /* 仅 selftest 使用：在一致性检查前篡改本方 w 视图 */
} Party;

Party *party_new(const NodeConfig *cfg, const DcfBackendOps *dcf, const char *message, const char *out_dir);
void party_free(Party *P);

void plog(const Party *P, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void phase_begin(Party *P, PhaseId id);
void phase_end(Party *P, PhaseId id);
const char *phase_name(PhaseId id);

int party_handshake(Party *P);
void party_ctx(const Party *P, const char *label, int a, int b2, uint8_t out[32]);
int party_run(Party *P);
void party_print_summary(Party *P);
int party_write_outputs(Party *P);

#endif
