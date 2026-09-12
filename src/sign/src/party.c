/*
 * party.c —— 参与方生命周期、日志与度量、会话握手、结果输出。
 */
#define _GNU_SOURCE
#include "party.h"

#include "fips202.h"
#include "mldsa_compat.h"
#include "protocol.h"
#include "secure_random.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

const char *terminal_name(Terminal t) {
    switch (t) {
        case TERM_NONE: return "NONE";
        case TERM_SUCCESS: return "SUCCESS";
        case TERM_HANDSHAKE_FAILED: return "HANDSHAKE_FAILED";
        case TERM_CHANNEL_ERROR: return "CHANNEL_ERROR";
        case TERM_DKG_FAILED: return "DKG_FAILED";
        case TERM_DCF_ERROR: return "DCF_ERROR";
        case TERM_PREPROCESSING_EXHAUSTED: return "PREPROCESSING_EXHAUSTED";
        case TERM_POOL_REFILL_FAILED: return "POOL_REFILL_FAILED";
        case TERM_OPEN_CHECK_FAILED: return "OPEN_CHECK_FAILED";
        case TERM_VERIFY_FAILED: return "VERIFY_FAILED";
        case TERM_PEER_DISAGREE: return "PEER_DISAGREE";
    }
    return "UNKNOWN";
}

const char *phase_name(PhaseId id) {
    static const char *names[PH_COUNT] = {
        "handshake", "dkeygen", "dcf_prep", "sign_attempt",
        "rejects_dcf_online", "open_zr_alg7", "open_check", "verify"
    };
    return (id >= 0 && id < PH_COUNT) ? names[id] : "?";
}

void plog(const Party *P, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[P%d] ", P->b);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
    fflush(stdout);
}

void phase_begin(Party *P, PhaseId id) {
    PhaseMetric *m = &P->phase[id];
    m->t0 = now_ms();
    m->r0 = P->ch.rounds;
    m->s0 = P->ch.sent_bytes;
    m->v0 = P->ch.recv_bytes;
}

void phase_end(Party *P, PhaseId id) {
    PhaseMetric *m = &P->phase[id];
    m->ms += now_ms() - m->t0;
    m->rounds += P->ch.rounds - m->r0;
    m->sent_bytes += P->ch.sent_bytes - m->s0;
    m->recv_bytes += P->ch.recv_bytes - m->v0;
    m->entries++;
}

Party *party_new(const NodeConfig *cfg, const DcfBackendOps *dcf, const char *message, const char *out_dir) {
    Party *P = (Party *)calloc(1, sizeof(Party));
    if (!P) return NULL;
    P->commit = (CommitCache *)calloc(1, sizeof(CommitCache));
    if (!P->commit) { free(P); return NULL; }
    P->cfg = *cfg;
    P->dcf = dcf;
    P->b = cfg->self_index;
    P->ch.fd = -1;
    snprintf(P->message, sizeof(P->message), "%s", message ? message : "");
    snprintf(P->out_dir, sizeof(P->out_dir), "%s", out_dir ? out_dir : "");
    return P;
}

void party_free(Party *P) {
    if (!P) return;
    channel_close(&P->ch);
    dcf_pool_free(&P->pool);
    secure_bzero(P->sk_share, sizeof(P->sk_share));
    free(P->commit);
    secure_bzero(P, sizeof(*P));
    free(P);
}

void party_ctx(const Party *P, const char *label, int a, int b2, uint8_t out[32]) {
    uint8_t buf[256];
    size_t off = 0;
    static const char dom[] = "TPM2-CTX";
    memcpy(buf + off, dom, sizeof(dom) - 1); off += sizeof(dom) - 1;
    memcpy(buf + off, P->sid, 32); off += 32;
    size_t ll = strlen(label);
    if (ll > 128) ll = 128;
    memcpy(buf + off, label, ll); off += ll;
    for (int k = 0; k < 4; k++) buf[off++] = (uint8_t)((uint32_t)a >> (8 * k));
    for (int k = 0; k < 4; k++) buf[off++] = (uint8_t)((uint32_t)b2 >> (8 * k));
    sha3_256(out, buf, off);
}

/* ---------------------------------------------------------------- */
/* 握手                                                              */
/* ---------------------------------------------------------------- */

#define HELLO_BYTES 128

static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void encode_hello(const Party *P, const uint8_t nonce[32], uint8_t out[HELLO_BYTES]) {
    memset(out, 0, HELLO_BYTES);
    memcpy(out, "TPM2HELO", 8);
    uint32_t fields[] = {
        2u, (uint32_t)MLDSA_MODE, (uint32_t)P->b,
        (uint32_t)P->cfg.batch_size, (uint32_t)P->cfg.pool_size,
        (uint32_t)P->cfg.pool_mode, (uint32_t)P->cfg.open_check,
        (uint32_t)P->cfg.party[0].dfss_port, (uint32_t)P->cfg.party[1].dfss_port
    };
    for (int i = 0; i < 9; i++) put32(out + 8 + 4 * i, fields[i]);
    sha3_256(out + 44, (const uint8_t *)P->message, strlen(P->message));
    memcpy(out + 76, nonce, 32);
}

int party_handshake(Party *P) {
    uint8_t nonce[32], mine[HELLO_BYTES], peer[HELLO_BYTES];
    if (secure_random_os_bytes(nonce, 32) != 0) return -1;
    encode_hello(P, nonce, mine);
    if (channel_exchange_fixed(&P->ch, TAG_HELLO, mine, peer, HELLO_BYTES) != 0) return -1;

    if (memcmp(peer, "TPM2HELO", 8) != 0 || get32(peer + 8) != 2u) {
        plog(P, "握手失败：对方不是本协议版本"); return -1;
    }
    if (get32(peer + 16) != (uint32_t)(1 - P->b)) {
        plog(P, "握手失败：双方 self_index 冲突（对方声明自己是 P%u）", get32(peer + 16)); return -1;
    }
    static const char *names[] = { "version", "mldsa_mode", "self_index", "dcf_batch_size",
                                   "dcf_pregen_pool_size", "dcf_pool_exhaustion_mode",
                                   "open_check_mode", "P0.dfss_port", "P1.dfss_port" };
    for (int i = 0; i < 9; i++) {
        if (i == 2) continue;
        if (get32(peer + 8 + 4 * i) != get32(mine + 8 + 4 * i)) {
            plog(P, "握手失败：参数 %s 不一致（本方 %u，对方 %u）", names[i],
                 get32(mine + 8 + 4 * i), get32(peer + 8 + 4 * i));
            return -1;
        }
    }
    if (memcmp(peer + 44, mine + 44, 32) != 0) {
        plog(P, "握手失败：双方授权签名的消息不同——两方门限签名要求双方各自同意同一条消息");
        return -1;
    }
    uint8_t buf[8 + 2 * HELLO_BYTES];
    memcpy(buf, "TPM2-SID", 8);
    memcpy(buf + 8, P->b == 0 ? mine : peer, HELLO_BYTES);
    memcpy(buf + 8 + HELLO_BYTES, P->b == 0 ? peer : mine, HELLO_BYTES);
    sha3_256(P->sid, buf, sizeof(buf));
    P->session_id = (int)(get32(P->sid) & 0x7fffffffU);
    if (P->session_id == 0) P->session_id = 1;
    plog(P, "握手完成：session_id=%d，sid=%02x%02x%02x%02x…，双方参数与待签消息一致",
         P->session_id, P->sid[0], P->sid[1], P->sid[2], P->sid[3]);
    return 0;
}

/* ---------------------------------------------------------------- */
/* 顶层流程                                                          */
/* ---------------------------------------------------------------- */

/* 阶段分隔线：让日志按“第几步在做什么”分块，便于定位。 */
static void pstage(const Party *P, int idx, const char *name) {
    printf("\n[P%d] ───────── 阶段 %d/4 · %s ─────────\n", P->b, idx, name);
    fflush(stdout);
}

int party_run(Party *P) {
    printf("\n[P%d] ══════════ 2-of-2 门限 %s · 本方 = 签名方 P%d = DFSS 比较方 C%d ══════════\n",
           P->b, MLDSA_LEVEL_NAME, P->b, P->b);
    plog(P, "拓扑：无协调方，两方运行同一份顺序代码，每一步同时交换");
    plog(P, "待签消息：%zu 字节，摘要见握手日志（两方不一致会在握手阶段中止）", strlen(P->message));
    if (!P->dcf->available()) {
        plog(P, "DFSS 后端不可用（%s），拒绝运行（fail-closed）。", P->dcf->label);
        P->terminal = TERM_DCF_ERROR;
        return -1;
    }
    pstage(P, 1, "握手（校验参数与待签消息一致）");
    phase_begin(P, PH_HANDSHAKE);
    int rc = party_handshake(P);
    phase_end(P, PH_HANDSHAKE);
    if (rc != 0) { P->terminal = TERM_HANDSHAKE_FAILED; return -1; }
    pstage(P, 2, "DKeyGen（分布式密钥生成）");
    if (dkg_run(P) != 0) {
        if (P->terminal == TERM_NONE) P->terminal = TERM_DKG_FAILED;
        return -1;
    }
    pstage(P, 3, "DCFPrep（离线：一次性 DFSS 密钥与掩码，通常是耗时大头）");
    if (dcf_pool_generate(P, 0, P->cfg.pool_size) != 0) {
        if (P->terminal == TERM_NONE) P->terminal = TERM_DCF_ERROR;
        return -1;
    }
    pstage(P, 4, "DSign + Verify（候选、DCF 拒绝采样、打开、标准验签）");
    return sign_run(P);
}

/* ---------------------------------------------------------------- */
/* 输出                                                              */
/* ---------------------------------------------------------------- */

static void hex(char *out, const uint8_t *in, size_t n) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[in[i] >> 4]; out[2 * i + 1] = d[in[i] & 15]; }
    out[2 * n] = '\0';
}

void party_print_summary(Party *P) {
    /* 表格用固定列宽渲染；标签一律放在竖线左侧的纯 ASCII 列里，避免中英混排错位。 */
    static const char *RULE =
        "──────────────────────┼────────────┼────────┼────────────┼────────────┼──────";
    printf("\n[P%d] ══════════ 阶段汇总（本方视角，仅 P0↔P1 协议信道）══════════\n", P->b);
    printf("  phase               │    time_ms │ rounds │   sent_KiB │   recv_KiB │ calls\n");
    printf("%s\n", RULE);
    uint64_t tot_r = 0, tot_s = 0, tot_v = 0;
    double tot_ms = 0;
    for (int i = 0; i < PH_COUNT; i++) {
        PhaseMetric *m = &P->phase[i];
        printf("  %-19s │ %10.3f │ %6llu │ %10.3f │ %10.3f │ %5d\n",
               phase_name((PhaseId)i), m->ms, (unsigned long long)m->rounds,
               (double)m->sent_bytes / 1024.0, (double)m->recv_bytes / 1024.0, m->entries);
        tot_ms += m->ms; tot_r += m->rounds; tot_s += m->sent_bytes; tot_v += m->recv_bytes;
    }
    printf("%s\n", RULE);
    printf("  %-19s │ %10.3f │ %6llu │ %10.3f │ %10.3f │\n",
           "TOTAL", tot_ms, (unsigned long long)tot_r,
           (double)tot_s / 1024.0, (double)tot_v / 1024.0);
    printf("  注：以上不含 DFSS 内部 2PC 流量——离线每个池项在 DFSS 自己的连接上要走数 MiB，\n"
           "      节点看不到，只能由适配器的 DFSS_CORE_* 行记录。两侧合并后的完整口径见\n"
           "      scripts/report.py 生成的 report.txt / report.json。\n");

    SignStats *s = &P->stats;
    printf("\n[P%d] ══════════ 本次运行 ══════════\n", P->b);
    printf("  · 配置：%s，K=%d，L=%d（%s），open_check=%s\n",
           MLDSA_LEVEL_NAME, P->cfg.batch_size, P->cfg.pool_size,
           pool_mode_name(P->cfg.pool_mode), open_check_mode_name(P->cfg.open_check));
    printf("  · 离线池：生成 %d 项 / %d 段 / 续池 %d 次；本方计时 keygen=%.3f ms，eval=%.3f ms\n",
           s->pool_items_generated, s->pool_segments, s->pool_refills,
           s->dfss_keygen_ms, s->dfss_eval_ms);
    printf("  · 拒绝采样：尝试 %d 次 / 批 %d 个；DCF accept=%d reject=%d；已打开候选 %d\n",
           s->attempts, s->batches, s->dcf_accepts, s->dcf_rejects, s->opened_candidates);
    printf("  · 打开后被 Algorithm 7 拒绝：%d 次（z=%d r0=%d ct0=%d hint=%d）\n",
           s->alg7_rejects_after_open, s->alg7_z_fail, s->alg7_r0_fail,
           s->alg7_ct0_fail, s->alg7_hint_fail);
    printf("  · 打开一致性检查：mode=%s，checks=%d，items=%d\n",
           open_check_mode_name(P->cfg.open_check), s->open_checks, s->open_check_items);
    if (P->terminal == TERM_SUCCESS) {
        printf("  · 审计：||c*s2||_inf=%d（%s）——这是协议边界，不是实现错误\n",
               s->cs2_audit_norm,
               s->cs2_audit_small ? "短向量，任一方可由 (w,z,t) 反解 s2" : "异常");
    }
    char sh[65];
    hex(sh, P->sig_hash, 32);
    printf("[P%d] verify_result=%s terminal_reason=%s accept_attempt=%d attempts=%d hint_ones=%d signature_sha3=%s\n",
           P->b, P->verify_ok ? "ACCEPT" : "REJECT", terminal_name(P->terminal),
           s->accept_attempt, s->attempts, s->hint_ones, P->terminal == TERM_SUCCESS ? sh : "-");
    printf("[P%d] ══════════════════════════════════════════════\n", P->b);
    fflush(stdout);
}

static int write_file(const char *dir, const char *name, const uint8_t *buf, size_t len) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    size_t n = fwrite(buf, 1, len, fp);
    fclose(fp);
    return n == len ? 0 : -1;
}

int party_write_outputs(Party *P) {
    if (!P->out_dir[0]) return 0;
    mkdir(P->out_dir, 0755);
    if (P->terminal == TERM_SUCCESS) {
        write_file(P->out_dir, "public_key.bin", P->pk, MLDSA_PUBLICKEY_BYTES);
        write_file(P->out_dir, "signature.bin", P->sig, MLDSA_SIGNATURE_BYTES);
        write_file(P->out_dir, "message.txt", (const uint8_t *)P->message, strlen(P->message));
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/summary.json", P->out_dir);
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    char sh[65];
    hex(sh, P->sig_hash, 32);
    SignStats *s = &P->stats;
    fprintf(fp, "{\n  \"party\": %d,\n  \"mldsa_mode\": %d,\n  \"verify_result\": \"%s\",\n  \"terminal_reason\": \"%s\",\n",
            P->b, MLDSA_MODE, P->verify_ok ? "ACCEPT" : "REJECT", terminal_name(P->terminal));
    fprintf(fp, "  \"session_id\": %d,\n  \"signature_sha3\": \"%s\",\n", P->session_id,
            P->terminal == TERM_SUCCESS ? sh : "");
    fprintf(fp, "  \"config\": {\"batch_size\": %d, \"pool_size\": %d, \"pool_mode\": \"%s\", \"open_check\": \"%s\"},\n",
            P->cfg.batch_size, P->cfg.pool_size, pool_mode_name(P->cfg.pool_mode), open_check_mode_name(P->cfg.open_check));
    fprintf(fp, "  \"stats\": {\"attempts\": %d, \"batches\": %d, \"accept_attempt\": %d, \"dcf_accepts\": %d, \"dcf_rejects\": %d, "
                "\"opened_candidates\": %d, \"alg7_rejects_after_open\": %d, \"alg7_z_fail\": %d, \"alg7_r0_fail\": %d, "
                "\"alg7_ct0_fail\": %d, \"alg7_hint_fail\": %d, \"pool_items_generated\": %d, \"pool_segments\": %d, "
                "\"pool_refills\": %d, \"open_checks\": %d, \"open_check_items\": %d, \"dfss_keygen_ms\": %.3f, "
                "\"dfss_eval_ms\": %.3f, \"hint_ones\": %d, \"cs2_audit_norm\": %d},\n",
            s->attempts, s->batches, s->accept_attempt, s->dcf_accepts, s->dcf_rejects, s->opened_candidates,
            s->alg7_rejects_after_open, s->alg7_z_fail, s->alg7_r0_fail, s->alg7_ct0_fail, s->alg7_hint_fail,
            s->pool_items_generated, s->pool_segments, s->pool_refills, s->open_checks, s->open_check_items,
            s->dfss_keygen_ms, s->dfss_eval_ms, s->hint_ones, s->cs2_audit_norm);
    fprintf(fp, "  \"phases\": {\n");
    for (int i = 0; i < PH_COUNT; i++) {
        PhaseMetric *m = &P->phase[i];
        fprintf(fp, "    \"%s\": {\"time_ms\": %.3f, \"rounds\": %llu, \"sent_bytes\": %llu, \"recv_bytes\": %llu, \"entries\": %d}%s\n",
                phase_name((PhaseId)i), m->ms, (unsigned long long)m->rounds, (unsigned long long)m->sent_bytes,
                (unsigned long long)m->recv_bytes, m->entries, i + 1 < PH_COUNT ? "," : "");
    }
    fprintf(fp, "  }\n}\n");
    fclose(fp);
    return 0;
}
