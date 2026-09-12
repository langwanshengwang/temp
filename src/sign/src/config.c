/*
 * config.c —— key=value 配置解析，支持 include=。
 */
#include "config.h"

#include "common.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *pool_mode_name(PoolMode m) { return m == POOL_MODE_REFILL ? "refill" : "fixed"; }
const char *open_check_mode_name(OpenCheckMode m) { return m == OPEN_CHECK_STRICT ? "strict" : "off"; }

void config_defaults(NodeConfig *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->self_index = -1;
    cfg->mldsa_mode = MLDSA_MODE;
    cfg->batch_size = 1;
    cfg->pool_size = 4;
    cfg->pool_mode = POOL_MODE_FIXED;
    cfg->open_check = OPEN_CHECK_STRICT;
    cfg->worker_threads = 0;
    cfg->timeout_seconds = 600;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static void resolve_relative(const char *base_file, const char *value, char *out, size_t out_sz) {
    if (value[0] == '/' || !base_file) { snprintf(out, out_sz, "%s", value); return; }
    const char *slash = strrchr(base_file, '/');
    if (!slash) { snprintf(out, out_sz, "%s", value); return; }
    snprintf(out, out_sz, "%.*s/%s", (int)(slash - base_file), base_file, value);
}

static int parse_file(const char *path, NodeConfig *cfg, int depth) {
    if (depth > 4) { fprintf(stderr, "[config] include 嵌套过深: %s\n", path); return -1; }
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "[config] 无法打开 %s\n", path); return -1; }
    char line[1024];
    int lineno = 0, rc = 0;
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        char *s = trim(line);
        if (!*s) continue;
        char *eq = strchr(s, '=');
        if (!eq) { fprintf(stderr, "[config] %s:%d 缺少 '='\n", path, lineno); rc = -1; break; }
        *eq = '\0';
        char *key = trim(s), *val = trim(eq + 1);
        if (strcmp(key, "include") == 0) {
            char inc[PATH_MAX];
            resolve_relative(path, val, inc, sizeof(inc));
            if (parse_file(inc, cfg, depth + 1) != 0) { rc = -1; break; }
        } else if (strcmp(key, "party") == 0) {
            int idx, port, dport; char ip[64];
            if (sscanf(val, "%d , %63[^,] , %d , %d", &idx, ip, &port, &dport) != 4 || idx < 0 || idx > 1) {
                fprintf(stderr, "[config] %s:%d party 格式应为 party=<0|1>,<ip>,<port>,<dfss_port>\n", path, lineno);
                rc = -1; break;
            }
            cfg->party[idx].present = 1;
            snprintf(cfg->party[idx].ip, sizeof(cfg->party[idx].ip), "%s", trim(ip));
            cfg->party[idx].port = port;
            cfg->party[idx].dfss_port = dport;
        } else if (strcmp(key, "self_index") == 0) {
            cfg->self_index = atoi(val);
        } else if (strcmp(key, "private_seed_file") == 0) {
            resolve_relative(path, val, cfg->private_seed_file, sizeof(cfg->private_seed_file));
        } else if (strcmp(key, "mldsa_mode") == 0) {
            cfg->mldsa_mode = atoi(val);
        } else if (strcmp(key, "dcf_batch_size") == 0) {
            cfg->batch_size = atoi(val);
        } else if (strcmp(key, "dcf_pregen_pool_size") == 0) {
            cfg->pool_size = atoi(val);
        } else if (strcmp(key, "dcf_pool_exhaustion_mode") == 0) {
            if (strcmp(val, "fixed") == 0) cfg->pool_mode = POOL_MODE_FIXED;
            else if (strcmp(val, "refill") == 0) cfg->pool_mode = POOL_MODE_REFILL;
            else { fprintf(stderr, "[config] dcf_pool_exhaustion_mode 只能是 fixed/refill\n"); rc = -1; break; }
        } else if (strcmp(key, "open_check_mode") == 0) {
            if (strcmp(val, "strict") == 0) cfg->open_check = OPEN_CHECK_STRICT;
            else if (strcmp(val, "off") == 0) cfg->open_check = OPEN_CHECK_OFF;
            else { fprintf(stderr, "[config] open_check_mode 只能是 strict/off\n"); rc = -1; break; }
        } else if (strcmp(key, "worker_threads") == 0) {
            cfg->worker_threads = atoi(val);
        } else if (strcmp(key, "timeout_seconds") == 0) {
            cfg->timeout_seconds = atoi(val);
        } else if (strcmp(key, "ezpc_root") == 0) {
            /* 本机工具链路径属于 config/toolchain.local.conf，不是协议参数；这里忽略。 */
        } else {
            if (strcmp(key, "dcf_node") == 0 || strcmp(key, "member") == 0 ||
                strcmp(key, "self_id") == 0 || strcmp(key, "maccheck_mode") == 0) {
                fprintf(stderr,
                        "[config] %s:%d '%s' 属于旧的“协调方 + C0/C1”拓扑，本工程已改为两方对称结构，请改用 party=/self_index=/open_check_mode=\n",
                        path, lineno, key);
            } else {
                fprintf(stderr, "[config] %s:%d 未知字段 '%s'\n", path, lineno, key);
            }
            rc = -1; break;
        }
    }
    fclose(fp);
    return rc;
}

int config_validate(const NodeConfig *cfg, int require_identity) {
    if (cfg->mldsa_mode != MLDSA_MODE) {
        fprintf(stderr, "[config] mldsa_mode=%d，但分发器选中的实现是 ML-DSA-%d\n", cfg->mldsa_mode, MLDSA_MODE);
        return -1;
    }
    if (require_identity && cfg->self_index != 0 && cfg->self_index != 1) {
        fprintf(stderr, "[config] self_index 必须是 0 或 1\n"); return -1;
    }
    if (require_identity && (!cfg->party[0].present || !cfg->party[1].present)) {
        fprintf(stderr, "[config] 需要 party=0,... 与 party=1,... 两行\n"); return -1;
    }
    if (cfg->batch_size < 1 || cfg->batch_size > TDILITHIUM_DCF_BATCH_MAX) {
        fprintf(stderr, "[config] dcf_batch_size 必须在 1..%d\n", TDILITHIUM_DCF_BATCH_MAX); return -1;
    }
    if (cfg->pool_size < 1 || cfg->pool_size > 64 || cfg->pool_size < cfg->batch_size) {
        fprintf(stderr, "[config] dcf_pregen_pool_size 必须在 1..64 且不小于 dcf_batch_size\n"); return -1;
    }
    if (cfg->timeout_seconds < 5) { fprintf(stderr, "[config] timeout_seconds 至少为 5\n"); return -1; }
    if (require_identity) {
        for (int i = 0; i < 2; i++) {
            if (cfg->party[i].port <= 0 || cfg->party[i].dfss_port <= 0) {
                fprintf(stderr, "[config] party=%d 的端口无效\n", i); return -1;
            }
        }
        int d0 = cfg->party[0].dfss_port, p0 = cfg->party[0].port, p1 = cfg->party[1].port;
        int reserved[] = { d0, d0 + 3, d0 + 50, d0 + 100 };
        for (int k = 0; k < 4; k++) {
            if (reserved[k] == p0 || (strcmp(cfg->party[0].ip, cfg->party[1].ip) == 0 && reserved[k] == p1)) {
                fprintf(stderr, "[config] 协议端口与 DFSS 端口(base,+3,+50,+100)冲突\n"); return -1;
            }
        }
    }
    return 0;
}

int config_load(const char *path, NodeConfig *cfg, int require_identity) {
    config_defaults(cfg);
    char abs[PATH_MAX];
    const char *p = realpath(path, abs) ? abs : path;
    if (parse_file(p, cfg, 0) != 0) return -1;
    return config_validate(cfg, require_identity);
}

void config_print(const NodeConfig *cfg) {
    printf("[config] self=P%d mldsa=ML-DSA-%d batch_K=%d pool_L=%d pool_mode=%s open_check=%s worker_threads=%d timeout=%ds\n",
           cfg->self_index, cfg->mldsa_mode, cfg->batch_size, cfg->pool_size,
           pool_mode_name(cfg->pool_mode), open_check_mode_name(cfg->open_check),
           cfg->worker_threads, cfg->timeout_seconds);
    for (int i = 0; i < 2; i++) {
        printf("[config] P%d endpoint=%s:%d dfss_port=%d%s\n", i, cfg->party[i].ip,
               cfg->party[i].port, cfg->party[i].dfss_port, i == cfg->self_index ? " (self)" : "");
    }
}
