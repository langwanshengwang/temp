/*
 * config.h —— 节点配置。
 *
 * 公共拓扑写在 common.*.conf，每台主机的私有身份写在 nodes/p{0,1}.conf，
 * 运行时由 scripts/prepare_runtime_configs.py 生成一个 include 两者的配置。
 *
 *   party=<b>,<ip>,<protocol_port>,<dfss_port>   两行，b ∈ {0,1}
 *   self_index=<b>                               私有配置
 *   private_seed_file=<path>                     私有配置，相对该文件所在目录
 *   mldsa_mode=44|65|87                          运行时选择（同一 node 含三套实现）
 *   dcf_batch_size=K (1..8)
 *   dcf_pregen_pool_size=L (1..64, 且 L >= K)
 *   dcf_pool_exhaustion_mode=fixed|refill
 *   open_check_mode=strict|off
 *   worker_threads=0                             DFSS 在线阶段线程数，0=自动
 *   timeout_seconds=600                          单次信道收发超时
 */
#ifndef CONFIG_H
#define CONFIG_H

typedef enum { POOL_MODE_FIXED = 0, POOL_MODE_REFILL = 1 } PoolMode;
typedef enum { OPEN_CHECK_OFF = 0, OPEN_CHECK_STRICT = 1 } OpenCheckMode;

typedef struct {
    int present;
    char ip[64];
    int port;        /* 协议信道端口；只有 P0 实际监听 */
    int dfss_port;   /* DFSS/EzPC 基端口；适配器还会使用 +3、+50、+100 */
} PartyEndpoint;

typedef struct {
    int self_index;
    int mldsa_mode;
    PartyEndpoint party[2];
    int batch_size;
    int pool_size;
    PoolMode pool_mode;
    OpenCheckMode open_check;
    int worker_threads;
    int timeout_seconds;
    char private_seed_file[512];
} NodeConfig;

void config_defaults(NodeConfig *cfg);
int config_load(const char *path, NodeConfig *cfg, int require_identity);
int config_validate(const NodeConfig *cfg, int require_identity);
void config_print(const NodeConfig *cfg);
const char *pool_mode_name(PoolMode m);
const char *open_check_mode_name(OpenCheckMode m);

#endif
