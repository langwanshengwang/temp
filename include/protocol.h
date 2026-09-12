/*
 * protocol.h —— 各阶段入口与消息标签。
 */
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "party.h"

/* 信道帧标签（高 8 位区分阶段，便于在失步日志中定位）。 */
#define TAG_HELLO            0x01000001U
#define TAG_DKG_A_COMMIT     0x02000001U
#define TAG_DKG_T_SHARE      0x02000002U
#define TAG_POOL_SYNC        0x03000001U
#define TAG_POOL_DONE        0x03000002U
#define TAG_SIGN_COMMIT      0x04000001U
#define TAG_DCF_MASKED       0x05000001U
#define TAG_DCF_PHI          0x05000002U
#define TAG_OPEN_ZR          0x06000001U
#define TAG_CHECK_COIN       0x07000001U
#define TAG_CHECK_VALUES     0x07000002U
#define TAG_FINAL            0x08000001U

int dkg_run(Party *P);

/* 生成池项 [first, first+count)。两方必须以相同参数同时调用。 */
int dcf_pool_generate(Party *P, int first, int count);
/* 确保 [a0, a0+K) 可用；按 fixed/refill 语义处理耗尽。 */
int dcf_pool_ensure(Party *P, int a0, int K);
void dcf_pool_free(DcfPool *pool);

struct Candidate;
/* 对一批候选运行在线 DCF 比较，写回每个候选的 dcf_accept。 */
int dcf_rejects_batch(Party *P, struct Candidate *cands, int K);

typedef struct {
    const char *label;
    const DilithiumCoeff *view;
    int n;
} OpenCheckItem;
/* 严格打开一致性检查；返回 1 通过，0 不一致，-1 通信错误。 */
int open_check_run(Party *P, const char *scope, int attempt, const OpenCheckItem *items, int count);

int sign_run(Party *P);

#endif
