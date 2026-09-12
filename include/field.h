/*
 * field.h —— 模 q 基本运算与序列化工具。
 */
#ifndef FIELD_H
#define FIELD_H

#include "common.h"

#include <stddef.h>
#include <stdint.h>

/* 规约到 [0,q)。 */
DilithiumCoeff dilithium_mod_q(int64_t x);
/* 中心表示的小整数 → [0,q)。 */
DilithiumCoeff dilithium_centered_to_mod_q(int32_t x);
/* [0,q) → 中心表示 (-q/2, q/2]。 */
int32_t dilithium_mod_q_to_centered(DilithiumCoeff x);

/* 仅用于日志的 64 位 FNV-1a 摘要（非密码学用途）。 */
uint64_t field_digest_coeffs(const DilithiumCoeff *v, int n);
uint64_t field_digest_bytes(const unsigned char *buf, size_t len);

/* 24 比特定长打包：每个 [0,q) 系数 3 字节，小端。 */
size_t field_pack24_len(int count);
void field_pack24(unsigned char *out, const DilithiumCoeff *v, int count);
/* 返回 -1 表示存在 >= q 的非法系数。 */
int field_unpack24(DilithiumCoeff *v, const unsigned char *in, int count);

void field_add_vec(DilithiumCoeff *dst, const DilithiumCoeff *a, const DilithiumCoeff *b, int n);

#endif
