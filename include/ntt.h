/*
 * 中文头文件说明：ntt.h 声明 Dilithium 域 (q=8380417, n=256) 的数论变换接口。
 * 实现移植自 pq-crystals/dilithium 的 ref 实现，用于把原来的 O(n^2) 朴素
 * 负循环卷积替换为 O(n log n) 的 NTT 多项式乘法。
 *
 * 语义约定：除特别说明外，接口输入/输出均为标准 [0,q) 表示（与 DilithiumCoeff
 * 约定一致）。NTT 域中间表示（bitreversed + Montgomery 因子）只在本模块内部使用。
 */
#ifndef DILITHIUM_NTT_H
#define DILITHIUM_NTT_H

#include "common.h"

#include <stdint.h>

/* 在标准 [0,q) 表示下计算 acc += a*b mod q，其中乘法在
 * R_q = Z_q[X]/(X^N+1) 中，使用 NTT 完成。三个参数均按 DILITHIUM_N 个系数布局。 */
void dilithium_poly_mul_acc(DilithiumCoeff acc[DILITHIUM_N],
                            const DilithiumCoeff a[DILITHIUM_N],
                            const DilithiumCoeff b[DILITHIUM_N]);

/* 前向 NTT：标准 [0,q) 表示 -> NTT 域（bitreversed + Montgomery 因子 2^32）。 */
void dilithium_poly_ntt(DilithiumCoeff a[DILITHIUM_N]);

/* 逆 NTT：NTT 域 -> 标准 [0,q) 表示。输入系数绝对值须小于 2*Q。 */
void dilithium_poly_invntt(DilithiumCoeff a[DILITHIUM_N]);

/* NTT 域点乘累加：acc += a*b mod q（a、b、acc 均为 NTT 域表示）。
 * 多次累加后调用 dilithium_poly_reduce32 再 dilithium_poly_invntt。 */
void dilithium_poly_pointwise_acc(DilithiumCoeff acc[DILITHIUM_N],
                                  const DilithiumCoeff a[DILITHIUM_N],
                                  const DilithiumCoeff b[DILITHIUM_N]);

/* 将 NTT 域累加结果的系数约减到 [-0.75q, 0.75q]，供逆 NTT 使用。 */
void dilithium_poly_reduce32(DilithiumCoeff a[DILITHIUM_N]);

#endif
