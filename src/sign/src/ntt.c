/*
 * 中文源码说明：ntt.c 实现 Dilithium 域 (q=8380417, n=256) 的 NTT 与 Montgomery 约减。
 * 移植自 pq-crystals/dilithium ref 实现（ntt.c / reduce.c），并把高层接口统一为
 * 项目约定的标准 [0,q) 表示。用 NTT 替换原来的朴素 O(n^2) 负循环卷积。
 */
#include "ntt.h"

#include <string.h>

#define NTT_Q DILITHIUM_Q
#define NTT_QINV 58728449 /* q^{-1} mod 2^32 */

/*
 * Dilithium 前向 NTT 使用的 2n 次本原单位根表（bitreversed 蝴蝶用的 zetas）。
 * 数值与 pq-crystals/dilithium ref/ntt.c 完全一致。
 */
static const int32_t zetas[DILITHIUM_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/*
 * Montgomery 约减：对 -2^31*Q <= a <= Q*2^31，返回 r ≡ a*2^{-32} (mod Q)，
 * 且 -Q < r < Q。
 */
static int32_t montgomery_reduce(int64_t a) {
    int32_t t = (int64_t)(int32_t)a * NTT_QINV;
    t = (a - (int64_t)t * NTT_Q) >> 32;
    return t;
}

/* 部分约减到 [-6283008, 6283008]。 */
static int32_t reduce32(int32_t a) {
    int32_t t = (a + (1 << 22)) >> 23;
    t = a - t * NTT_Q;
    return t;
}

/* 负数加 Q，输出 [0, Q)。 */
static int32_t caddq(int32_t a) {
    a += (a >> 31) & NTT_Q;
    return a;
}

/* 前向 NTT，原地。输出为 bitreversed order，系数绝对值可到 8*Q。 */
static void dilithium_ntt(int32_t a[DILITHIUM_N]) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = zetas[++k];
            for (j = start; j < start + len; ++j) {
                t = montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

/* 逆 NTT 并乘以 Montgomery 因子 2^32，原地。 */
static void dilithium_invntt_tomont(int32_t a[DILITHIUM_N]) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    const int32_t f = 41978; /* mont^2/256 */

    k = DILITHIUM_N;
    for (len = 1; len < DILITHIUM_N; len <<= 1) {
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = -zetas[--k];
            for (j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < DILITHIUM_N; ++j) {
        a[j] = montgomery_reduce((int64_t)f * a[j]);
    }
}

/*
 * acc += a*b mod q，其中 a、b 为标准 [0,q) 表示，乘法在 R_q 中。
 * 用 NTT 完成一次稠密多项式乘法；acc 累加后仍回到 [0,q) 标准表示。
 */
void dilithium_poly_mul_acc(DilithiumCoeff acc[DILITHIUM_N],
                            const DilithiumCoeff a[DILITHIUM_N],
                            const DilithiumCoeff b[DILITHIUM_N]) {
    int32_t ta[DILITHIUM_N];
    int32_t tb[DILITHIUM_N];

    memcpy(ta, a, sizeof(ta));
    memcpy(tb, b, sizeof(tb));

    dilithium_ntt(ta);
    dilithium_ntt(tb);

    for (int i = 0; i < DILITHIUM_N; i++) {
        ta[i] = montgomery_reduce((int64_t)ta[i] * tb[i]);
    }

    dilithium_invntt_tomont(ta);

    for (int i = 0; i < DILITHIUM_N; i++) {
        /* invntt_tomont 输出在 (-Q, Q)，先归到 [0, Q)。 */
        int32_t v = reduce32(ta[i]);
        v = caddq(v);
        int32_t s = (int32_t)acc[i] + v;
        if (s >= NTT_Q) {
            s -= NTT_Q;
        }
        acc[i] = (DilithiumCoeff)s;
    }
}

/* 前向 NTT：标准 [0,q) 表示 -> NTT 域。 */
void dilithium_poly_ntt(DilithiumCoeff a[DILITHIUM_N]) {
    dilithium_ntt(a);
}

/* 逆 NTT：NTT 域 -> 标准 [0,q) 表示。 */
void dilithium_poly_invntt(DilithiumCoeff a[DILITHIUM_N]) {
    dilithium_invntt_tomont(a);
    for (int i = 0; i < DILITHIUM_N; i++) {
        int32_t v = reduce32(a[i]);
        v = caddq(v);
        a[i] = (DilithiumCoeff)v;
    }
}

/* NTT 域点乘累加：acc += a*b，a、b、acc 均为 NTT 域表示。 */
void dilithium_poly_pointwise_acc(DilithiumCoeff acc[DILITHIUM_N],
                                  const DilithiumCoeff a[DILITHIUM_N],
                                  const DilithiumCoeff b[DILITHIUM_N]) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        int32_t t = montgomery_reduce((int64_t)a[i] * b[i]);
        acc[i] = (DilithiumCoeff)(acc[i] + t);
    }
}

/* 约减 NTT 域累加结果的系数，供逆 NTT 使用。 */
void dilithium_poly_reduce32(DilithiumCoeff a[DILITHIUM_N]) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        a[i] = (DilithiumCoeff)reduce32(a[i]);
    }
}
