#define _GNU_SOURCE
#include "secure_random.h"
#include "fips202.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

static void store_u64_le(uint8_t out[8], uint64_t x) {
    for (unsigned i = 0; i < 8; i++) {
        out[i] = (uint8_t)(x >> (8U * i));
    }
}

void secure_bzero(void *ptr, size_t len) {
    if (!ptr || len == 0) return;
#if defined(__STDC_LIB_EXT1__)
    memset_s(ptr, len, 0, len);
#else
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
#endif
}

static int read_urandom_exact(void *out, size_t out_len) {
    int fd;
    do {
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;

    uint8_t *p = (uint8_t *)out;
    size_t off = 0;
    while (off < out_len) {
        ssize_t n = read(fd, p + off, out_len - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        close(fd);
        secure_bzero(out, out_len);
        return -1;
    }
    close(fd);
    return 0;
}

int secure_random_os_bytes(void *out, size_t out_len) {
    if (!out && out_len != 0) return -1;
    uint8_t *p = (uint8_t *)out;
    size_t off = 0;

    while (off < out_len) {
        ssize_t n = getrandom(p + off, out_len - off, 0);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == ENOSYS) break;
        secure_bzero(out, out_len);
        return -1;
    }
    if (off == out_len) return 0;

    /* /dev/urandom is an OS CSPRNG compatibility path, not a weak fallback. */
    secure_bzero(out, out_len);
    return read_urandom_exact(out, out_len);
}

static int read_private_seed_from_env(uint8_t out[32], int *present) {
    const char *path = getenv("TDILITHIUM_NODE_SEED_FILE");
    *present = 0;
    if (!path || !path[0]) return 0;
    struct stat sb;
    if (lstat(path, &sb) != 0 || !S_ISREG(sb.st_mode) || (sb.st_mode & 077) != 0) {
        fprintf(stderr, "private_seed_file must be a regular owner-only file: %s\n", path);
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < 32) {
        ssize_t got = read(fd, out + off, 32 - off);
        if (got > 0) { off += (size_t)got; continue; }
        if (got < 0 && errno == EINTR) continue;
        close(fd);
        secure_bzero(out, 32);
        return -1;
    }
    close(fd);
    *present = 1;
    return 0;
}

int secure_random_init(SecureRandom *rng, const char *domain,
                       const void *context, size_t context_len) {
    if (!rng || !domain || (!context && context_len != 0)) return -1;
    memset(rng, 0, sizeof(*rng));

    uint8_t entropy[48];
    uint8_t private_seed[32];
    int have_private_seed = 0;
    if (secure_random_os_bytes(entropy, sizeof(entropy)) != 0 ||
        read_private_seed_from_env(private_seed, &have_private_seed) != 0) {
        secure_bzero(entropy, sizeof(entropy));
        secure_bzero(private_seed, sizeof(private_seed));
        return -1;
    }

    keccak_state st;
    shake256_init(&st);
    static const uint8_t prefix[] = "threshold-mldsa-hardened-csprng-v1";
    shake256_absorb(&st, prefix, sizeof(prefix) - 1);
    uint64_t domain_len = (uint64_t)strlen(domain);
    uint8_t lenbuf[8];
    store_u64_le(lenbuf, domain_len);
    shake256_absorb(&st, lenbuf, sizeof(lenbuf));
    shake256_absorb(&st, (const uint8_t *)domain, (size_t)domain_len);
    store_u64_le(lenbuf, (uint64_t)context_len);
    shake256_absorb(&st, lenbuf, sizeof(lenbuf));
    if (context_len) shake256_absorb(&st, (const uint8_t *)context, context_len);
    shake256_absorb(&st, entropy, sizeof(entropy));
    if (have_private_seed) shake256_absorb(&st, private_seed, sizeof(private_seed));
    shake256_finalize(&st);
    shake256_squeeze(rng->key, sizeof(rng->key), &st);
    secure_bzero(&st, sizeof(st));
    secure_bzero(entropy, sizeof(entropy));
    secure_bzero(private_seed, sizeof(private_seed));
    secure_bzero(lenbuf, sizeof(lenbuf));

    rng->counter = 0;
    rng->available = 0;
    rng->initialized = 1;
    return 0;
}

static int refill(SecureRandom *rng) {
    if (!rng || !rng->initialized || rng->counter == UINT64_MAX) return -1;
    uint8_t input[32 + 8 + 24];
    size_t off = 0;
    static const uint8_t label[] = "shake256-drbg-block-v1";
    memcpy(input + off, label, sizeof(label) - 1); off += sizeof(label) - 1;
    memcpy(input + off, rng->key, sizeof(rng->key)); off += sizeof(rng->key);
    store_u64_le(input + off, rng->counter++); off += 8;
    shake256(rng->buffer, sizeof(rng->buffer), input, off);
    secure_bzero(input, sizeof(input));
    rng->available = sizeof(rng->buffer);
    return 0;
}

int secure_random_bytes(SecureRandom *rng, void *out, size_t out_len) {
    if (!rng || !rng->initialized || (!out && out_len != 0)) return -1;
    uint8_t *dst = (uint8_t *)out;
    while (out_len) {
        if (rng->available == 0 && refill(rng) != 0) return -1;
        size_t start = sizeof(rng->buffer) - rng->available;
        size_t take = out_len < rng->available ? out_len : rng->available;
        memcpy(dst, rng->buffer + start, take);
        secure_bzero(rng->buffer + start, take);
        rng->available -= take;
        dst += take;
        out_len -= take;
    }
    return 0;
}

int secure_random_u32_below(SecureRandom *rng, uint32_t upper_exclusive,
                            uint32_t *out) {
    if (!rng || !out || upper_exclusive == 0) return -1;
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % upper_exclusive);
    for (;;) {
        uint8_t b[4];
        if (secure_random_bytes(rng, b, sizeof(b)) != 0) return -1;
        uint32_t x = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                     ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        secure_bzero(b, sizeof(b));
        if (x < limit) {
            *out = x % upper_exclusive;
            return 0;
        }
    }
}

int secure_random_centered(SecureRandom *rng, int32_t bound, int32_t *out) {
    if (!rng || !out || bound < 0 || bound > INT32_MAX / 2) return -1;
    uint32_t width = (uint32_t)(2 * bound + 1);
    uint32_t x;
    if (secure_random_u32_below(rng, width, &x) != 0) return -1;
    *out = (int32_t)x - bound;
    return 0;
}

void secure_random_destroy(SecureRandom *rng) {
    if (!rng) return;
    secure_bzero(rng, sizeof(*rng));
}
