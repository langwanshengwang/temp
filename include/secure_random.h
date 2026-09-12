#ifndef SECURE_RANDOM_H
#define SECURE_RANDOM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Process-local CSPRNG used by the hardened research profile.
 * Entropy is obtained only from the operating system.  There is deliberately
 * no time(), rand(), PID, node-id, or public-transcript fallback.
 */
typedef struct {
    uint8_t key[32];
    uint64_t counter;
    uint8_t buffer[136];
    size_t available;
    int initialized;
} SecureRandom;

int secure_random_os_bytes(void *out, size_t out_len);
int secure_random_init(SecureRandom *rng, const char *domain,
                       const void *context, size_t context_len);
int secure_random_bytes(SecureRandom *rng, void *out, size_t out_len);
int secure_random_u32_below(SecureRandom *rng, uint32_t upper_exclusive,
                            uint32_t *out);
int secure_random_centered(SecureRandom *rng, int32_t bound, int32_t *out);
void secure_random_destroy(SecureRandom *rng);
void secure_bzero(void *ptr, size_t len);

#endif
