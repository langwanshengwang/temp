#include "dcf_dealerless_backend.h"

#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define DCF_WEAK __attribute__((weak))
#else
#define DCF_WEAK
#endif

DCF_WEAK int dcf_dealerless_backend_available(void) {
    return 0;
}

DCF_WEAK const char *dcf_dealerless_backend_name(void) {
    return "unlinked-real-dealerless-dcf-backend";
}

DCF_WEAK int dcf_dealerless_backend_keygen_share(const DcfDealerlessKeygenCtx *ctx,
                                                DcfDealerlessKeyShare *out) {
    (void)ctx;
    if (out) memset(out, 0, sizeof(*out));
    return -1;
}

DCF_WEAK int dcf_dealerless_backend_eval_failure_shares(const DcfDealerlessEvalCtx *ctx,
                                                        uint32_t *failure_shares,
                                                        uint64_t *eval_digests) {
    (void)ctx;
    if (failure_shares) failure_shares[0] = UINT32_MAX;
    if (eval_digests) eval_digests[0] = 0;
    return -1;
}

DCF_WEAK void dcf_dealerless_backend_free_key_share(DcfDealerlessKeyShare *share) {
    if (!share) return;
    free(share->key_bytes);
    memset(share, 0, sizeof(*share));
}
