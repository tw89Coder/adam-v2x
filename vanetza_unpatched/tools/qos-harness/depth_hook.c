#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdatomic.h>
#include <stddef.h>

/* reference the weak symbols defined in qos_measure binary */
extern _Atomic int  g_seq_decode_max_depth;
extern _Atomic int  g_seq_decode_cur_depth;
extern _Atomic long g_seq_decode_calls;

typedef struct { size_t max_stack_size; } asn_codec_ctx_t;
typedef struct asn_TYPE_descriptor_s asn_TYPE_descriptor_t;
typedef enum { RC_OK=0, RC_WMORE=-1, RC_FAIL=-2 } asn_dec_code_t;
typedef struct { size_t consumed; asn_dec_code_t code; } asn_dec_rval_t;
typedef asn_dec_rval_t (*real_fn_t)(const asn_codec_ctx_t *,
                                    const asn_TYPE_descriptor_t *,
                                    void **, const void *, size_t, int);

asn_dec_rval_t
SEQUENCE_decode_ber(const asn_codec_ctx_t *opt_codec_ctx,
                    const asn_TYPE_descriptor_t *td,
                    void **struct_ptr,
                    const void *ptr, size_t size, int tag_mode) {
    static real_fn_t real_fn = NULL;
    if (!real_fn)
        real_fn = (real_fn_t)dlsym(RTLD_NEXT, "SEQUENCE_decode_ber");

    int d = atomic_fetch_add(&g_seq_decode_cur_depth, 1) + 1;
    atomic_fetch_add(&g_seq_decode_calls, 1);
    int m = atomic_load(&g_seq_decode_max_depth);
    while (d > m)
        atomic_compare_exchange_weak(&g_seq_decode_max_depth, &m, d);

    asn_dec_rval_t ret = real_fn(opt_codec_ctx, td, struct_ptr, ptr, size, tag_mode);

    atomic_fetch_sub(&g_seq_decode_cur_depth, 1);
    return ret;
}