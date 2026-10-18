#ifndef __GOSNOOP_IOV_COMPAT_H__
#define __GOSNOOP_IOV_COMPAT_H__

#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

/*
 * Reading the payload out of a `struct msghdr` means walking `struct iov_iter`,
 * which the kernel has reshaped a few times:
 *
 *   <= 6.3   the iovec array lives in `msg_iter.iov`
 *      6.4   `iov` was renamed to `__iov`, and `ubuf` holds the buffer for a
 *            single-segment (ITER_UBUF) iterator
 *   >= 6.5   `__ubuf_iovec` overlays `{__iov, count}`, so an ITER_UBUF iterator
 *            keeps its user pointer in the slot `__iov` occupies and its length
 *            in `count`
 *
 * CO-RE type flavors let a single object file cope with all of them. libbpf
 * strips the `___` suffix, matches `iov_iter___gosnoop` against the running
 * kernel's `iov_iter`, and resolves each field *by name* — so the layout of the
 * structs below is irrelevant, only the field names matter. Field and enum
 * probes are patched to constants before verification, and the verifier then
 * drops the branches that do not apply to this kernel.
 */
struct iov_iter___gosnoop
{
    u8 iter_type;
    size_t count;
    const struct iovec *iov;
    const struct iovec *__iov;
    void *ubuf;
    struct iovec __ubuf_iovec;
};

struct msghdr___gosnoop
{
    struct iov_iter___gosnoop msg_iter;
};

/*
 * Find the first segment of `msg`: its user address in `*base` and its length
 * in `*len`. Returns false when there is none. Call this before the kernel
 * consumes the iterator; afterwards the fields no longer describe the buffer.
 */
static __always_inline bool getMsgFirstBuffer(struct msghdr *msg, void **base, __u64 *len)
{
    struct msghdr___gosnoop *m = (struct msghdr___gosnoop *)msg;
    const struct iovec *iov = NULL;
    void *b = NULL;
    __u64 l = 0;
    __u8 iterType = 0;

    if (!msg)
        return false;

    BPF_CORE_READ_INTO(&iterType, m, msg_iter.iter_type);

    if (bpf_core_field_exists(struct iov_iter___gosnoop, __ubuf_iovec))
    {
        /* 6.5 and later. ITER_UBUF is guaranteed to exist on these kernels. */
        if (iterType == bpf_core_enum_value(enum iter_type, ITER_UBUF))
        {
            BPF_CORE_READ_INTO(&b, m, msg_iter.__ubuf_iovec.iov_base);
            BPF_CORE_READ_INTO(&l, m, msg_iter.__ubuf_iovec.iov_len);
        }
        else
        {
            BPF_CORE_READ_INTO(&iov, m, msg_iter.__iov);
        }
    }
    else if (bpf_core_field_exists(struct iov_iter___gosnoop, ubuf) &&
             bpf_core_enum_value_exists(enum iter_type, ITER_UBUF))
    {
        /* 6.0 - 6.4: `ubuf` is its own union member, the length is in `count`. */
        if (iterType == bpf_core_enum_value(enum iter_type, ITER_UBUF))
        {
            BPF_CORE_READ_INTO(&b, m, msg_iter.ubuf);
            BPF_CORE_READ_INTO(&l, m, msg_iter.count);
        }
        else if (bpf_core_field_exists(struct iov_iter___gosnoop, __iov))
        {
            BPF_CORE_READ_INTO(&iov, m, msg_iter.__iov);
        }
        else
        {
            BPF_CORE_READ_INTO(&iov, m, msg_iter.iov);
        }
    }
    else
    {
        /* 5.x: no single-buffer iterator, always an iovec array. */
        BPF_CORE_READ_INTO(&iov, m, msg_iter.iov);
    }

    if (iov)
    {
        b = BPF_CORE_READ(iov, iov_base);
        l = BPF_CORE_READ(iov, iov_len);
    }

    if (!b || l == 0)
        return false;

    *base = b;
    *len = l;
    return true;
}

/*
 * Copy the first segment of `msg` into `dst` and return how many bytes landed
 * there, or 0 when the payload could not be reached. `dst_sz` must be a
 * compile-time constant so the verifier can bound the copy.
 */
static __always_inline __u16 readMsgPayload(struct msghdr *msg, __u8 *dst, __u32 dst_sz)
{
    void *base = NULL;
    __u64 len = 0;

    if (!getMsgFirstBuffer(msg, &base, &len) || len > dst_sz)
        return 0;

    if (bpf_probe_read_user(dst, len, base) != 0)
        return 0;

    return (__u16)len;
}

#endif /* __GOSNOOP_IOV_COMPAT_H__ */
