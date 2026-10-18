#ifndef __GOSNOOP_ARCH_COMPAT_H__
#define __GOSNOOP_ARCH_COMPAT_H__

#include <vmlinux.h>

/*
 * vmlinux.h is checked in once, generated on x86_64. Field *names* are all that
 * CO-RE cares about and those are architecture independent for the kernel
 * structs GoSnoop reads, so the same header serves every target — with one
 * exception: libbpf's PT_REGS_PARMn() macros need the arch's register struct,
 * and an x86_64 vmlinux.h has no `struct user_pt_regs`.
 *
 * Supply it here for the architectures that need it. These are uapi layouts
 * (arch/<arch>/include/uapi/asm/ptrace.h), so they are frozen by the kernel's
 * ABI guarantees rather than something CO-RE has to relocate.
 *
 * Include this before <bpf/bpf_tracing.h>.
 */

#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs
{
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#endif

#endif /* __GOSNOOP_ARCH_COMPAT_H__ */
