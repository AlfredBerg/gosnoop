#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <string.h>

#define BUF_SIZE 256
#define COMM_SIZE 64
#define MAX_STACK 15

struct processInfo
{
    __u32 pid;
    __u8 comm[BUF_SIZE]; // name of process

    __u8 cgroup[64];

    __u32 spid[MAX_STACK];
    __u8 scomm[MAX_STACK][COMM_SIZE];
};

static __always_inline void collectProcessInfo(struct processInfo *p)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    p->pid = pid_tgid >> 32;

    bpf_get_current_comm(&p->comm, sizeof(p->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // get cgroup
    const char *name;
    name = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
    if (!name)
        return;

    bpf_probe_read_str(p->cgroup, sizeof(p->cgroup), name);

    for (int i = 0; i < MAX_STACK; i++)
    {
        task = BPF_CORE_READ(task, parent);
        if (task == 0)
            break;

        __u32 pid;
        pid = BPF_CORE_READ(task, pid);
        if (pid == 0)
            break;

        p->spid[i] = pid;

        const char *pcomm;
        pcomm = BPF_CORE_READ(task, comm);

        bpf_probe_read_str(p->scomm[i], sizeof(p->scomm[i]), pcomm);
    }
}