#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
	pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("entry: pid = %d, filename = %s\n", pid, name->name);
    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    pid_t pid;

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("exit: pid = %d, filename: %s, ret = %ld\n", pid, name->name, ret);
    return 0;
}

// SEC("kretprobe/do_fork")
// int BPF_KRETPROBE(do_fork, long ret)
// {
//     pid_t pid;
// 
//     pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("KPROBE FORK: pid = %d, ret = %ld\n", pid, ret);
//     return 0;
// }
