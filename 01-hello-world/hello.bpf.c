#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
  pid_t pid = bpf_get_current_pid_tgid() >> 32;
  if(pid_filter && pid != pid_filter)
    return 0;
  bpf_printk("Hello world bpf sys_enter_write from pid: %d\n", pid);
  return 0;
}
