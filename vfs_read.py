from bcc import BPF

code = """
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <uapi/linux/binfmts.h>

BPF_HASH(last);

int kprobe__search_binary_handler(struct pt_regs *ctx, struct linux_binprm *bprm) {
    u64 pid = bpf_get_current_pid_tgid();

    u64 t = 1;
    last.update(&pid, &t);

    return 0;
}

int kretprobe__kernel_read(struct pt_regs *ctx, struct file *file, char *buf, u64 count) { 
    u64 pid = bpf_get_current_pid_tgid();
    u64 *check = last.lookup(&pid);
    if (check == NULL) return 0;

    bpf_trace_printk("%x %d\\n", *buf, count); 
    return 0; 
}
"""
b = BPF(text=code)
b.trace_print()
