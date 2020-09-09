from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

int kprobe__elf_map(struct pt_regs *ctx) {
    int length = (int)PT_REGS_PARM5(ctx);
    int prot = (int)PT_REGS_PARM4(ctx);

    u64 id = bpf_get_current_pid_tgid();

    bpf_trace_printk("elf_map():\\n");
    bpf_trace_printk("  + pid: %d\\n", id);
    bpf_trace_printk("  + length: %d\\n", length);
    bpf_trace_printk("  + prot: %d\\n", prot);

    return 0;
}

int kretprobe__elf_map(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void *addr = (void *)PT_REGS_RC(ctx);

    bpf_trace_printk("ret mmap():\\n");
    bpf_trace_printk("  + pid: %d\\n", id);
    bpf_trace_printk("  + addr: %x\\n", addr);
    bpf_trace_printk("  + content: %x\\n", *((char *)addr));
    return 0;
}

"""

bpf = BPF(text = bpf_code)
bpf.trace_print()
