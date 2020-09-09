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
    char *addr = (void *)PT_REGS_RC(ctx);

    bpf_trace_printk("ret mmap():\\n");
    bpf_trace_printk("  + pid: %d\\n", id);
    bpf_trace_printk("  + addr: %x\\n", addr[100]);
    return 0;
}

"""

bpf = BPF(text = bpf_code)
#sysmmap_name = bpf.get_syscall_fnname("mmap")
#bpf.attach_kprobe(event = sysmmap_name, fn_name = "kprobe_mmap")
#bpf.attach_kretprobe(event = sysmmap_name, fn_name = "kretprobe_mmap")
#bpf.attach_kprobe(event = sysopenat_name, fn_name = "kprobe_openat")
bpf.trace_print()
