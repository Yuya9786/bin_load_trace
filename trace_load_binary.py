from bcc import BPF
import codecs

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <uapi/linux/binfmts.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

struct data_t {
    u32 pid;
    u64 ts;
    char buf[128];
    u32 uid;
    u32 gid;
    u8 type;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

BPF_HASH(load_script, u32, u32);

int kprobe__load_script(struct pt_regs *ctx, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid();
    
    u32 count = 0;
    load_script.update(&pid, &count);
    
    return 0;
}

int kretprobe_load_script(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    load_script.delete(&pid);

    return 0;
}


int kprobe__bprm_change_interp(struct pt_regs *ctx, char *interp, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};

    u32 *count = load_script.lookup(&pid);
    if (count == NULL) return 0; 
    
    bpf_probe_read_str(data.buf, 128, interp);
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    data.uid = bprm->cred->uid.val;
    data.gid = bprm->cred->gid.val;
    data.type = 2;
    bpf_get_current_comm(&data.comm, TASK_COMM_LEN);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int kprobe__load_elf_binary(struct pt_regs *ctx, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t content = {0};

    content.pid = pid;
    content.ts = bpf_ktime_get_ns();
    content.uid = bprm->cred->uid.val;
    content.gid = bprm->cred->gid.val;
    content.type = 1;
    bpf_get_current_comm(&content.comm, TASK_COMM_LEN);

    events.perf_submit(ctx, &content, sizeof(content));  
                                    
    return 0;
}

""")

# header
print("%-18s %-16s %-6s %-6s %-6s %-7s %s" % ("TIME(s)", "COMM", "PID", "UID", "GID", "TYPE", "CODE"))
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    if event.type == 1:
        print("%-18s %-16s %-6s %-6s %-6s %-7s" % (time_s, event.comm, event.pid, event.uid, event.gid, "ELF"))
    elif event.type == 2:
        print("%-18s %-16s %-6s %-6s %-6s %-7s %s" % (time_s, event.comm, event.pid, event.uid, event.gid, "script", event.buf))
    else:
        print("%-18s %-16s %-6s %-6s %-6s %-7s" % (time_s, event.comm, event.pid, event.uid, event.gid, "Unknown"))

b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
