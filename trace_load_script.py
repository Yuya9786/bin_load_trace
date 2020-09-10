from bcc import BPF
import codecs

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <uapi/linux/binfmts.h>

struct data_t {
    u32 pid;
    u64 ts;
    char buf[128];
};
BPF_PERF_OUTPUT(events);

BPF_HASH(load_script, u32, u32);

int kprobe__load_script(struct pt_regs *ctx, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid();
    
    u32 count = 0;
    load_script.update(&pid, &count);
    
    return 0;
}

int kprobe__bprm_change_interp(struct pt_regs *ctx, char *interp, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t data = {};

    u32 *count = load_script.lookup(&pid);
    if (count != NULL) {
        bpf_probe_read_str(data.buf, 128, interp);
        data.pid = pid;
        data.ts = bpf_ktime_get_ns();
    }

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

""")

# header
print("%-18s %-6s %s" % ("TIME(s)", "PID", "CODE"))
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18s %-6s %s" % (time_s, event.pid, event.buf))

b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
