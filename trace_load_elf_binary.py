from bcc import BPF
import codecs

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <uapi/linux/binfmts.h>

struct data_t {
    char buf[128];
    int res;
};
BPF_PERF_OUTPUT(events);

int kprobe__search_binary_handler(struct pt_regs *ctx, struct linux_binprm *bprm) {
    struct data_t data = {};

    data.res = bpf_probe_read(data.buf, 128, bprm->buf);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

""")

# header
print("Tracing search_binary_handler()... Hit Ctrl-C to end.")

def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    print("%d: %s" % (len(event.buf), event.buf))

b["events"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
