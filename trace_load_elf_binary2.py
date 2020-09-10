from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <uapi/linux/binfmts.h>

BPF_PERCPU_ARRAY(code, char);

int kprobe__search_binary_handler(struct pt_regs *ctx, struct linux_binprm *bprm) {
    const char *contents;
    char *value;
    u32 id;
    int res;

    // data.pid = bpf_get_current_pid_tgid();
    // data.ts = bpf_ktime_get_ns();
    
    res = bpf_probe_read(&contents, sizeof(contents), &bprm->buf);

    id = 0;
    code.update(&id, &contents);

    // value = code.lookup(&id);
    
    // res = bpf_probe_read_str(value, 256, contents);

    return 0;
}

""")

# header
print("Tracing search_binary_handler()... Hit Ctrl-C to end.")

# sleep until Ctrl-C
try:
    sleep(999999999)
except KeyboardInterrupt:
    pass

# process output
print("CONTENTS")
code = b["code"].items()
for i in code:
    print(i)
