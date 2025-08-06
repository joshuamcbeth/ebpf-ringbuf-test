#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define FILE_NAME_LEN 256
#define TASK_COMM_LEN 256

struct event {
    u32 e_pid;
    char e_filename[FILE_NAME_LEN];
    char e_comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} rb SEC(".maps");

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx)
{
    struct event *evt;
    char comm[TASK_COMM_LEN] = {};
    char filename[FILE_NAME_LEN];

    evt = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!evt)
        return 0;

    evt->e_pid = bpf_get_current_pid_tgid();
    bpf_probe_read_user_str(evt->e_filename, sizeof(filename), (char *)ctx->si);
    bpf_get_current_comm(evt->e_comm, sizeof(comm));
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
