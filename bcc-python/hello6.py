from time import sleep

from bcc import BPF

import ctypes as ct

program = r"""

struct message{
    char msg[12];
};

BPF_HASH(config, u32, struct message);

BPF_PERF_OUTPUT(output);

struct data_t{
    int pid;
    u32 uid;
    char command[16];
    char message[12];
};

int hello(void*ctx){
    struct data_t data = {};
    struct message *p;
    char message[12]= "Hello world";

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.command, sizeof(data.command));

    p=config.lookup(&data.uid);
    if (p!=0) {
     bpf_probe_read_kernel(&data.message, sizeof(data.message), p->msg);
    }else{
     bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    }

       output.perf_submit(ctx, &data, sizeof(data));
     return 0;
}


"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")

print(syscall)


b.attach_kprobe(event=syscall, fn_name="hello")
# b.trace_print()

b["config"][ct.c_int(0)] = ct.create_string_buffer(b"Root!")
b["config"][ct.c_int(1000)] = ct.create_string_buffer(b"Hi 1000!")


def print_event(cpu, data, size):
    data = b["output"].event(data)
    print(f"{data.uid} {data.pid}", end="")
    print(f" {data.command.decode()}", end="")
    print(f" {data.message.decode()}")


b["output"].open_perf_buffer(print_event)
while True:
    b.perf_buffer_poll()
