from time import sleep
from bcc import BPF

program1 = r"""
int hello(void *ctx){
    bpf_trace_printk("hello world");
    return 0;
}

"""


program = r"""

struct datatable{
    u64 uid;
    int cexec;
    int copen;
    int cwrite;
};

BPF_HASH(counter_table, u64, struct datatable);

static __always_inline  struct datatable * busca(void *ctx){
    struct datatable p1 ={0};
    p1.uid =  bpf_get_current_uid_gid() & 0xFFFFFFFF;

    return counter_table.lookup_or_try_init(&p1.uid, &p1);
}

int hexec(void *ctx) {
    struct datatable *p=busca(ctx);
    if (p==0) return 0;

    struct datatable p1 =*p;
    p1.cexec++;
    counter_table.update(&p1.uid, &p1);
    return 0;
}

int hopen(void *ctx){
    struct datatable *p=busca(ctx);
    if (p==0) return 0;

    struct datatable p1 =*p;
    p1.copen++;
    counter_table.update(&p1.uid, &p1);
    return 0;
}


int hwrite(void *ctx){
    struct datatable *p=busca(ctx);
    if (p==0) return 0;

    struct datatable p1 =*p;
    p1.cwrite++;
    counter_table.update(&p1.uid, &p1);
    return 0;
}

"""

b = BPF(text=program)
sexec = b.get_syscall_fnname("execve")
sopen = b.get_syscall_fnname("openat")
swrite = b.get_syscall_fnname("write")

b.attach_kprobe(event=sexec, fn_name="hexec")
b.attach_kprobe(event=sopen, fn_name="hopen")
b.attach_kprobe(event=swrite, fn_name="hwrite")

while True:
    sleep(2)
    for k, data in b["counter_table"].items():
        s = f"UID [{data.uid}] e:{data.cexec} "
        s += f" o:{data.copen} w:{data.cwrite} \n"
        print(s)


