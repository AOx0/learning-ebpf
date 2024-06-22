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
    u64 uopcode;
    u64 csys;
};

BPF_HASH(counter_table, u64, struct datatable);

static __always_inline
struct datatable * busca(struct bpf_raw_tracepoint_args *ctx) {
   struct datatable p1 ={0};
   p1.uopcode =ctx->args[1];

    return counter_table.lookup_or_try_init(&p1.uopcode, &p1);
}

//int hsys(struct bpf_raw_tracepoint_args *ctx) {

RAW_TRACEPOINT_PROBE(sys_enter){
    struct datatable *p=busca(ctx);
    if (p==0) return 0;

    struct datatable p1 =*p;
    p1.csys++;
    counter_table.update(&p1.uopcode, &p1);
    return 0;
}

"""

b = BPF(text=program)

# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hsys")

# b.trace_print()
while True:
    sleep(2)
    for k, data in b["counter_table"].items():
        s = f"UID [{data.uopcode}] {data.csys} \n"
        print(s)


