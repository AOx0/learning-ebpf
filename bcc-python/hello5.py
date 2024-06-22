from time import sleep
from bcc import BPF
import ctypes as ct

program = r"""

BPF_PROG_ARRAY(systemcall,300);

int ignore_opcode(void *ctx){
    bpf_trace_printk("\nIGNORAR OPCION CODE");
    return 0;
}

int hello_execve(void *ctx){
    bpf_trace_printk("\nExecuting a program");
    return 0;
}

RAW_TRACEPOINT_PROBE(sys_enter){
   int opcode =ctx->args[1];
   systemcall.call(ctx,opcode);
   bpf_trace_printk("\nAnother systemcall: >>%d<<",opcode);
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx){
   if (ctx->args[1]==222){
       bpf_trace_printk("\nCreando un timer");
   }
   else
   if (ctx->args[1]==226){
       bpf_trace_printk("\nBorrando un timer");
   }
   else{
       bpf_trace_printk("\nOtra operación de timmer");
   }
   return 0;
}

"""

b = BPF(text=program)
# b.attach_raw_tracepoint(tp="sys_ente", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve", BPF.RAW_TRACEPOINT)
timer_fn = b. load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("systemcall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)

prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
b.trace_print()


