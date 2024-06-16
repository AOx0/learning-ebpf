#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_raw_tracepoint_args,
    macros::{map, raw_tracepoint},
    maps::{ProgramArray, RingBuf},
    programs::RawTracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use raw_syscall_common::Args;

#[map]
static PROGRAMS: ProgramArray = ProgramArray::with_max_entries(300, 0);

#[map]
static REGS: RingBuf = RingBuf::with_byte_size(1, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn raw_syscall(ctx: RawTracePointContext) -> i32 {
    match try_raw_syscall(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn print_execve(ctx: RawTracePointContext) -> i32 {
    info!(&ctx, "Ejecutado execve");
    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn print_kill(ctx: RawTracePointContext) -> i32 {
    info!(&ctx, "Ejecutado kill");
    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn print_timer(ctx: RawTracePointContext) -> i32 {
    let args = get_args(&ctx);

    match args[1] {
        222 => info!(&ctx, "Creando timer"),
        226 => info!(&ctx, "Borrando timer"),
        _ => info!(&ctx, "Otro timer"),
    }

    0
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn do_nothing(_ctx: RawTracePointContext) -> i32 {
    0
}

fn try_raw_syscall(ctx: RawTracePointContext) -> Result<i32, i32> {
    let Some(mut reg) = REGS.reserve(0) else {
        return Ok(0);
    };

    let args = get_args(&ctx);

    reg.write(Args {
        ptr: args[0],
        op: args[1],
    });
    reg.submit(0);

    let Ok(_) = (unsafe { PROGRAMS.tail_call(&ctx, args[1].try_into().unwrap()) }) else {
        // info!(&ctx, "Otra llamada");
        return Ok(0);
    };

    Ok(0)
}

fn get_args(ctx: &RawTracePointContext) -> &[u64] {
    let args: &bpf_raw_tracepoint_args =
        unsafe { &*{ ctx.as_ptr() as *mut bpf_raw_tracepoint_args } };

    let args = unsafe { args.args.as_slice(2) };
    args
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
