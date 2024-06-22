#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

use aya_ebpf::{
    bindings::bpf_raw_tracepoint_args,
    macros::{map, raw_tracepoint},
    maps::HashMap,
    programs::RawTracePointContext,
    EbpfContext,
};

#[map]
static COUNT: HashMap<u64, u64> = HashMap::with_max_entries(457, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn count_syscalls(ctx: RawTracePointContext) -> i32 {
    match try_count_syscalls(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn get_syscall(ctx: RawTracePointContext) -> u64 {
    let ctx: &mut bpf_raw_tracepoint_args =
        unsafe { &mut *(ctx.as_ptr() as *mut bpf_raw_tracepoint_args) };
    let args = unsafe { ctx.args.as_slice(2) };
    args[1]
}

fn try_count_syscalls(ctx: RawTracePointContext) -> Result<i32, i32> {
    let syscall = get_syscall(ctx);

    if unsafe { COUNT.get(&syscall).is_none() } {
        COUNT.insert(&syscall, &0, 0).unwrap();
    }

    let Some(curr) = COUNT.get_ptr_mut(&syscall) else {
        return Ok(0);
    };

    unsafe { core::intrinsics::atomic_xadd_relaxed(curr, 1) };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
