#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

use aya_ebpf::{
    macros::{map, raw_tracepoint},
    maps::HashMap,
    programs::RawTracePointContext,
    EbpfContext,
};

#[map]
static COUNT: HashMap<u32, u64> = HashMap::with_max_entries(10, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn count_syscalls(ctx: RawTracePointContext) -> i32 {
    match try_count_syscalls(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_count_syscalls(ctx: RawTracePointContext) -> Result<i32, i32> {
    let uid = ctx.uid();
    if unsafe { COUNT.get(&uid).is_none() } {
        COUNT.insert(&uid, &0, 0).unwrap();
    }

    let Some(curr) = COUNT.get_ptr_mut(&uid) else {
        return Ok(0);
    };

    unsafe { core::intrinsics::atomic_xadd_relaxed(curr, 1) };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
