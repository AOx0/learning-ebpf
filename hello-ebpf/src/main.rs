#![no_std]
#![no_main]

use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::EbpfContext;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[map]
static USERCOUNT: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[kprobe]
pub fn hello(ctx: ProbeContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello(ctx: ProbeContext) -> Result<u32, u32> {
    let uid = ctx.uid();
    let curr = unsafe { USERCOUNT.get(&uid) }.copied().unwrap_or_default() + 1;

    let _ = USERCOUNT.insert(&uid, &curr, 0);

    // info!(&ctx, "User {} ran {} so far", uid, curr);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
