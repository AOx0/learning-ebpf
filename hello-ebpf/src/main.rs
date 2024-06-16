#![no_std]
#![no_main]

use aya_ebpf::macros::{map, perf_event};
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::EbpfContext;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use hello_common::Data;

#[map]
static OUTPUT: RingBuf = RingBuf::with_byte_size(1, 0);

#[kprobe]
pub fn hello(ctx: ProbeContext) -> u32 {
    match try_hello(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello(ctx: ProbeContext) -> Result<u32, u32> {
    let mut t: RingBufEntry<Data> = OUTPUT.reserve(0).ok_or(1u32)?;
    let message = b"Hello world";
    let command = ctx.command().unwrap_or(*b"ERR             ");

    t.write(Data {
        uid: ctx.uid(),
        pid: ctx.pid(),
        command,
        message: *message,
    });
    t.submit(0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
