#![no_std]
#![no_main]

use core::ptr;

use aya_ebpf::bindings::task_struct;
use aya_ebpf::helpers::{
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str, bpf_probe_read_user_str_bytes,
};
use aya_ebpf::macros::{map, perf_event};
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_ebpf::{EbpfContext, PtRegs};
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
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let arg: *const u8 = regs.arg(0).ok_or(1u32)?;

    let mut t = OUTPUT.reserve(0).ok_or(1u32)?;

    unsafe {
        ptr::write_unaligned(
            t.as_mut_ptr(),
            Data {
                uid: ctx.uid(),
                pid: ctx.pid(),
                command: ctx.command().unwrap_or(*b"ERR             "),
                message: *b"Hello world",
                path: [0; 64],
            },
        );

        let _ = bpf_probe_read_user_str_bytes(arg, &mut (*t.as_mut_ptr()).path);
    }
    t.submit(0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
