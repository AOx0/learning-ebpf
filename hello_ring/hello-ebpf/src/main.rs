#![no_std]
#![no_main]

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
    let message = b"Hello world";
    let command = ctx.command().unwrap_or(*b"ERR             ");

    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);

    let regs_ptr: *const u8 = ctx.arg(0).ok_or(1u32)?;
    let args_ptr: [u8; 8] = unsafe { core::mem::transmute(ctx.regs as *const u8) };

    info!(
        &ctx,
        "(regs) 0x{:x} vs 0x{:x} (arg0)",
        u64::from_be_bytes(args_ptr),
        u64::from_be_bytes((regs_ptr as u64).to_le_bytes())
    );

    // ctx->rdi->rdi
    let arg: *const u8 = regs.arg(0).ok_or(1u32)?;

    let mut buff = [0u8; 64];

    unsafe { bpf_probe_read_user_str_bytes(arg, &mut buff) }.map_err(|_| 1u32)?;

    let mut t: RingBufEntry<Data> = OUTPUT.reserve(0).ok_or(1u32)?;
    t.write(Data {
        uid: ctx.uid(),
        pid: ctx.pid(),
        command,
        path: buff,
        message: *message,
    });
    t.submit(0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
