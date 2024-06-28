#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[allow(unused_imports)]
use aya_log_ebpf::info;

type EthernetHeader = etherparse::Ethernet2HeaderSlice<'static>;
type IP4Header = etherparse::Ipv4HeaderSlice<'static>;

#[xdp]
pub fn hello_ping(ctx: XdpContext) -> u32 {
    match try_hello_ping(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_hello_ping(ctx: XdpContext) -> Result<u32, u32> {
    let mut data = data_ptrs(&ctx);

    let eth: EthernetHeader = unsafe { eth_header(&mut data) }?;
    if !matches!(eth.ether_type(), etherparse::EtherType::IPV4) {
        return Ok(xdp_action::XDP_PASS);
    };

    let ip: IP4Header = unsafe { ipv4_header(&mut data) }?;
    if matches!(ip.protocol(), etherparse::IpNumber::ICMP) {
        Ok(xdp_action::XDP_DROP)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

unsafe fn ipv4_header((start, end): &mut (*const u8, *const u8)) -> Result<IP4Header, u32> {
    const HEADER_LEN: usize = etherparse::Ipv4Header::MAX_LEN;

    if start.wrapping_add(HEADER_LEN) > *end {
        return Err(xdp_action::XDP_ABORTED);
    }

    let slice = core::slice::from_raw_parts(*start, HEADER_LEN);
    let header: IP4Header = IP4Header::from_slice(slice).map_err(|_| xdp_action::XDP_ABORTED)?;

    *start = start.wrapping_add(header.ihl() as usize);
    Ok(header)
}

unsafe fn eth_header((start, end): &mut (*const u8, *const u8)) -> Result<EthernetHeader, u32> {
    const HEADER_LEN: usize = etherparse::Ethernet2Header::LEN;

    if start.wrapping_add(HEADER_LEN) > *end {
        return Err(xdp_action::XDP_ABORTED);
    }

    let slice = core::slice::from_raw_parts(*start, HEADER_LEN);
    let header: EthernetHeader =
        EthernetHeader::from_slice(slice).map_err(|_| xdp_action::XDP_ABORTED)?;

    *start = start.wrapping_add(HEADER_LEN);
    Ok(header)
}

fn data_ptrs(ctx: &XdpContext) -> (*const u8, *const u8) {
    let start = ctx.data() as *const u8;
    let end = ctx.data_end() as *const u8;
    (start, end)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
