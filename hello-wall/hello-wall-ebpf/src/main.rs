#![no_std]
#![no_main]

use core::slice;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
#[allow(unused_imports)]
// use aya_log_ebpf::{error, info, warn};
use aya_log_ebpf::info;

use etherparse::{EtherType, Ethernet2HeaderSlice, IpNumber, Ipv4Header, Ipv4HeaderSlice};

struct Data<'a> {
    ctx: &'a XdpContext,
    offset: usize,
}

impl Data<'_> {
    #[inline(always)]
    fn curr(&self) -> Option<*const u8> {
        Some(self.ctx.data().checked_add(self.offset)? as *const u8)
    }

    #[inline(always)]
    #[must_use]
    fn ocheck_bounds(&self, size: usize) -> Option<()> {
        self.scheck_bounds(size + self.offset)
    }

    #[inline(always)]
    #[must_use]
    fn scheck_bounds(&self, size: usize) -> Option<()> {
        (self.ctx.data().checked_add(size)? <= self.ctx.data_end()).then_some(())
    }

    fn inc(&mut self, size: usize) {
        self.offset += size;
    }

    #[inline(always)]
    #[must_use]
    fn checked_slice(&self, size: usize) -> Option<&'static [u8]> {
        self.ocheck_bounds(size)?;
        Some(unsafe { slice::from_raw_parts(self.curr()?, size) })
    }
}

#[xdp]
pub fn hello_wall(ctx: XdpContext) -> u32 {
    match try_hello_wall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_hello_wall(ctx: XdpContext) -> Result<u32, u32> {
    let data = &mut Data {
        ctx: &ctx,
        offset: 0,
    };

    let eth = parse_eth_header(data).ok_or(xdp_action::XDP_DROP)?;
    if !matches!(eth.ether_type(), EtherType::IPV4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip4 = parse_ip4_header(data).ok_or(xdp_action::XDP_DROP)?;
    if !matches!(ip4.protocol(), IpNumber::TCP) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip4_mut: &mut [u8] = slice_mut(ip4.slice());
    let eth_mut: &mut [u8] = slice_mut(eth.slice());
    let red = if let [192, 168, 1, 99] = ip4.destination() {
        ip4_mut[15] = 67;

        eth_mut[6] = 0xa4;
        eth_mut[7] = 0x83;
        eth_mut[8] = 0xe7;
        eth_mut[9] = 0x4d;
        eth_mut[10] = 0x99;
        eth_mut[11] = 0x65;

        ip4_mut[19] = 112;

        eth_mut[0] = 0x18;
        eth_mut[1] = 0x3d;
        eth_mut[2] = 0xa2;
        eth_mut[3] = 0x55;
        eth_mut[4] = 0x7f;
        eth_mut[5] = 0xb0;

        info!(&ctx, "Redirecting to...");
        true
    } else
    /* if let [192, 168, 1, 67] = ip4.source() {
        ip4_mut[15] = 192;

        eth_mut[6] = 0x00;
        eth_mut[7] = 0xc0;
        eth_mut[8] = 0xca;
        eth_mut[9] = 0xb3;
        eth_mut[10] = 0xf7;
        eth_mut[11] = 0xd3;

        info!(&ctx, "Redirecting back...");
        true
    } else */
    {
        info!(&ctx, "Pass...");
        false
    };

    let [s1, s2, s3, s4] = ip4.source();
    let [d1, d2, d3, d4] = ip4.destination();

    let [sm1, sm2, sm3, sm4, sm5, sm6] = eth.source();
    let [dm1, dm2, dm3, dm4, dm5, dm6] = eth.destination();

    info!(
        &ctx,
        "{}.{}.{}.{} [{:x}:{:x}:{:x}:{:x}:{:x}:{:x}] -> {}.{}.{}.{} [{:x}:{:x}:{:x}:{:x}:{:x}:{:x}]",
        s1,
        s2,
        s3,
        s4,
        sm1,
        sm2,
        sm3,
        sm4,
        sm5,
        sm6,
        d1,
        d2,
        d3,
        d4,
        dm1,
        dm2,
        dm3,
        dm4,
        dm5,
        dm6,
    );

    if red {
        Ok(xdp_action::XDP_TX)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

#[allow(clippy::mut_from_ref)]
fn slice_mut(slice: &[u8]) -> &mut [u8] {
    #[allow(mutable_transmutes)]
    unsafe {
        core::mem::transmute(slice)
    }
}

fn parse_ip4_header(data: &mut Data) -> Option<Ipv4HeaderSlice<'static>> {
    data.ocheck_bounds(Ipv4Header::MIN_LEN)?;

    let [first_byte] = *data.checked_slice(1)? else {
        unreachable!("We have a slice of len 1")
    };

    let size = first_byte & 0b0000_1111;
    if !(5..=15).contains(&size) {
        return None;
    }

    let slice = data.checked_slice(size as usize * 4)?;
    let header = Ipv4HeaderSlice::from_slice(slice).ok()?;

    data.inc(header.slice().len());
    Some(header)
}

fn parse_eth_header(data: &mut Data) -> Option<Ethernet2HeaderSlice<'static>> {
    const HEADER_LEN: usize = etherparse::Ethernet2Header::LEN;

    let slice = data.checked_slice(HEADER_LEN)?;
    let header = Ethernet2HeaderSlice::from_slice(slice).ok()?;

    data.inc(HEADER_LEN);
    Some(header)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
