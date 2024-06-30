#![no_std]
#![no_main]

use core::slice;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use etherparse::{
    EtherType, Ethernet2HeaderSlice, IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeaderSlice,
};

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

    #[inline(always)]
    #[must_use]
    fn schecked_slice(&self, offset: usize, size: usize) -> Option<&'static [u8]> {
        self.scheck_bounds(offset + size)?;
        Some(unsafe { slice::from_raw_parts((self.ctx.data() + offset) as *const u8, size) })
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

    macro_rules! check {
        ($val:expr) => {{
            const OFFSET: usize = 14 + $val * 4;
            let slice = data
                .schecked_slice(OFFSET, 20)
                .ok_or(xdp_action::XDP_PASS)?;
            info!(&ctx, "This is a IPv{}: {}", ip4.version(), slice[1]);
            return Ok(xdp_action::XDP_PASS);
        }};
    }

    match ip4.ihl() {
        5 => check!(5),
        6 => check!(6),
        7 => check!(7),
        8 => check!(8),
        9 => check!(9),
        10 => check!(10),
        11 => check!(11),
        12 => check!(12),
        13 => check!(13),
        14 => check!(14),
        15 => check!(15),
        _ => Err(xdp_action::XDP_ABORTED),
    }
}

// fn parse_tcp_header<const START: usize>(data: &mut Data) -> Option<TcpHeaderSlice<'static>> {
//     data.scheck_bounds(START + Ipv4Header::MIN_LEN)?;

//     todo!()
// }

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
