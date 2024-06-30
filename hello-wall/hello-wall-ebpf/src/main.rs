#![no_std]
#![no_main]

use core::slice;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use etherparse::{
    EtherType, Ethernet2HeaderSlice as Ethernet, IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader,
    TcpHeaderSlice,
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
        Err(ret) => ret,
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

    // From: (eth_header) + (ipv4 header)
    //  aka: (14) + ( ip::ihl * 4 )
    match ip4.ihl() {
        5 => post_ip4::<34>(data, eth, ip4),
        6 => post_ip4::<38>(data, eth, ip4),
        7 => post_ip4::<42>(data, eth, ip4),
        8 => post_ip4::<46>(data, eth, ip4),
        9 => post_ip4::<50>(data, eth, ip4),
        10 => post_ip4::<54>(data, eth, ip4),
        11 => post_ip4::<58>(data, eth, ip4),
        12 => post_ip4::<62>(data, eth, ip4),
        13 => post_ip4::<66>(data, eth, ip4),
        14 => post_ip4::<70>(data, eth, ip4),
        15 => post_ip4::<74>(data, eth, ip4),
        _ => Err(xdp_action::XDP_ABORTED),
    }
}

fn post_ip4<const START: usize>(
    data: &mut Data,
    eth: Ethernet,
    ip4: Ipv4HeaderSlice,
) -> Result<u32, u32> {
    let tcp = parse_tcp_header::<START>(data).ok_or(xdp_action::XDP_DROP)?;

    info!(
        data.ctx,
        "\n[{:mac}] {:i}:{}\n[{:mac}] {:i}:{}",
        eth.source(),
        u32::from_be_bytes(ip4.source()),
        tcp.source_port(),
        eth.destination(),
        u32::from_be_bytes(ip4.destination()),
        tcp.destination_port(),
    );

    // #[allow(mutable_transmutes)]
    // let eth_mut: &mut [u8] = unsafe { core::mem::transmute(eth.slice()) };

    Ok(xdp_action::XDP_PASS)
}

fn parse_tcp_header<const START: usize>(data: &mut Data) -> Option<TcpHeaderSlice<'static>> {
    data.scheck_bounds(START + TcpHeader::MIN_LEN)?;

    let [.., byte12] = *data.schecked_slice(START, 13)? else {
        unreachable!("We have a slice of len 1")
    };

    let size = byte12 >> 4;
    if !(5..=15).contains(&size) {
        return None;
    }

    let slice = data.schecked_slice(START, size as usize * 4)?;
    let header = TcpHeaderSlice::from_slice(slice).ok()?;

    data.inc(header.slice().len());
    Some(header)
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

fn parse_eth_header(data: &mut Data) -> Option<Ethernet<'static>> {
    const HEADER_LEN: usize = etherparse::Ethernet2Header::LEN;

    let slice = data.checked_slice(HEADER_LEN)?;
    let header = Ethernet::from_slice(slice).ok()?;

    data.inc(HEADER_LEN);
    Some(header)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
