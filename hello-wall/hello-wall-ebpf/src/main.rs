#![no_std]
#![no_main]

use core::slice;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use etherparse::{
    checksum, EtherType, Ethernet2HeaderSlice as Ethernet, IpNumber, Ipv4Header, Ipv4HeaderSlice,
    TcpHeader, TcpHeaderSlice,
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
        5 => post_ip4::<34, 20>(data, eth, ip4),
        6 => post_ip4::<38, 24>(data, eth, ip4),
        7 => post_ip4::<42, 28>(data, eth, ip4),
        8 => post_ip4::<46, 32>(data, eth, ip4),
        9 => post_ip4::<50, 36>(data, eth, ip4),
        10 => post_ip4::<54, 40>(data, eth, ip4),
        11 => post_ip4::<58, 44>(data, eth, ip4),
        12 => post_ip4::<62, 48>(data, eth, ip4),
        13 => post_ip4::<66, 52>(data, eth, ip4),
        14 => post_ip4::<70, 56>(data, eth, ip4),
        15 => post_ip4::<74, 60>(data, eth, ip4),
        _ => Err(xdp_action::XDP_ABORTED),
    }
}

fn calc_header_checksum<const SIZE: usize>(header: Ipv4HeaderSlice) -> u16 {
    if header.slice().len() != SIZE {
        return 0;
    }
    checksum::Sum16BitWords::new()
        .add_2bytes([
            (4 << 4) | header.ihl(),
            (header.dcp().value() << 2) | header.ecn().value(),
        ])
        .add_2bytes(header.total_len().to_be_bytes())
        .add_2bytes(header.identification().to_be_bytes())
        .add_2bytes({
            let frag_off_be = header.fragments_offset().value().to_be_bytes();
            let flags = {
                let mut result = 0;
                if header.dont_fragment() {
                    result |= 64;
                }
                if header.more_fragments() {
                    result |= 32;
                }
                result
            };
            [flags | (frag_off_be[0] & 0x1f), frag_off_be[1]]
        })
        .add_2bytes([header.ttl(), header.protocol().0])
        .add_4bytes(header.source())
        .add_4bytes(header.destination())
        .add_slice(header.options())
        .ones_complement()
        .to_be()
}

fn post_ip4<const OFFSET: usize, const SIZE: usize>(
    data: &mut Data,
    eth: Ethernet,
    ip4: Ipv4HeaderSlice,
) -> Result<u32, u32> {
    let tcp = parse_tcp_header::<OFFSET>(data).ok_or(xdp_action::XDP_DROP)?;

    const CLIENT: [u8; 4] = [192, 168, 1, 67];
    const CLIENT_MAC: [u8; 6] = [0xa4, 0x83, 0xe7, 0x4d, 0x99, 0x65];

    const SERVER: [u8; 4] = [192, 168, 1, 112];
    const SERVER_MAC: [u8; 6] = [0x18, 0x3d, 0xa2, 0x55, 0x7f, 0xb0];

    const LOADER_MAC: [u8; 6] = [0x00, 0xc0, 0xca, 0xb3, 0xf7, 0xd3];

    let source = core::hint::black_box(ip4.source());

    let from_server = source == SERVER;
    let from_client = source == CLIENT && tcp.destination_port() == 6000;
    if !(from_server || from_client) {
        return Ok(xdp_action::XDP_PASS);
    }

    #[allow(mutable_transmutes)]
    let ip4_mut: &mut [u8] = unsafe { core::mem::transmute(ip4.slice()) };
    #[allow(mutable_transmutes)]
    let eth_mut: &mut [u8] = unsafe { core::mem::transmute(eth.slice()) };

    // data.scheck_bounds(START).ok_or(xdp_action::XDP_PASS)?;

    ip4_mut[15] = 192;
    eth_mut[6] = LOADER_MAC[0];
    eth_mut[7] = LOADER_MAC[1];
    eth_mut[8] = LOADER_MAC[2];
    eth_mut[9] = LOADER_MAC[3];
    eth_mut[10] = LOADER_MAC[4];
    eth_mut[11] = LOADER_MAC[5];

    if source == CLIENT {
        ip4_mut[19] = 112;

        eth_mut[0] = SERVER_MAC[0];
        eth_mut[1] = SERVER_MAC[1];
        eth_mut[2] = SERVER_MAC[2];
        eth_mut[3] = SERVER_MAC[3];
        eth_mut[4] = SERVER_MAC[4];
        eth_mut[5] = SERVER_MAC[5];

        data.scheck_bounds(OFFSET).ok_or(xdp_action::XDP_PASS)?;
        let calculate_ipv4_checksum = calc_header_checksum::<SIZE>(ip4);
        let checksum = calculate_ipv4_checksum.to_be_bytes();
        ip4_mut[10] = checksum[0];
        ip4_mut[11] = checksum[1];

        info!(
            data.ctx,
            "SUM: 0x{:x}\n[{:mac}] {:i}:{}\n[{:mac}] {:i}:{}",
            calculate_ipv4_checksum,
            core::hint::black_box(eth.source()),
            core::hint::black_box(u32::from_be_bytes(ip4.source())),
            core::hint::black_box(tcp.source_port()),
            core::hint::black_box(eth.destination()),
            core::hint::black_box(u32::from_be_bytes(ip4.destination())),
            core::hint::black_box(tcp.destination_port()),
        );
        Ok(xdp_action::XDP_TX)
    } else {
        ip4_mut[19] = 67;

        eth_mut[0] = CLIENT_MAC[0];
        eth_mut[1] = CLIENT_MAC[1];
        eth_mut[2] = CLIENT_MAC[2];
        eth_mut[3] = CLIENT_MAC[3];
        eth_mut[4] = CLIENT_MAC[4];
        eth_mut[5] = CLIENT_MAC[5];

        data.scheck_bounds(OFFSET).ok_or(xdp_action::XDP_PASS)?;
        let calculate_ipv4_checksum = calc_header_checksum::<SIZE>(ip4);
        let checksum = calculate_ipv4_checksum.to_be_bytes();
        ip4_mut[10] = checksum[0];
        ip4_mut[11] = checksum[1];

        info!(
            data.ctx,
            "SUM: 0x{:x}\n[{:mac}] {:i}:{}\n[{:mac}] {:i}:{}",
            calculate_ipv4_checksum,
            core::hint::black_box(eth.source()),
            core::hint::black_box(u32::from_be_bytes(ip4.source())),
            core::hint::black_box(tcp.source_port()),
            core::hint::black_box(eth.destination()),
            core::hint::black_box(u32::from_be_bytes(ip4.destination())),
            core::hint::black_box(tcp.destination_port()),
        );
        Ok(xdp_action::XDP_TX)
    }
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
