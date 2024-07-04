#![no_std]
#![no_main]

use core::{mem, ops::Add, ptr, slice};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use etherparse::{
    EtherType, Ethernet2HeaderSlice as Ethernet, IpNumber, Ipv4Header, Ipv4HeaderSlice, UdpHeader,
    UdpHeaderSlice,
};

#[map]
static PACKET: RingBuf = RingBuf::with_byte_size(100, 0);

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
    if !matches!(ip4.protocol(), IpNumber::UDP) {
        return Ok(xdp_action::XDP_PASS);
    }

    // From: (eth_header) + (ipv4 header)
    //  aka: (14) + ( ip::ihl * 4 )
    match ip4.ihl() {
        5 => post_ip4::<34, 20>(data, ip4),
        6 => post_ip4::<38, 24>(data, ip4),
        7 => post_ip4::<42, 28>(data, ip4),
        8 => post_ip4::<46, 32>(data, ip4),
        9 => post_ip4::<50, 36>(data, ip4),
        10 => post_ip4::<54, 40>(data, ip4),
        11 => post_ip4::<58, 44>(data, ip4),
        12 => post_ip4::<62, 48>(data, ip4),
        13 => post_ip4::<66, 52>(data, ip4),
        14 => post_ip4::<70, 56>(data, ip4),
        15 => post_ip4::<74, 60>(data, ip4),
        _ => Err(xdp_action::XDP_ABORTED),
    }
}

pub fn calc_ip_csum<const SIZE: usize>(header: Ipv4HeaderSlice) -> u16 {
    if header.slice().len() != SIZE {
        return 0;
    }
    etherparse::checksum::Sum16BitWords::new()
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

pub fn calc_checksum_ipv4_raw(
    udp: &UdpHeaderSlice,
    source: [u8; 4],
    destination: [u8; 4],
    payload: &[u8],
) -> Result<u16, etherparse::err::ValueTooBigError<usize>> {
    // check that the total length fits into the field
    const MAX_PAYLOAD_LENGTH: usize = (u16::MAX as usize) - UdpHeader::LEN;
    if MAX_PAYLOAD_LENGTH < payload.len() {
        return Err(etherparse::err::ValueTooBigError {
            actual: payload.len(),
            max_allowed: MAX_PAYLOAD_LENGTH,
            value_type: etherparse::err::ValueType::UdpPayloadLengthIpv4,
        });
    }

    Ok(calc_checksum_ipv4_internal(
        udp,
        source,
        destination,
        payload,
    ))
}

fn calc_checksum_post_ip(
    udp: &UdpHeaderSlice,
    ip_pseudo_header_sum: etherparse::checksum::Sum16BitWords,
    payload: &[u8],
) -> u16 {
    ip_pseudo_header_sum
        .add_2bytes(udp.source_port().to_be_bytes())
        .add_2bytes(udp.destination_port().to_be_bytes())
        .add_2bytes(udp.length().to_be_bytes())
        .add_slice(payload)
        .to_ones_complement_with_no_zero()
        .to_be()
}

fn calc_checksum_ipv4_internal(
    udp: &UdpHeaderSlice,
    source: [u8; 4],
    destination: [u8; 4],
    payload: &[u8],
) -> u16 {
    calc_checksum_post_ip(
        udp,
        //pseudo header
        etherparse::checksum::Sum16BitWords::new()
            .add_4bytes(source)
            .add_4bytes(destination)
            .add_2bytes([0, etherparse::ip_number::UDP.0])
            .add_2bytes(udp.length().to_be_bytes()),
        payload,
    )
}

fn post_ip4<const OFFSET: usize, const SIZE: usize>(
    data: &mut Data,
    ip4: Ipv4HeaderSlice,
) -> Result<u32, u32> {
    const CLIENT: [u8; 4] = [192, 168, 1, 67];
    const CLIENT_MAC: [u8; 6] = [0xa4, 0x83, 0xe7, 0x4d, 0x99, 0x65];

    const SERVER: [u8; 4] = [192, 168, 1, 112];
    const SERVER_MAC: [u8; 6] = [0x18, 0x3d, 0xa2, 0x55, 0x7f, 0xb0];

    const LOADER_MAC: [u8; 6] = [0x00, 0x45, 0xe2, 0x4d, 0x9f, 0xe5];

    let udp = parse_udp_header::<OFFSET>(data).ok_or(xdp_action::XDP_DROP)?;
    if !((ip4.source() == SERVER) || (ip4.source() == CLIENT && udp.destination_port() == 5000)) {
        return Ok(xdp_action::XDP_PASS);
    }

    data.scheck_bounds(OFFSET + UdpHeader::LEN)
        .ok_or(xdp_action::XDP_PASS)?;
    let eth_mut: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(data.ctx.data() as *mut u8, 14) };
    let ip4_mut: &mut [u8] =
        unsafe { core::slice::from_raw_parts_mut(data.ctx.data().add(14) as *mut u8, SIZE) };

    ip4_mut[15] = 99;
    eth_mut[6..12].copy_from_slice(&LOADER_MAC);

    let msg = if ip4.source() == CLIENT {
        ip4_mut[19] = 112;
        eth_mut[0..6].copy_from_slice(&SERVER_MAC);
        "LOAD -> SERVER"
    } else {
        ip4_mut[19] = 67;
        eth_mut[0..6].copy_from_slice(&CLIENT_MAC);
        "LOAD -> CLIENT"
    };

    let ip_source = *ip4_mut[12..16].first_chunk::<4>().unwrap();
    let ip_destination = *ip4_mut[16..20].first_chunk::<4>().unwrap();

    let eth_source = *eth_mut[6..12].first_chunk::<6>().unwrap();
    let eth_destination = *eth_mut[0..6].first_chunk::<6>().unwrap();

    data.scheck_bounds(OFFSET).ok_or(xdp_action::XDP_PASS)?;
    let checksum =
        calc_ip_csum::<SIZE>(Ipv4HeaderSlice::from_slice(ip4_mut).unwrap()).to_be_bytes();
    ip4_mut[10..12].copy_from_slice(&checksum);

    info!(
        data.ctx,
        "{} csum: 0x{:x}\n[{:mac}] {:i}:{}\n[{:mac}] {:i}:{}",
        msg,
        u16::from_be_bytes(checksum),
        core::hint::black_box(eth_source),
        core::hint::black_box(u32::from_be_bytes(ip_source)),
        core::hint::black_box(udp.source_port()),
        core::hint::black_box(eth_destination),
        core::hint::black_box(u32::from_be_bytes(ip_destination)),
        core::hint::black_box(udp.destination_port()),
    );

    let packet_len = data.ctx.data_end() - data.ctx.data();
    if packet_len <= 1500 {
        if let Some(mut space) = PACKET.reserve::<[u8; 1508]>(0) {
            if packet_len >= OFFSET + UdpHeader::LEN {
                unsafe {
                    (space.as_mut_ptr() as *mut u8).write_bytes(0, 1500);
                    let ret = aya_ebpf::helpers::bpf_xdp_load_bytes(
                        data.ctx.ctx,
                        0,
                        (space.as_ptr() as *const u8).add(8) as *mut _,
                        packet_len as u32,
                    );

                    ptr::write_unaligned(
                        space.as_mut_ptr() as *mut [u8; 8],
                        packet_len.to_be_bytes(),
                    );

                    if ret == 0 {
                        space.submit(0);
                        info!(
                            data.ctx,
                            "Packet of length {} submitted to ring buffer", packet_len
                        );
                    } else {
                        info!(
                            data.ctx,
                            "Packet of length {} failed to submit to ring buffer from xdp_load err: {}", packet_len, ret
                        );
                        space.discard(0);
                    }
                }
            } else {
                info!(
                    data.ctx,
                    "Packet of length {} failed to submit to ring buffer", packet_len
                );

                space.discard(0);
            }

            // Submit the packet data to the ring buffer
        }
    }

    Ok(xdp_action::XDP_TX)
}

fn parse_udp_header<const START: usize>(data: &mut Data) -> Option<UdpHeaderSlice<'static>> {
    data.scheck_bounds(START + UdpHeader::LEN)?;

    const HEADER_LEN: usize = UdpHeader::LEN;

    let slice = data.schecked_slice(START, HEADER_LEN)?;
    let header = UdpHeaderSlice::from_slice(slice).ok()?;

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
