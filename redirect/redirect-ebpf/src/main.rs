#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::RingBuf,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use netp::{
    aya::XdpErr,
    bounds,
    eth::{EtherType, Ethernet},
    ipv4::IPv4,
    udp::Udp,
    InetProtocol,
};

#[map]
static PACKET: RingBuf = RingBuf::with_byte_size(1024 * 16, 0);
const MTU: usize = 1500;

const CLIENT: [u8; 4] = [192, 168, 1, 67];
const CLIENT_MAC: [u8; 6] = [0xa4, 0x83, 0xe7, 0x4d, 0x99, 0x65];

const SERVER: [u8; 4] = [192, 168, 1, 112];
const SERVER_MAC: [u8; 6] = [0x18, 0x3d, 0xa2, 0x55, 0x7f, 0xb0];

const LOADER: [u8; 4] = [192, 168, 1, 99];
const LOADER_MAC: [u8; 6] = [0x00, 0x45, 0xe2, 0x4d, 0x9f, 0xe5];

#[xdp]
pub fn hello_wall(ctx: XdpContext) -> u32 {
    match try_hello_wall(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello_wall(ctx: XdpContext) -> Result<u32, u32> {
    if ctx.data_end() - ctx.data() > MTU {
        unsafe { core::hint::unreachable_unchecked() }
    }

    let packet = unsafe {
        core::slice::from_raw_parts_mut(ctx.data() as *mut u8, ctx.data_end() - ctx.data())
    };

    bounds!(ctx, Ethernet::MIN_LEN).or_drop()?;
    let (mut eth, rem) = Ethernet::new(packet).or_drop()?;
    if !matches!(eth.ethertype(), EtherType::IPV4) {
        return Ok(xdp_action::XDP_PASS);
    }

    bounds!(ctx, eth.size_usize() + IPv4::MIN_LEN).or_drop()?;
    let (mut ip4, rem) = IPv4::new(rem).or_drop()?;
    if !matches!(ip4.protocol(), InetProtocol::UDP) {
        return Ok(xdp_action::XDP_PASS);
    }

    bounds!(ctx, eth.size_usize() + ip4.size() as usize + Udp::SIZE).or_drop()?;
    let (mut udp, _) = Udp::new(rem).or_drop()?;
    if !((ip4.source() == &SERVER) || (ip4.source() == &CLIENT && udp.destination() == 5000)) {
        return Ok(xdp_action::XDP_PASS);
    }

    let msg = if ip4.source() == &CLIENT {
        ip4.set_destination(&SERVER);
        eth.set_destination(&SERVER_MAC);
        "LOAD -> SERVER"
    } else {
        ip4.set_destination(&CLIENT);
        eth.set_destination(&CLIENT_MAC);
        "LOAD -> CLIENT"
    };

    ip4.set_source(&LOADER);
    eth.set_source(&LOADER_MAC);
    udp.set_checksum_zero();
    ip4.update_csum();
    let csum = ip4.csum();

    info!(
        &ctx,
        "{} csum: 0x{:x}\n[{:mac}] {:i}:{}\n[{:mac}] {:i}:{}",
        msg,
        csum,
        *eth.source(),
        ip4.source_u32(),
        udp.source(),
        *eth.destination(),
        ip4.destination_u32(),
        udp.destination(),
    );

    let _ = save_to_pcap(eth, ip4, udp, ctx);

    Ok(xdp_action::XDP_TX)
}

fn save_to_pcap(eth: Ethernet, ip4: IPv4, udp: Udp, ctx: XdpContext) -> Result<(), ()> {
    if let Some(mut space) = PACKET.reserve::<[u8; 1502]>(0) {
        let ret = unsafe {
            let size = (eth.size_usize() as u32) + ip4.size() as u32 + udp.length() as u32;

            core::ptr::write_unaligned(
                space.as_mut_ptr() as *mut [u8; 2],
                (size as u16).to_be_bytes(),
            );
            if size < (Ethernet::MIN_LEN + IPv4::MIN_LEN + Udp::SIZE) as u32 {
                space.discard(0);
                return Err(());
            }

            if size > MTU as u32 {
                space.discard(0);
                return Err(());
            }

            aya_ebpf::helpers::bpf_xdp_load_bytes(
                ctx.ctx,
                0,
                (space.as_ptr() as *const u8).add(2) as *mut _,
                size,
            )
        };

        if ret == 0 {
            space.submit(0);
            info!(&ctx, "Packet submitted to ring buffer");
        } else {
            space.discard(0);
            info!(&ctx, "Packet failed to submit to ring buffer");
        }
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
