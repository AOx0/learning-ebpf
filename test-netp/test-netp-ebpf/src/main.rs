#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use netp::{
    aya::XdpErr,
    bounds,
    eth::{EtherType, Ethernet},
    ipv4::IPv4,
    tcp::Tcp,
    udp::Udp,
    InetProtocol,
};

// ip a | grep mtu
const MTU: usize = 1500;

#[xdp]
pub fn test_netp(ctx: XdpContext) -> u32 {
    match try_test_netp(ctx) {
        Ok(ret) => ret,
        Err(code) => code,
    }
}

fn try_test_netp(ctx: XdpContext) -> Result<u32, u32> {
    if ctx.data_end() - ctx.data() > MTU {
        unsafe { core::hint::unreachable_unchecked() }
    }

    let packet = unsafe {
        core::slice::from_raw_parts_mut(ctx.data() as *mut u8, ctx.data_end() - ctx.data())
    };

    bounds!(ctx, Ethernet::MIN_LEN, ret Err(xdp_action::XDP_DROP));
    let (eth, rem) = Ethernet::new(packet).or_drop()?;
    if !matches!(eth.get_ethertype(), EtherType::IPV4) {
        return Ok(xdp_action::XDP_PASS);
    }

    bounds!(ctx, eth.get_size_usize() + IPv4::MIN_LEN, ret Err(xdp_action::XDP_DROP));
    let (ip4, rem) = IPv4::new(rem).or_drop()?;

    let (proto, source_port, destination_port) = match ip4.get_protocol() {
        InetProtocol::UDP => {
            bounds!(ctx, eth.get_size_usize() + ip4.calc_size().unwrap() as usize + Udp::SIZE, ret Err(xdp_action::XDP_DROP));
            let (udp, _) = Udp::new(rem).or_drop()?;

            ("UDP", udp.get_source(), udp.get_destination())
        }
        InetProtocol::TCP => {
            bounds!(ctx, eth.get_size_usize() + ip4.calc_size().unwrap() as usize + Tcp::MIN_LEN, ret Err(xdp_action::XDP_DROP));
            let (tcp, _) = Tcp::new(rem).or_drop()?;

            ("TCP", tcp.get_source(), tcp.get_destination())
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    if destination_port == 22 {
        return Ok(xdp_action::XDP_PASS);
    }

    let destination = *eth.get_destination();
    let source = *eth.get_source();

    let source_ip = ip4.get_source_u32();
    let destination_ip = ip4.get_destination_u32();

    info!(
        &ctx,
        "{} {:i}:{} -> {:i}:{} [{:mac} -> {:mac}]",
        proto,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        source,
        destination,
    );

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
