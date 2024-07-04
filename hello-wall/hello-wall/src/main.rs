use std::io::Write;

use anyhow::Context;
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use byteorder::BigEndian;
use clap::Parser;
use log::{debug, info, warn};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use pcap_file::pcapng::blocks::packet::PacketBlock;
use pcap_file::pcapng::{Block, PcapNgBlock, PcapNgWriter};
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hello-wall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/hello-wall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("hello_wall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let packets = RingBuf::try_from(bpf.map("PACKET").unwrap()).unwrap();
    let mut fd = AsyncFd::new(packets).unwrap();
    let mut counter = 1;
    let file = std::fs::File::create("out.pcap").expect("Error creating file");
    let mut pcapng_writer = PcapWriter::new(file).unwrap();

    let start = tokio::time::Instant::now();
    loop {
        let mut guard = fd.readable_mut().await.unwrap();
        let inner = guard.get_inner_mut();

        while let Some(packet) = inner.next() {
            let size = usize::from_be_bytes([
                packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6],
                packet[7],
            ]);
            pcapng_writer
                .write_packet(&PcapPacket::new(
                    tokio::time::Instant::now().duration_since(start),
                    size as u32,
                    &packet[8..=size],
                ))
                .unwrap();
            info!("Packet size {:?}", size);
        }

        guard.clear_ready();
    }

    pcapng_writer.into_writer().flush();
}
