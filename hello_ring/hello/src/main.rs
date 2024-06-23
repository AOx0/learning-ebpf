use aya::maps::RingBuf;
use aya::programs::KProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use hello_common::Data;
use log::{debug, info, warn};
use tokio::{io::unix::AsyncFd, signal};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
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
        "../../target/bpfel-unknown-none/debug/hello"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/hello"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("hello").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_execve", 0)?;

    let map = bpf.map("OUTPUT").unwrap();
    let mapa = RingBuf::try_from(map).unwrap();
    let mut poll = AsyncFd::new(mapa).unwrap();

    loop {
        let mut guard = poll.readable_mut().await.unwrap();
        let ring = guard.get_inner_mut();
        while let Some(ref data) = ring.next() {
            let [data]: &[Data] = unsafe { data.align_to() }.1 else {
                continue;
            };

            println!("{:?}", data);
        }
        guard.clear_ready();
    }

    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}
