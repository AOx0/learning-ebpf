use aya::maps::{ProgramArray, RingBuf};
use aya::programs::RawTracePoint;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{debug, warn};
use raw_syscall_common::Args;
use tokio::io::unix::AsyncFd;

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
        "../../target/bpfel-unknown-none/debug/raw_syscall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/raw_syscall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    macro_rules! register {
        ($name:expr) => {{
            let program0: &mut RawTracePoint = bpf.program_mut($name).unwrap().try_into().unwrap();
            program0.load()?;
            program0
        }};
    }

    macro_rules! fd {
        ($name:expr) => {{
            let program0: &RawTracePoint = bpf.program($name).unwrap().try_into().unwrap();

            program0.fd().unwrap()
        }};
    }

    let program = register!("raw_syscall");
    program.attach("sys_enter")?;

    let _ = register!("print_execve");
    let _ = register!("do_nothing");
    let _ = register!("print_timer");
    let _ = register!("print_kill");

    let mut programs = ProgramArray::try_from(bpf.take_map("PROGRAMS").unwrap()).unwrap();

    let exec_fd = fd!("print_execve");
    let void_fd = fd!("do_nothing");
    let time_fd = fd!("print_timer");
    let kill_fd = fd!("print_kill");

    programs.set(59, exec_fd, 0).unwrap();

    programs.set(62, kill_fd, 0).unwrap();

    for timer in 222..=226 {
        programs.set(timer, time_fd, 0).unwrap();
    }

    programs.set(0, void_fd, 0).unwrap();
    programs.set(1, void_fd, 0).unwrap();
    programs.set(22, void_fd, 0).unwrap();
    programs.set(23, void_fd, 0).unwrap();
    programs.set(25, void_fd, 0).unwrap();

    let regs = RingBuf::try_from(bpf.map_mut("REGS").unwrap()).unwrap();
    let mut poll = AsyncFd::new(regs).unwrap();

    loop {
        let mut guard = poll.readable_mut().await.unwrap();
        let inner = guard.get_inner_mut();
        while let Some(ref data) = inner.next() {
            let [_reg]: &[Args] = (unsafe { data.align_to().1 }) else {
                continue;
            };

            // if reg.op == 59 {
            // println!("{reg:?}");
            // }
        }
        guard.clear_ready();
    }

    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}
