pub const FISH_FUNCTIONS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/functions.fish"));

pub const PROGRAM_TYPES: [(&str, &str); 48] = [
    ("socket", "Attach to network sockets"),
    ("kprobe", "Instrument kernel function entry"),
    ("kretprobe", "Instrument kernel function return"),
    ("classifier", "Classify network packets"),
    ("action", "Modify network packets"),
    ("tracepoint", "Trace static kernel tracepoints"),
    ("raw_tracepoint", "Trace raw kernel tracepoints"),
    ("xdp", "Process packets at network driver level"),
    ("perf_event", "Attach to performance monitoring events"),
    ("cgroup/skb", "Control network packet handling in cgroups"),
    ("cgroup/sock", "Control socket operations in cgroups"),
    ("cgroup/dev", "Control device access in cgroups"),
    ("lwt_in", "Light-weight tunnel ingress processing"),
    ("lwt_out", "Light-weight tunnel egress processing"),
    ("lwt_xmit", "Light-weight tunnel transmit processing"),
    ("lwt_seg6local", "Segment Routing IPv6 local processing"),
    ("sockops", "Perform socket operations"),
    ("sk_skb", "Operate on network socket buffers"),
    ("sk_msg", "Process socket messages"),
    ("lirc_mode2", "Process infrared remote control signals"),
    ("cgroup/bind4", "Control IPv4 bind operations in cgroups"),
    ("cgroup/bind6", "Control IPv6 bind operations in cgroups"),
    ("cgroup/post_bind4", "Post-bind IPv4 operations in cgroups"),
    ("cgroup/post_bind6", "Post-bind IPv6 operations in cgroups"),
    (
        "cgroup/connect4",
        "Control IPv4 connect operations in cgroups",
    ),
    (
        "cgroup/connect6",
        "Control IPv6 connect operations in cgroups",
    ),
    (
        "cgroup/connect_unix",
        "Control Unix domain socket connect in cgroups",
    ),
    ("cgroup/getpeername4", "Control IPv4 getpeername in cgroups"),
    ("cgroup/getpeername6", "Control IPv6 getpeername in cgroups"),
    (
        "cgroup/getpeername_unix",
        "Control Unix getpeername in cgroups",
    ),
    ("cgroup/getsockname4", "Control IPv4 getsockname in cgroups"),
    ("cgroup/getsockname6", "Control IPv6 getsockname in cgroups"),
    (
        "cgroup/getsockname_unix",
        "Control Unix getsockname in cgroups",
    ),
    ("cgroup/sendmsg4", "Control IPv4 sendmsg in cgroups"),
    ("cgroup/sendmsg6", "Control IPv6 sendmsg in cgroups"),
    ("cgroup/sendmsg_unix", "Control Unix sendmsg in cgroups"),
    ("cgroup/recvmsg4", "Control IPv4 recvmsg in cgroups"),
    ("cgroup/recvmsg6", "Control IPv6 recvmsg in cgroups"),
    ("cgroup/recvmsg_unix", "Control Unix recvmsg in cgroups"),
    ("cgroup/sysctl", "Control sysctl operations in cgroups"),
    ("cgroup/getsockopt", "Control getsockopt in cgroups"),
    ("cgroup/setsockopt", "Control setsockopt in cgroups"),
    ("cgroup/sock_release", "Handle socket release in cgroups"),
    ("struct_ops", "Implement kernel structures in eBPF"),
    ("fentry", "Hook function entry"),
    ("fexit", "Hook function exit"),
    ("freplace", "Replace kernel functions"),
    ("sk_lookup", "Perform socket lookup operations"),
];

pub const ATTACH_TYPES: [(&str, &str); 5] = [
    ("sk_msg_verdict", "Deliver verdict on socket messages"),
    ("sk_skb_verdict", "Deliver verdict on socket buffers"),
    (
        "sk_skb_stream_verdict",
        "Deliver verdict on stream socket buffers",
    ),
    ("sk_skb_stream_parser", "Parse stream socket buffers"),
    ("flow_dissector", "Analyze and dissect network flows"),
];

pub const METRIC_TYPES: [(&str, &str); 6] = [
    ("cycles", "CPU cycle count"),
    ("instructions", "Executed instruction count"),
    ("l1d_loads", "L1 data cache load operations"),
    ("llc_misses", "Last-level cache misses"),
    ("itlb_misses", "Instruction TLB misses"),
    ("dtlb_misses", "Data TLB misses"),
];
