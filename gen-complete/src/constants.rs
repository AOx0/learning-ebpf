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

pub const PROG_FUNCT: &str = r#"
function __fish_bpftool_prog_profile_needs_completion
    set -l cmd (commandline -opc)
    set -l token (commandline -t)
    set -l cursor_pos (commandline -C)
    set -l cmd_str (commandline -c)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")

    if string match -q "*id " "$cmd_before_cursor"
        or string match -q "*name " "$cmd_before_cursor" 
        or string match -q "*tag " "$cmd_before_cursor"
        or string match -q "*pinned " "$cmd_before_cursor"
        if test -z "$token"; or test (string length "$token") -eq (math $cursor_pos - (string length "$cmd_before_cursor"))
            return 0
        end
    end
    return 1
end

function __fish_bpftool_keyword_needs_completion
    set -l keyword $argv[1]
    set -l cmd (commandline -opc)
    set -l token (commandline -t)
    set -l cursor_pos (commandline -C)
    set -l cmd_str (commandline -c)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")

    if string match -q "$keyword " "$cmd_before_cursor"
        if test -z "$token"; or test (string length "$token") -eq (math $cursor_pos - (string length "$cmd_before_cursor"))
            return 0
        end
    end
    return 1
end

function __fish_bpftool_count_keyword
    set -l keyword $argv[1]
    set -l cmd_str (commandline -c)
    set -l cursor_pos (commandline -C)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")
    echo (count (string match -a -- $keyword (string split ' ' "$cmd_before_cursor")))
end

function __fish_bpftool_get_last_token
    set -l cmd_str (commandline -c)
    set -l cursor_pos (commandline -C)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")
    set cmd_before_cursor (string replace -r ' {2,}' ' ' "$cmd_before_cursor")
    set cmd_before_cursor (string trim "$cmd_before_cursor")
    set -l cmd_parts (string split ' ' "$cmd_before_cursor")

    echo $cmd_parts[-1]
end

function __fish_bpftool_count_commands
    set -l cmd_str (commandline -c)
    set -l cursor_pos (commandline -C)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")
    set cmd_before_cursor (string replace -r ' {2,}' ' ' "$cmd_before_cursor")
    # The last space does need to be counted
    # set cmd_before_cursor (string trim "$cmd_before_cursor")
    set -l cmd_parts (string split ' ' "$cmd_before_cursor")
    set -l cmd_count 0
    for part in $cmd_parts[2..-1] # Start from index 2 to skip the command name (bpftool)
        if not string match -q -- '-*' $part # Ignore flags (starting with -)
            set cmd_count (math $cmd_count + 1)
        end
    end
    echo $cmd_count
end

function __fish_bpftool_complete_file 
    set -l options 's/source=' 'f/filters='
    argparse $options -- $argv
    
    set ct -l (commandline -ct)
    set ct (string trim $ct)
    set start -l ""

    if set -q _flag_source
        set start "$_flag_source"
    end

    if test -n "$ct"
        set start "$ct"
    end

    if set -q _flag_filters
        complete -C"\'\' $start" | string match -re "(?:/$_flag_filters)\$"
    else
        complete -C"\'\' $start"
    end
end

function __fish_bpftool_complete_o_file
    complete -C"\'\' $(commandline -ct)" | string match -re "(?:/|\.o)\$"
end

function __fish_bpftool_complete_map_id
    sudo bpftool map list | rg '^\d+:' | awk -F ' ' '{ print($1 "\'"$4"\'") }' | sed 's/:/\t/g'
end

function __fish_bpftool_complete_progs_id
    sudo bpftool prog list | rg '^\d+:' | awk -F ' ' '{ print($1 "\'"$4"\'") }' | sed 's/:/\t/g'
end

function __fish_bpftool_complete_progs_name
    sudo bpftool prog list | rg 'name ' | awk -F ' ' '{ print($4) }'
end

function __fish_bpftool_complete_progs_tag
    sudo bpftool prog list | rg 'tag ' | awk -F ' ' '{ print($6) }'
end
"#;
