set -l program_types socket kprobe kretprobe classifier action tracepoint raw_tracepoint xdp perf_event cgroup/skb cgroup/sock cgroup/dev lwt_in lwt_out lwt_xmit lwt_seg6local sockops sk_skb sk_msg lirc_mode2 cgroup/bind4 cgroup/bind6 cgroup/post_bind4 cgroup/post_bind6 cgroup/connect4 cgroup/connect6 cgroup/connect_unix cgroup/getpeername4 cgroup/getpeername6 cgroup/getpeername_unix cgroup/getsockname4 cgroup/getsockname6 cgroup/getsockname_unix cgroup/sendmsg4 cgroup/sendmsg6 cgroup/sendmsg_unix cgroup/recvmsg4 cgroup/recvmsg6 cgroup/recvmsg_unix cgroup/sysctl cgroup/getsockopt cgroup/setsockopt cgroup/sock_release struct_ops fentry fexit freplace sk_lookup
set -l attach_types sk_msg_verdict sk_skb_verdict sk_skb_stream_verdict sk_skb_stream_parser flow_dissector
set -l metric_types cycles instructions l1d_loads llc_misses itlb_misses dtlb_misses
set -l prog_spec name id tag


# Complete functions by name, tag or id
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
complete -c bpftool -f
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s h -l help -d "Print short help message"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s V -l version -d "Print version number, libbpf version, and included optional features."
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s j -l json -d "Generate JSON output."
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s p -l pretty -d "Generate human-readable JSON output. Implies -j."
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s d -l debug -d "Print all available logs, even debug-level information."
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s m -l mapcompat -d "Allow loading maps with unknown map definitions."
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 0" -s n -l nomount -d "Do not automatically attempt to mount any virtual file system when necessary."
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka iter -d "Create BPF iterators"
complete -c bpftool -n "__fish_seen_subcommand_from iter; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from iter; and test (__fish_bpftool_count_commands) -eq 2" -ka pin -d "Create a BPF iterator from an object file and pin it to a path"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka struct_ops -d "Register/unregister/introspect BPF struct_ops"
complete -c bpftool -n "__fish_seen_subcommand_from struct_ops; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from struct_ops; and test (__fish_bpftool_count_commands) -eq 2" -ka unregister -d "Unregister a struct_ops from the kernel subsystem"
complete -c bpftool -n "__fish_seen_subcommand_from struct_ops; and test (__fish_bpftool_count_commands) -eq 2" -ka register -d "Register BPF struct_ops from an object file"
complete -c bpftool -n "__fish_seen_subcommand_from struct_ops; and test (__fish_bpftool_count_commands) -eq 2" -ka dump -d "Dump detailed information about struct_ops in the system"
complete -c bpftool -n "__fish_seen_subcommand_from struct_ops; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "List all struct_ops currently existing in the system"
complete -c bpftool -n "__fish_seen_subcommand_from struct_ops; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "Show brief information about struct_ops in the system"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka gen -d "BPF code-generation tool"
complete -c bpftool -n "__fish_seen_subcommand_from gen; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from gen; and test (__fish_bpftool_count_commands) -eq 2" -ka min_core_btf -d "Generate minimum BTF file for CO-RE relocations"
complete -c bpftool -n "__fish_seen_subcommand_from gen; and test (__fish_bpftool_count_commands) -eq 2" -ka subskeleton -d "Generate BPF subskeleton C header file"
complete -c bpftool -n "__fish_seen_subcommand_from gen; and test (__fish_bpftool_count_commands) -eq 2" -ka skeleton -d "Generate BPF skeleton C header file"
complete -c bpftool -n "__fish_seen_subcommand_from gen; and test (__fish_bpftool_count_commands) -eq 2" -ka object -d "Statically link BPF ELF object files"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka btf -d "Inspect BTF (BPF Type Format) data"
complete -c bpftool -n "__fish_seen_subcommand_from btf; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from btf; and test (__fish_bpftool_count_commands) -eq 2" -ka dump -d "Dump BTF entries from a given source"
complete -c bpftool -n "__fish_seen_subcommand_from btf; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "List all BTF objects currently loaded on the system"
complete -c bpftool -n "__fish_seen_subcommand_from btf; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "Show information about loaded BTF objects"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka feature -d "Inspect eBPF-related parameters for Linux kernel or net device"
complete -c bpftool -n "__fish_seen_subcommand_from feature; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from feature; and test (__fish_bpftool_count_commands) -eq 2" -ka list_builtins -d "List items known to bpftool from compilation time"
complete -c bpftool -n "__fish_seen_subcommand_from feature; and test (__fish_bpftool_count_commands) -eq 2" -ka probe -d "Probe and dump eBPF-related parameters"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka net -d "Inspect networking-related BPF program attachments"
complete -c bpftool -n "__fish_seen_subcommand_from net; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from net; and test (__fish_bpftool_count_commands) -eq 2" -ka detach -d "Detach a BPF program from a network interface"
complete -c bpftool -n "__fish_seen_subcommand_from net; and test (__fish_bpftool_count_commands) -eq 2" -ka attach -d "Attach a BPF program to a network interface"
complete -c bpftool -n "__fish_seen_subcommand_from net; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "List BPF program attachments in the kernel networking subsystem"
complete -c bpftool -n "__fish_seen_subcommand_from net; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "List BPF program attachments in the kernel networking subsystem"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka perf -d "Inspect perf-related BPF program attachments"
complete -c bpftool -n "__fish_seen_subcommand_from perf; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from perf; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "List all raw_tracepoint, tracepoint, and kprobe attachments"
complete -c bpftool -n "__fish_seen_subcommand_from perf; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "List all raw_tracepoint, tracepoint, and kprobe attachments"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka cgroup -d "Inspect and manipulate eBPF progs in cgroups"
complete -c bpftool -n "__fish_seen_subcommand_from cgroup; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from cgroup; and test (__fish_bpftool_count_commands) -eq 2" -ka detach -d "Detach a program from a cgroup"
complete -c bpftool -n "__fish_seen_subcommand_from cgroup; and test (__fish_bpftool_count_commands) -eq 2" -ka attach -d "Attach a program to a cgroup"
complete -c bpftool -n "__fish_seen_subcommand_from cgroup; and test (__fish_bpftool_count_commands) -eq 2" -ka tree -d "List attached programs for all cgroups in a hierarchy"
complete -c bpftool -n "__fish_seen_subcommand_from cgroup; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "List all programs attached to a specific cgroup"
complete -c bpftool -n "__fish_seen_subcommand_from cgroup; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "List all programs attached to a specific cgroup"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka link -d "Inspect and manipulate eBPF links"
complete -c bpftool -n "__fish_seen_subcommand_from link; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from link; and test (__fish_bpftool_count_commands) -eq 2" -ka detach -d "Force-detach a link"
complete -c bpftool -n "__fish_seen_subcommand_from link; and test (__fish_bpftool_count_commands) -eq 2" -ka pin -d "Pin link to a file in bpffs"
complete -c bpftool -n "__fish_seen_subcommand_from link; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "Show information about active links"
complete -c bpftool -n "__fish_seen_subcommand_from link; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "Show information about active links"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -s f -l bpffs -d "When showing BPF programs, show file names of pinned programs"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -s L -l use-loader -d "Load program as a 'loader' program"
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka prog -d "Inspect and manipulate eBPF progs"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka profile -d "Profile bpf program"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 3" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 3" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 3" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 5" -ka cycles -d "CPU cycle count"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 5" -ka instructions -d "Executed instruction count"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 5" -ka l1d_loads -d "L1 data cache load operations"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 5" -ka llc_misses -d "Last-level cache misses"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 5" -ka itlb_misses -d "Instruction TLB misses"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and test (__fish_bpftool_count_commands) -eq 5" -ka dtlb_misses -d "Data TLB misses"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka run -d "Run BPF program in the kernel testing infrastructure"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and test (__fish_bpftool_count_commands) -eq 3" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and test (__fish_bpftool_count_commands) -eq 3" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and test (__fish_bpftool_count_commands) -eq 3" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and test (__fish_bpftool_count_commands) -eq 5" -ka data_in -d ""
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and not __fish_should_complete_switches; and test (__fish_bpftool_count_commands) -eq 6" -f -x -a "(__fish_bpftool_complete_file  )"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka tracelog -d "Dump the trace pipe of the system to stdout"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka detach -d "Detach bpf program"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_msg_verdict -d "Deliver verdict on socket messages"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_skb_verdict -d "Deliver verdict on socket buffers"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_skb_stream_verdict -d "Deliver verdict on stream socket buffers"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_skb_stream_parser -d "Parse stream socket buffers"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and test (__fish_bpftool_count_commands) -eq 3" -ka flow_dissector -d "Analyze and dissect network flows"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and test (__fish_bpftool_count_commands) -eq 4" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_map_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka attach -d "Attach bpf program PROG (with type specified by ATTACH_TYPE)."
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_msg_verdict -d "Deliver verdict on socket messages"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_skb_verdict -d "Deliver verdict on socket buffers"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_skb_stream_verdict -d "Deliver verdict on stream socket buffers"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and test (__fish_bpftool_count_commands) -eq 3" -ka sk_skb_stream_parser -d "Parse stream socket buffers"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and test (__fish_bpftool_count_commands) -eq 3" -ka flow_dissector -d "Analyze and dissect network flows"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and test (__fish_bpftool_count_commands) -eq 4" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_map_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka loadall -d "Pins all programs from the OBJ under PATH directory.Note: PATH must be located in bpffs mount. It must not contain a dot character ('.'), which is reserved for future extensions of bpffs."
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka load -d " Pins only the first program from the OBJ as PATH.Note: PATH must be located in bpffs mount. It must not contain a dot character ('.'), which is reserved for future extensions of bpffs."
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from load; and not __fish_should_complete_switches; and test (__fish_bpftool_count_commands) -eq 3" -f -x -a "(__fish_bpftool_complete_file  --filters='|\.o')"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka pin -d "Pin program as a FILE"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and test (__fish_bpftool_count_commands) -eq 3" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and test (__fish_bpftool_count_commands) -eq 3" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and test (__fish_bpftool_count_commands) -eq 3" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and not __fish_should_complete_switches; and test (__fish_bpftool_count_commands) -eq 5" -f -x -a "(__fish_bpftool_complete_file --source='/sys/fs/bpf/' )"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka dump -d "Dump eBPF instructions/image of programs"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and test (__fish_bpftool_count_commands) -eq 3" -ka jited -d "Dump jited image (host machine code) of the program"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -eq 4" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -eq 4" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -eq 4" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -ge 6" -ka opcodes -d "Display raw codes"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -ge 6" -ka file -d "Dump eBPF instructions of the programs from the kernel"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -ge 6" -ka linum -d "Display filename, line number and column"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and test (__fish_bpftool_count_commands) -ge 6" -ka visual -d "Display eBPF instructions with CFG in DOT format"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from jited; and not __fish_should_complete_switches; and test (__fish_bpftool_count_commands) -gt 6" -f -x -a "(__fish_bpftool_complete_file  )"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and test (__fish_bpftool_count_commands) -eq 3" -ka xlated -d "Dump eBPF instructions of the programs from the kernel"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -eq 4" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -eq 4" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -eq 4" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 5" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -ge 6" -ka opcodes -d "Display raw codes"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -ge 6" -ka file -d "Dump eBPF instructions of the programs from the kernel"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -ge 6" -ka linum -d "Display filename, line number and column"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and test (__fish_bpftool_count_commands) -ge 6" -ka visual -d "Display eBPF instructions with CFG in DOT format"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from dump; and __fish_seen_subcommand_from xlated; and not __fish_should_complete_switches; and test (__fish_bpftool_count_commands) -gt 6" -f -x -a "(__fish_bpftool_complete_file  )"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "Show information about loaded programs"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and test (__fish_bpftool_count_commands) -eq 3" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and test (__fish_bpftool_count_commands) -eq 3" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and test (__fish_bpftool_count_commands) -eq 3" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "Show information about loaded programs"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and test (__fish_bpftool_count_commands) -eq 3" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and test (__fish_bpftool_count_commands) -eq 3" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and test (__fish_bpftool_count_commands) -eq 3" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'id'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'tag'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_get_last_token) = 'name'; and test (__fish_bpftool_count_commands) -eq 4" -ka '(__fish_bpftool_complete_progs_name)'
complete -c bpftool -n "test (__fish_bpftool_count_commands) -eq 1" -ka map -d "Inspect and manipulate eBPF maps"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka freeze -d "Freeze the map as read-only from user space"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka dequeue -d "Dequeue and print value from the queue"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka enqueue -d "Enqueue value into the queue"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka pop -d "Pop and print value from the stack"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka push -d "Push value onto the stack"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka peek -d "Peek next value in the queue or stack"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka event_pipe -d "Read events from a perf event array map"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka pin -d "Pin map to a file"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka delete -d "Remove entry from the map"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka getnext -d "Get next key in the map"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka lookup -d "Lookup key in the map"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka update -d "Update map entry for a given key"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka dump -d "Dump all entries in a given map"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka create -d "Create a new map with given parameters"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka list -d "Show information about loaded maps"
complete -c bpftool -n "__fish_seen_subcommand_from map; and test (__fish_bpftool_count_commands) -eq 2" -ka show -d "Show information about loaded maps"
