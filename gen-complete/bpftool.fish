set -l commands map prog link cgroup perf net feature btf gen struct_ops iter
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

function __fish_bpftool_count_keyword
    set -l keyword $argv[1]
    set -l cmd_str (commandline -c)
    set -l cursor_pos (commandline -C)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")
    echo (count (string match -a -- $keyword (string split ' ' "$cmd_before_cursor")))
end

function __fish_bpftool_count_commands
    set -l cmd_str (commandline -c)
    set -l cursor_pos (commandline -C)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")
    set -l cmd_parts (string split ' ' "$cmd_before_cursor")
    set -l cmd_count 0
    for part in $cmd_parts[3..-1] # Start from index 2 to skip the command name (bpftool)
        if not string match -q -- '-*' $part # Ignore flags (starting with -)
            set cmd_count (math $cmd_count + 1)
        end
    end
    echo $cmd_count
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


# Top level help
complete -c bpftool -s h -l help -d "Print short help message"
complete -c bpftool -s V -l version -d "Print version number, libbpf version, and included optional features."
complete -c bpftool -s j -l json -d "Generate JSON output."
complete -c bpftool -s p -l pretty -d "Generate human-readable JSON output. Implies -j."
complete -c bpftool -s d -l debug -d "Print all available logs, even debug-level information."
complete -c bpftool -s m -l mapcompat -d "Allow loading maps with unknown map definitions."
complete -c bpftool -s n -l nomount -d "Do not automatically attempt to mount any virtual file system when necessary."


# Top level commands
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka iter -d "Create BPF iterators"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka struct_ops -d "Register/unregister/introspect BPF struct_ops"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka gen -d "BPF code-generation"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka btf -d "Inspect BTF data"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka feature -d "Inspect eBPF-related parameters for Linux kernel or net device"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka net -d "Inspect networking related bpf prog attachments"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka perf -d "Inspect perf related bpf prog attachments"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka cgroup -d "Inspect and manipulate eBPF progs"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka link -d "Inspect and manipulate eBPF links"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka prog -d "Inspect and manipulate eBPF progs"
complete -c bpftool -n "not __fish_seen_subcommand_from $commands" -ka map -d "Inspect and manipulate eBPF maps"


# bpftool-prog
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka help -d "Print short help message"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka profile -d "Profile bpf program"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka run -d "Run BPF program in the kernel testing infrastructure"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka tracelog -d "Dump the trace pipe of the system to stdout"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka detach -d "Detach bpf program"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka attach -d "Attach bpf program"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka loadall -d "Load bpf program(s) from binary OBJ and pin as PATH"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka load -d "Load bpf program(s) from binary OBJ and pin as PATH"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka pin -d "Pin program as FILE"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka dump -d "Dump eBPF instructions of programs"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka list -d "Show information about loaded programs"
complete -c bpftool -n "__fish_seen_subcommand_from prog; and not __fish_seen_subcommand_from show list dump pin load loadall attach detach tracelog run profile help; and test (__fish_bpftool_count_commands) -eq 1" -ka show -d "Show information about loaded programs"


 # bpftool pin PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from pin; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


 # bpftool list PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from list; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


 # bpftool show PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from show; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


 # bpftool attach PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from attach; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


 # bpftool detach PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from detach; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


 # bpftool run PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from run; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


 # bpftool profile PROG
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a id
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a tag
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and not __fish_seen_subcommand_from id tag name; and test (__fish_bpftool_count_commands) -eq 2" -a name
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from id; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_id)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from tag; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword tag) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_tag)'
complete -c bpftool -n "__fish_seen_subcommand_from prog; and __fish_seen_subcommand_from profile; and __fish_seen_subcommand_from name; and __fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword name) -eq 1; and test (__fish_bpftool_count_commands) -eq 3" -ka '(__fish_bpftool_complete_progs_name)'


# bpftool-prog help
complete -c bpftool -n "__fish_seen_subcommand_from prog" -s f -l bpffs -d "When showing BPF programs, show file names of pinned programs"
complete -c bpftool -n "__fish_seen_subcommand_from prog" -s L -l use-loader -d "Load program as a 'loader' program"
