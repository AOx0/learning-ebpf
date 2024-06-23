
function __fish_bpftool_complete_progs_name
    set -l contains (__fish_bpftool_contains_bpf_name)

    if [ "$contains" = n ]
        sudo bpftool prog list | rg 'name ' | awk -F ' ' '{ print($4) }'
    end
end

function __fish_bpftool_complete_progs_id
    set -l contains (__fish_bpftool_contains_bpf_id)

    if [ "$contains" = n ]
        sudo bpftool prog list | rg '^\d+:' | awk -F ' ' '{ print($1 "\'"$4"\'") }' | sed 's/:/\t/g'
    end
end

function __fish_bpftool_complete_progs_tag
    set -l contains (__fish_bpftool_contains_bpf_tag)

    if [ "$contains" = n ]
        sudo bpftool prog list | rg 'tag ' | awk -F ' ' '{ print($6) }'
    end
end


function __fish_bpftool_contains_bpf_name
    set -l cmd_args (commandline -opc)
    set -l list_arr (sudo bpftool prog list | rg 'name ' | awk -F  ' ' '{ print($4) }')
    set -l contains n

    for arg in $cmd_args
        if contains -- $arg $list_arr
            set contains s
        end
    end

    echo $contains
end

function __fish_bpftool_contains_bpf_id
    set -l cmd_args (commandline -opc)
    set -l list_arr (sudo bpftool prog list | rg '^\d+:' | awk -F ' ' '{ print($1) }' | sed 's/://g')
    set -l contains n

    for arg in $cmd_args
        if contains -- $arg $list_arr
            set contains s
        end
    end

    echo $contains
end

function __fish_bpftool_contains_bpf_tag
    set -l cmd_args (commandline -opc)
    set -l list_arr (sudo bpftool prog list | rg 'tag ' | awk -F  ' ' '{ print($6) }')
    set -l contains n

    for arg in $cmd_args
        if contains -- $arg $list_arr
            set contains s
        end
    end

    echo $contains
end

function __fish_bpftool_prog_profile_needs_completion
    set -l cmd (commandline -opc)
    set -l token (commandline -t)
    set -l cursor_pos (commandline -C)
    set -l cmd_str (commandline -c)
    set -l cmd_before_cursor (string sub -l $cursor_pos "$cmd_str")

    # Check if we're right after 'id', 'name', or 'tag'
    if string match -q "*id " "$cmd_before_cursor"; or string match -q "*name " "$cmd_before_cursor"; or string match -q "*tag " "$cmd_before_cursor"
        # Only complete if the current token is empty or we're at the end of it
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

function __fish_bpftool_complete_prog_id
    sudo bpftool prog list | rg '^\d+:' | awk -F ' ' '{ print($1 "\t"$4) }' | sed 's/://g'
end

function __fish_bpftool_complete_map_id
    sudo bpftool map list | rg '^\d+:' | awk -F ' ' '{ print($1 "\t"$4) }' | sed 's/://g'
end

complete -c bpftool -n '__fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 1' -a '(__fish_bpftool_complete_prog_id)'
complete -c bpftool -n '__fish_bpftool_prog_profile_needs_completion; and test (__fish_bpftool_count_keyword id) -eq 2' -a '(__fish_bpftool_complete_map_id)'
