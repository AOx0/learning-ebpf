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