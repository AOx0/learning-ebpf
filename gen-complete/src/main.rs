use std::{fmt::Display, ops::Not};

use itertools::Itertools;

macro_rules! SEC {
    ($section:expr) => {
        concat!(SEC!(), "# ", $section, "\n")
    };
    () => {
        "\n\n"
    };
}

fn contains_bpf_name() -> &'static str {
    r##"
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
"##
}

fn contains_bpf_id() -> &'static str {
    r#"
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
"#
}

fn contains_bpf_tag() -> &'static str {
    r#"
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
"#
}

fn complete_by_id() -> &'static str {
    r#"
function __fish_bpftool_complete_progs_id
    set -l contains (__fish_bpftool_contains_bpf_id)

    if [ "$contains" = n ]
        sudo bpftool prog list | rg '^\d+:' | awk -F ' ' '{ print($1 "\'"$4"\'") }' | sed 's/:/\t/g'
    end
end

function __fish_bpftool_complete_progs_repeating_id
    sudo bpftool prog list | rg '^\d+:' | awk -F ' ' '{ print($1 "\'"$4"\'") }' | sed 's/:/\t/g'
end
"#
}

fn complete_by_name() -> &'static str {
    r#"
function __fish_bpftool_complete_progs_name
    set -l contains (__fish_bpftool_contains_bpf_name)

    if [ "$contains" = n ]
        sudo bpftool prog list | rg 'name ' | awk -F ' ' '{ print($4) }'
    end
end

function __fish_bpftool_complete_progs_repeating_name
    sudo bpftool prog list | rg 'name ' | awk -F ' ' '{ print($4) }'
end
"#
}

fn complete_by_tag() -> &'static str {
    r#"
function __fish_bpftool_complete_progs_tag
    set -l contains (__fish_bpftool_contains_bpf_tag)

    if [ "$contains" = n ]
        sudo bpftool prog list | rg 'tag ' | awk -F ' ' '{ print($6) }'
    end
end

function __fish_bpftool_complete_progs_repeating_tag
    sudo bpftool prog list | rg 'tag ' | awk -F ' ' '{ print($6) }'
end
"#
}

#[derive(Default)]
struct Condition<'a> {
    pub parents: &'a [&'a str],
    pub peers: &'a [(&'a str, &'a str)],
    pub requires_peers: bool,
    pub conflicts: &'a [&'a str],
}

impl Condition<'_> {
    fn empty() -> Self {
        Self::default()
    }
}

impl<'a> Display for Condition<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.parents.is_empty() && self.peers.is_empty() && self.conflicts.is_empty() {
            write!(f, r#"complete -c bpftool"#)
        } else {
            write!(f, r#"complete -c bpftool -n ""#)?;

            for (i, parent) in self.parents.iter().enumerate() {
                write!(f, r#"__fish_seen_subcommand_from {parent};"#)?;
                if i < self.parents.len() - 1 {
                    write!(f, "and ")?;
                }
            }

            if self.peers.is_empty().not() {
                write!(
                    f,
                    r#"{chain}{seen} __fish_seen_subcommand_from {commands}{end}"#,
                    chain = if self.parents.is_empty().not() {
                        " and "
                    } else {
                        ""
                    },
                    seen = if self.requires_peers { "" } else { "not" },
                    commands = self.peers.iter().map(|a| a.0).join(" "),
                    end = if self.conflicts.is_empty().not() {
                        ";"
                    } else {
                        ""
                    }
                )?;
            }

            if self.conflicts.is_empty().not() {
                write!(
                    f,
                    "{chain}not __fish_seen_subcommand_from {commands}",
                    chain = if self.parents.is_empty().not() || self.peers.is_empty().not() {
                        " and "
                    } else {
                        ""
                    },
                    commands = self.conflicts.join(" ")
                )?
            }

            write!(f, r#"""#)
        }
    }
}

struct Command<'a> {
    pub condition: Condition<'a>,
    pub prog: (&'a str, &'a str),
}

impl<'a> Display for Command<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.condition)?;
        writeln!(f, r#" -a {} -d "{}""#, self.prog.0, self.prog.1)?;

        Ok(())
    }
}

struct Help<'a> {
    pub condition: Condition<'a>,
    pub help: (char, &'a str, &'a str),
}

impl<'a> Display for Help<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.condition)?;
        writeln!(
            f,
            r#" -s {short} -l {long} -d "{desc}""#,
            short = self.help.0,
            long = self.help.1,
            desc = self.help.2
        )?;

        Ok(())
    }
}

#[derive(Default)]
struct Prog<'a> {
    pub condition: Condition<'a>,
    allow_repetition: bool,
}

impl<'a> Display for Prog<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let selectors = ["id", "tag", "name"];
        for selector in selectors {
            write!(
                f,
                "{}",
                Condition {
                    conflicts: &if self.allow_repetition {
                        self.condition.conflicts.to_vec()
                    } else {
                        self.condition
                            .conflicts
                            .iter()
                            .chain(selectors.iter())
                            .copied()
                            .collect_vec()
                    },
                    ..self.condition
                }
            )?;
            writeln!(f, " -a {selector}", selector = selector)?;
        }

        for selector in selectors {
            write!(
                f,
                "{}",
                Condition {
                    parents: &self
                        .condition
                        .parents
                        .iter()
                        .chain([selector].iter())
                        .copied()
                        .collect_vec(),
                    ..self.condition
                }
            )?;
            writeln!(
                f,
                " -ka '(__fish_bpftool_complete_progs{repeating}_{selector})'",
                repeating = if self.allow_repetition {
                    "_repeating"
                } else {
                    ""
                },
                selector = selector
            )?;
        }

        Ok(())
    }
}

fn main() {
    let mut res = String::new();

    let program_types = [
        ("socket", ""),
        ("kprobe", ""),
        ("kretprobe", ""),
        ("classifier", ""),
        ("action", ""),
        ("tracepoint", ""),
        ("raw_tracepoint", ""),
        ("xdp", ""),
        ("perf_event", ""),
        ("cgroup/skb", ""),
        ("cgroup/sock", ""),
        ("cgroup/dev", ""),
        ("lwt_in", ""),
        ("lwt_out", ""),
        ("lwt_xmit", ""),
        ("lwt_seg6local", ""),
        ("sockops", ""),
        ("sk_skb", ""),
        ("sk_msg", ""),
        ("lirc_mode2", ""),
        ("cgroup/bind4", ""),
        ("cgroup/bind6", ""),
        ("cgroup/post_bind4", ""),
        ("cgroup/post_bind6", ""),
        ("cgroup/connect4", ""),
        ("cgroup/connect6", ""),
        ("cgroup/connect_unix", ""),
        ("cgroup/getpeername4", ""),
        ("cgroup/getpeername6", ""),
        ("cgroup/getpeername_unix", ""),
        ("cgroup/getsockname4", ""),
        ("cgroup/getsockname6", ""),
        ("cgroup/getsockname_unix", ""),
        ("cgroup/sendmsg4", ""),
        ("cgroup/sendmsg6", ""),
        ("cgroup/sendmsg_unix", ""),
        ("cgroup/recvmsg4", ""),
        ("cgroup/recvmsg6", ""),
        ("cgroup/recvmsg_unix", ""),
        ("cgroup/sysctl", ""),
        ("cgroup/getsockopt", ""),
        ("cgroup/setsockopt", ""),
        ("cgroup/sock_release", ""),
        ("struct_ops", ""),
        ("fentry", ""),
        ("fexit", ""),
        ("freplace", ""),
        ("sk_lookup", ""),
    ];

    let attach_types = [
        ("sk_msg_verdict", ""),
        ("sk_skb_verdict", ""),
        ("sk_skb_stream_verdict", ""),
        ("sk_skb_stream_parser", ""),
        ("flow_dissector", ""),
    ];

    let metric_types = [
        ("cycles", ""),
        ("instructions", ""),
        ("l1d_loads", ""),
        ("llc_misses", ""),
        ("itlb_misses", ""),
        (
            "dtlb_misses
",
            "",
        ),
    ];

    let top_commands = [
        (
            "map",
            "tool for inspection and simple manipulation of eBPF maps",
        ),
        (
            "prog",
            "tool for inspection and simple manipulation of eBPF progs",
        ),
        (
            "link",
            "tool for inspection and simple manipulation of eBPF links",
        ),
        (
            "cgroup",
            "tool for inspection and simple manipulation of eBPF progs",
        ),
        (
            "perf",
            "tool for inspection of perf related bpf prog attachments",
        ),
        (
            "net",
            "tool for inspection of networking related bpf prog attachments",
        ),
        (
            "feature",
            "tool for inspection of eBPF-related parameters for Linux kernel or net device",
        ),
        ("btf", "tool for inspection of BTF data"),
        ("gen", "tool for BPF code-generation"),
        (
            "struct_ops",
            "tool to register/unregister/introspect BPF struct_ops",
        ),
        ("iter", "tool to create BPF iterators"),
    ];

    res += &format!(
        "set -l commands {}\n",
        top_commands.iter().map(|v| v.0).join(" ")
    );
    res += &format!(
        "set -l program_types {}\n",
        program_types.iter().map(|v| v.0).join(" ")
    );
    res += &format!(
        "set -l attach_types {}\n",
        attach_types.iter().map(|v| v.0).join(" ")
    );
    res += &format!(
        "set -l metric_types {}\n",
        metric_types.iter().map(|v| v.0).join(" ")
    );
    res += "set -l prog_spec name id tag\n";

    res += SEC!("Helper functions to stop completion if already has completed");
    res += contains_bpf_name();
    res += contains_bpf_id();
    res += contains_bpf_tag();

    res += SEC!("Complete functions by name, tag or id");
    res += complete_by_name();
    res += complete_by_id();
    res += complete_by_tag();

    // We do not want to complete files by default
    res += "\ncomplete -c bpftool -f\n";

    let top_help = [
        ('h', "help", "Print short help message"),
        (
            'V',
            "version",
            "Print version number, libbpf version, and included optional features.",
        ),
        ('j', "json", "Generate JSON output."),
        (
            'p',
            "pretty",
            "Generate human-readable JSON output. Implies -j.",
        ),
        (
            'd',
            "debug",
            "Print all available logs, even debug-level information.",
        ),
        (
            'm',
            "mapcompat",
            "Allow loading maps with unknown map definitions.",
        ),
        (
            'n',
            "nomount",
            "Do ATTACH_TYPE := {
sk_msg_verdict | sk_skb_verdict | sk_skb_stream_verdict |
sk_skb_stream_parser | flow_dissector
}not automatically attempt to mount any virtual file system when necessary.",
        ),
    ];

    res += SEC!("Top level help");
    for help in top_help {
        res += &Help {
            condition: Condition::empty(),
            help,
        }
        .to_string();
    }

    res += SEC!("Top level commands");
    for prog in top_commands {
        res += &Command {
            condition: Condition {
                peers: &[("$commands", "")],
                ..Default::default()
            },
            prog,
        }
        .to_string();
    }

    let bpf_prog_help = [
        (
            'f',
            "bpffs",
            "When showing BPF programs, show file names of pinned programs",
        ),
        ('L', "use-loader", "Load program as a 'loader' program"),
    ];

    let bpf_prog = [
        ("show", "Show information about loaded programs"),
        ("list", "Show information about loaded programs"),
        ("dump", "Dump eBPF instructions of programs"),
        ("pin", "Pin program as FILE"),
        (
            "load",
            "Load bpf program(s) from binary OBJ and pin as PATH",
        ),
        (
            "loadall",
            "Load bpf program(s) from binary OBJ and pin as PATH",
        ),
        ("attach", "Attach bpf program"),
        ("detach", "Detach bpf program"),
        ("tracelog", "Dump the trace pipe of the system to stdout"),
        (
            "run",
            "Run BPF program in the kernel testing infrastructure",
        ),
        ("profile", "Profile bpf program"),
        ("help", "Print short help message"),
    ];

    res += SEC!("bpftool-prog");
    for prog in bpf_prog {
        res += &Command {
            condition: Condition {
                parents: &["prog"],
                peers: &bpf_prog,
                ..Default::default()
            },
            prog,
        }
        .to_string();
    }

    let progs_with_prog_arg: &[(&str, bool, &[&str])] = &[
        ("pin", false, &[]),
        ("list", false, &[]),
        ("attach", true, &["$attach_types"]),
        ("detach", true, &["$attach_types"]),
        ("run", false, &["data_in"]),
        ("profile", false, &["$metrics"]),
    ];

    for (prog, allow_repetition, conflicts) in progs_with_prog_arg.iter().copied() {
        res += &format!("\n\n # bpftool {} PROG\n", prog);
        res += &Prog {
            condition: Condition {
                parents: &["prog", prog],
                conflicts,
                ..Default::default()
            },
            allow_repetition,
        }
        .to_string();
    }

    res += SEC!("bpftool-prog help");
    for help in bpf_prog_help {
        res += &Help {
            condition: Condition {
                parents: &["prog"],
                ..Default::default()
            },
            help,
        }
        .to_string();
    }

    std::fs::write("bpftool.fish", res).unwrap();
}
