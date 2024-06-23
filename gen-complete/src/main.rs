use std::{fmt::Display, ops::Not};

use itertools::Itertools;

mod constants;

macro_rules! SEC {
    ($section:expr) => {
        concat!(SEC!(), "# ", $section, "\n")
    };
    () => {
        "\n\n"
    };
}

fn complete_prog_funs() -> &'static str {
    r#"
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
"#
}

#[derive(Default)]
struct Condition<'a> {
    pub parents: &'a [&'a str],
    pub peers: &'a [(&'a str, &'a str)],
    pub requires_peers: bool,
    pub conflicts: &'a [&'a str],
    pub extras: &'a [&'a str],
    pub token_position: Option<usize>,
}

impl Condition<'_> {
    fn empty() -> Self {
        Self::default()
    }
}

impl<'a> Display for Condition<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.parents.is_empty()
            && self.peers.is_empty()
            && self.conflicts.is_empty()
            && self.extras.is_empty()
            && self.token_position.is_none()
        {
            write!(f, r#"complete -c bpftool"#)
        } else {
            write!(f, r#"complete -c bpftool -n ""#)?;

            for (i, parent) in self.parents.iter().enumerate() {
                write!(f, r#"__fish_seen_subcommand_from {parent}"#)?;
                if i < self.parents.len() - 1 {
                    write!(f, "; and ")?;
                }
            }

            if self.peers.is_empty().not() {
                write!(
                    f,
                    r#"{chain}{seen} __fish_seen_subcommand_from {commands}"#,
                    chain = if self.parents.is_empty().not() {
                        "; and "
                    } else {
                        ""
                    },
                    seen = if self.requires_peers { "" } else { "not" },
                    commands = self.peers.iter().map(|a| a.0).join(" "),
                )?;
            }

            if self.conflicts.is_empty().not() {
                write!(
                    f,
                    "{chain}not __fish_seen_subcommand_from {commands}",
                    chain = if self.parents.is_empty().not() || self.peers.is_empty().not() {
                        "; and "
                    } else {
                        ""
                    },
                    commands = self.conflicts.join(" ")
                )?
            }

            if self.extras.is_empty().not() {
                write!(
                    f,
                    "{chain}{extras}",
                    chain = if self.parents.is_empty().not()
                        || self.peers.is_empty().not()
                        || self.conflicts.is_empty().not()
                    {
                        "; and "
                    } else {
                        ""
                    },
                    extras = self.extras.join("; and ")
                )?
            }

            if let Some(pos) = self.token_position {
                write!(
                    f,
                    "{chain}test (__fish_bpftool_count_commands) -eq {pos}",
                    chain = if self.parents.is_empty().not()
                        || self.peers.is_empty().not()
                        || self.conflicts.is_empty().not()
                        || self.extras.is_empty().not()
                    {
                        "; and "
                    } else {
                        ""
                    },
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
        writeln!(f, r#" -ka {} -d "{}""#, self.prog.0, self.prog.1)?;

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
struct File<'a> {
    pub condition: Condition<'a>,
}

impl<'a> Display for File<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} -f", self.condition)
    }
}

#[derive(Default)]
struct Prog<'a> {
    pub condition: Condition<'a>,
    pub allow_repetition: bool,
    pub position: usize,
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
                    token_position: self.condition.token_position.map(|a| a + 1),
                    extras: &[
                        "__fish_bpftool_prog_profile_needs_completion",
                        &format!(
                            "test (__fish_bpftool_count_keyword {selector}) -eq {position}",
                            selector = selector,
                            position = self.position
                        )
                    ],
                    ..self.condition
                }
            )?;
            writeln!(
                f,
                " -ka '(__fish_bpftool_complete_progs_{selector})'",
                selector = selector
            )?;
        }

        Ok(())
    }
}

fn main() {
    let mut res = String::new();

    let top_commands = [
        ("map", "Inspect and manipulate eBPF maps"),
        ("prog", "Inspect and manipulate eBPF progs"),
        ("link", "Inspect and manipulate eBPF links"),
        ("cgroup", "Inspect and manipulate eBPF progs"),
        ("perf", "Inspect perf related bpf prog attachments"),
        ("net", "Inspect networking related bpf prog attachments"),
        (
            "feature",
            "Inspect eBPF-related parameters for Linux kernel or net device",
        ),
        ("btf", "Inspect BTF data"),
        ("gen", "BPF code-generation"),
        (
            "struct_ops",
            "Register/unregister/introspect BPF struct_ops",
        ),
        ("iter", "Create BPF iterators"),
    ];

    res += &format!(
        "set -l commands {}\n",
        top_commands.iter().map(|v| v.0).join(" ")
    );
    res += &format!(
        "set -l program_types {}\n",
        constants::PROGRAM_TYPES.iter().map(|v| v.0).join(" ")
    );
    res += &format!(
        "set -l attach_types {}\n",
        constants::ATTACH_TYPES.iter().map(|v| v.0).join(" ")
    );
    res += &format!(
        "set -l metric_types {}\n",
        constants::METRIC_TYPES.iter().map(|v| v.0).join(" ")
    );
    res += "set -l prog_spec name id tag\n";

    res += SEC!("Complete functions by name, tag or id");
    res += complete_prog_funs();

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
            "Do not automatically attempt to mount any virtual file system when necessary.",
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
    for prog in top_commands.iter().rev().copied() {
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
    for prog in bpf_prog.iter().rev().copied() {
        res += &Command {
            condition: Condition {
                parents: &["prog"],
                peers: &bpf_prog,
                token_position: Some(1),
                ..Default::default()
            },
            prog,
        }
        .to_string();
    }

    let progs_starting_with_prog: &[&str] =
        &["pin", "list", "show", "attach", "detach", "run", "profile"];

    for prog in progs_starting_with_prog.iter().copied() {
        res += &format!("\n\n # bpftool {} PROG\n", prog);
        res += &Prog {
            condition: Condition {
                parents: &["prog", prog],
                token_position: Some(2),
                ..Default::default()
            },
            position: 1,
            ..Default::default()
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
