use std::fmt::Display;

use itertools::Itertools;

mod condition;
mod constants;

use condition::{Condition, Position};

macro_rules! sec {
    ($section:expr) => {
        concat!(sec!(), "# ", $section, "\n")
    };
    () => {
        "\n\n"
    };
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

#[derive(Default)]
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
        writeln!(f, "{} -F", self.condition)
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
                    token_position: self.condition.token_position + 1,
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

    res += &format!(
        "set -l commands {}\n",
        constants::TOP_COMMANDS.iter().map(|v| v.0).join(" ")
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

    res += sec!("Complete functions by name, tag or id");
    res += constants::PROG_FUNCT;

    // We do not want to complete files by default
    res += "\ncomplete -c bpftool -f\n";

    res += sec!("Top level help");
    for help in constants::TOP_HELP {
        res += &Help {
            condition: Condition::empty(),
            help,
        }
        .to_string();
    }

    res += sec!("Top level commands");
    for prog in constants::TOP_COMMANDS.iter().rev().copied() {
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
        ("dump", "Dump eBPF instructions/image of programs"),
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

    res += sec!("bpftool-prog help");
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

    res += sec!("bpftool-prog");
    for prog in bpf_prog.iter().rev().copied() {
        res += &Command {
            condition: Condition {
                parents: &["prog"],
                peers: &bpf_prog,
                token_position: Position::Eq(1),
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
                token_position: Position::Eq(2),
                ..Default::default()
            },
            position: 1,
            ..Default::default()
        }
        .to_string();
    }

    res += sec!("bpftool prog pin PROG FILE");
    res += &File {
        condition: Condition {
            parents: &["prog", "pin"],
            token_position: Position::Eq(4),
            ..Default::default()
        },
    }
    .to_string();

    res += sec!("bpftool prog dump { xlated | jitted } [{file FILE | [opcodes] [linum] }]");
    let prog_dump_kinds = [
        (
            "xlated",
            "Dump eBPF instructions of the programs from the kernel",
        ),
        (
            "jited",
            "Dump jited image (host machine code) of the program",
        ),
    ];

    let prog_dump_keywords = ["file", "opcodes", "linum"];

    for prog in prog_dump_kinds {
        res += &Command {
            prog,
            condition: Condition {
                parents: &["prog", "dump"],
                token_position: Position::Eq(2),
                ..Default::default()
            },
        }
        .to_string();

        res += &Prog {
            condition: Condition {
                parents: &["prog", "dump", prog.0],
                token_position: Position::Eq(3),
                ..Default::default()
            },
            position: 1,
            ..Default::default()
        }
        .to_string();

        for keyword in prog_dump_keywords {
            res += &Command {
                prog: (keyword, ""),
                condition: Condition {
                    parents: &["prog", "dump", prog.0],
                    token_position: Position::Gt(4),
                    ..Default::default()
                },
            }
            .to_string();
        }
    }

    res += &Command {
        prog: ("visual", ""),
        condition: Condition {
            parents: &["prog", "dump", "xlated"],
            token_position: Position::Gt(4),
            ..Default::default()
        },
    }
    .to_string();

    std::fs::write("bpftool.fish", res).unwrap();
}
