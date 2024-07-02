use crate::codegen::Codegen;
use itertools::Itertools;

mod codegen;
mod constants;

mod tree;

use tree::{Args, Command};

macro_rules! sec {
    ($section:expr) => {
        concat!(sec!(), "# ", $section, "\n")
    };
    () => {
        "\n\n"
    };
}

fn main() {
    let mut res = String::new();

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

    #[rustfmt::skip]
    let bpftree = Command {
        name: "bpftool",
        include_in_codegen: false,
        description: "Show BPF object hierarchy",
        flags: vec![
            ('h', "help", "Print short help message"),
            ('V', "version", "Print version number, libbpf version, and included optional features.",),
            ('j', "json", "Generate JSON output."),
            ('p', "pretty", "Generate human-readable JSON output. Implies -j.",),
            ('d', "debug", "Print all available logs, even debug-level information.",),
            ('m', "mapcompat", "Allow loading maps with unknown map definitions.",),
            ('n', "nomount", "Do not automatically attempt to mount any virtual file system when necessary.",),
        ].into(),
        children: vec![
            Command::rcd("map", "Inspect and manipulate eBPF maps")
            .with_children(&[
                Command::rcd("show", "Show information about loaded maps"),
                Command::rcd("list", "Show information about loaded maps"),
                Command::rcd("create", "Create a new map with given parameters"),
                Command::rcd("dump", "Dump all entries in a given map"),
                Command::rcd("update", "Update map entry for a given key"),
                Command::rcd("lookup", "Lookup key in the map"),
                Command::rcd("getnext", "Get next key in the map"),
                Command::rcd("delete", "Remove entry from the map"),
                Command::rcd("pin", "Pin map to a file"),
                Command::rcd("event_pipe", "Read events from a perf event array map"),
                Command::rcd("peek", "Peek next value in the queue or stack"),
                Command::rcd("push", "Push value onto the stack"),
                Command::rcd("pop", "Pop and print value from the stack"),
                Command::rcd("enqueue", "Enqueue value into the queue"),
                Command::rcd("dequeue", "Dequeue and print value from the queue"),
                Command::rcd("freeze", "Freeze the map as read-only from user space"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("prog", "Inspect and manipulate eBPF progs")
            .with_children(&[
                Command::rcd("show", "Show information about loaded programs")
                    .with_args(&[ Args::Prog, ]),
                Command::rcd("list", "Show information about loaded programs")
                    .with_args(&[ Args::Prog, ]),
                Command::rcd("dump", "Dump eBPF instructions/image of programs")
                .with_children(&[
                    Command::rcd("xlated", "Dump eBPF instructions of the programs from the kernel")
                    .with_args(&[ 
                        Args::Prog, 
                        Args::Repeatable(Box::new(Args::OneOf(vec![
                            Args::DLit("opcodes", "Display raw codes"),
                            Args::DLit("file", "Dump eBPF instructions of the programs from the kernel"),
                            Args::DLit("linum", "Display filename, line number and column"),
                            Args::DLit("visual", "Display eBPF instructions with CFG in DOT format")
                        ]))),
                        Args::Path
                    ]),
                    Command::rcd("jited", "Dump jited image (host machine code) of the program")
                    .with_args(&[ 
                        Args::Prog, 
                        Args::Repeatable(Box::new(Args::OneOf(vec![
                            Args::DLit("opcodes", "Display raw codes"),
                            Args::DLit("file", "Dump eBPF instructions of the programs from the kernel"),
                            Args::DLit("linum", "Display filename, line number and column"),
                            Args::DLit("visual", "Display eBPF instructions with CFG in DOT format")
                        ]))),
                        Args::Path
                    ]),
                ]),
                Command::rcd("pin", "Pin program as a FILE")
                .with_args(&[ 
                    Args::Prog,
                    Args::PathBpffs
                ]),
                Command::rcd("load", " Pins only the first program from the OBJ as PATH.Note: PATH must be located in bpffs mount. It must not contain a dot character ('.'), which is reserved for future extensions of bpffs.")
                .with_args(&[ 
                    Args::PathO 
                ]),
                Command::rcd("loadall", "Pins all programs from the OBJ under PATH directory.Note: PATH must be located in bpffs mount. It must not contain a dot character ('.'), which is reserved for future extensions of bpffs."),
                Command::rcd("attach", "Attach bpf program PROG (with type specified by ATTACH_TYPE).")
                .with_args(&[
                    Args::OneOf(
                        constants::ATTACH_TYPES.map(|(a, d)| Args::DLit(a, d)).to_vec()
                    ),
                    Args::Map
                ]),
                Command::rcd("detach", "Detach bpf program")
                .with_args(&[
                    Args::OneOf(
                        constants::ATTACH_TYPES.map(|(a, d)| Args::DLit(a, d)).to_vec()
                    ),
                    Args::Map
                ]),
                Command::rcd("tracelog", "Dump the trace pipe of the system to stdout"),
                Command::rcd("run", "Run BPF program in the kernel testing infrastructure")
                .with_args(&[
                   Args::Prog,
                   Args::Lit("data_in"),
                   Args::Path,
                ]),
                Command::rcd("profile", "Profile bpf program")
                .with_args(&[
                    Args::Prog,
                    Args::OneOf(constants::METRIC_TYPES.map(|(a, d)| Args::DLit(a, d)).to_vec())
                ]),
                Command::rcd("help", "Print short help message")
            ])
            .with_flags(&[
                ('f', "bpffs", "When showing BPF programs, show file names of pinned programs",),
                ('L', "use-loader", "Load program as a 'loader' program",),
            ]),
            Command::rcd("link", "Inspect and manipulate eBPF links")
            .with_children(&[
                Command::rcd("show", "Show information about active links"),
                Command::rcd("list", "Show information about active links"),
                Command::rcd("pin", "Pin link to a file in bpffs"),
                Command::rcd("detach", "Force-detach a link"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("cgroup", "Inspect and manipulate eBPF progs in cgroups")
            .with_children(&[
                Command::rcd("show", "List all programs attached to a specific cgroup"),
                Command::rcd("list", "List all programs attached to a specific cgroup"),
                Command::rcd("tree", "List attached programs for all cgroups in a hierarchy"),
                Command::rcd("attach", "Attach a program to a cgroup"),
                Command::rcd("detach", "Detach a program from a cgroup"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("perf", "Inspect perf-related BPF program attachments")
            .with_children(&[
                Command::rcd("show", "List all raw_tracepoint, tracepoint, and kprobe attachments"),
                Command::rcd("list", "List all raw_tracepoint, tracepoint, and kprobe attachments"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("net", "Inspect networking-related BPF program attachments")
            .with_children(&[
                Command::rcd("show", "List BPF program attachments in the kernel networking subsystem"),
                Command::rcd("list", "List BPF program attachments in the kernel networking subsystem"),
                Command::rcd("attach", "Attach a BPF program to a network interface"),
                Command::rcd("detach", "Detach a BPF program from a network interface"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("feature", "Inspect eBPF-related parameters for Linux kernel or net device")
            .with_children(&[
                Command::rcd("probe", "Probe and dump eBPF-related parameters"),
                Command::rcd("list_builtins", "List items known to bpftool from compilation time"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("btf", "Inspect BTF (BPF Type Format) data")
            .with_children(&[
                Command::rcd("show", "Show information about loaded BTF objects"),
                Command::rcd("list", "List all BTF objects currently loaded on the system"),
                Command::rcd("dump", "Dump BTF entries from a given source"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("gen", "BPF code-generation tool")
            .with_children(&[
                Command::rcd("object", "Statically link BPF ELF object files"),
                Command::rcd("skeleton", "Generate BPF skeleton C header file"),
                Command::rcd("subskeleton", "Generate BPF subskeleton C header file"),
                Command::rcd("min_core_btf", "Generate minimum BTF file for CO-RE relocations"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("struct_ops", "Register/unregister/introspect BPF struct_ops")
            .with_children(&[
                Command::rcd("show", "Show brief information about struct_ops in the system"),
                Command::rcd("list", "List all struct_ops currently existing in the system"),
                Command::rcd("dump", "Dump detailed information about struct_ops in the system"),
                Command::rcd("register", "Register BPF struct_ops from an object file"),
                Command::rcd("unregister", "Unregister a struct_ops from the kernel subsystem"),
                Command::rcd("help", "Print short help message"),
            ]),
            Command::rcd("iter", "Create BPF iterators")
            .with_children(&[
                Command::rcd("pin", "Create a BPF iterator from an object file and pin it to a path"),
                Command::rcd("help", "Print short help message"),
            ]),
        ].into(),
        ..Default::default()
    }.to_rc();
    bpftree.set_children_parents();
    bpftree.setup_args();

    res += &bpftree.generate();

    std::fs::write("bpftool.fish", res).unwrap();
}
