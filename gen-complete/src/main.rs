use std::cell::RefCell;
use std::fmt::Display;

use itertools::Itertools;
use crate::codegen::Codegen;

mod codegen;
mod constants;

mod tree;

use tree::Command;

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

    let bpftree = Command {
        name: "bpftool",
        include_in_codegen: false,
        description: "Show BPF object hierarchy",
        help: vec![
            ('h', "help", "Print short help message"),
            ('V', "version", "Print version number, libbpf version, and included optional features.",),
            ('j', "json", "Generate JSON output."),
            ('p', "pretty", "Generate human-readable JSON output. Implies -j.",),
            ('d', "debug", "Print all available logs, even debug-level information.",),
            ('m', "mapcompat", "Allow loading maps with unknown map definitions.",),
            ('n', "nomount", "Do not automatically attempt to mount any virtual file system when necessary.",),
        ].into(),
        children: vec![
            Command::rcd("map", "Inspect and manipulate eBPF maps", vec![
                Command::rcd("show", "Show information about loaded maps", vec![]),
                Command::rcd("list", "Show information about loaded maps", vec![]),
                Command::rcd("create", "Create a new map with given parameters", vec![]),
                Command::rcd("dump", "Dump all entries in a given map", vec![]),
                Command::rcd("update", "Update map entry for a given key", vec![]),
                Command::rcd("lookup", "Lookup key in the map", vec![]),
                Command::rcd("getnext", "Get next key in the map", vec![]),
                Command::rcd("delete", "Remove entry from the map", vec![]),
                Command::rcd("pin", "Pin map to a file", vec![]),
                Command::rcd("event_pipe", "Read events from a perf event array map", vec![]),
                Command::rcd("peek", "Peek next value in the queue or stack", vec![]),
                Command::rcd("push", "Push value onto the stack", vec![]),
                Command::rcd("pop", "Pop and print value from the stack", vec![]),
                Command::rcd("enqueue", "Enqueue value into the queue", vec![]),
                Command::rcd("dequeue", "Dequeue and print value from the queue", vec![]),
                Command::rcd("freeze", "Freeze the map as read-only from user space", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("prog", "Inspect and manipulate eBPF progs", vec![
                Command::rcd("show", "Show information about loaded programs", vec![]),
                Command::rcd("list", "Show information about loaded programs", vec![]),
                Command::rcd("dump", "Dump eBPF instructions/image of programs", vec![
                    Command::rcd("xlated", "Dump eBPF instructions of the programs from the kernel", vec![])
                    .with_help(&[
                        ('a', "Aaaaa", "Mas a")
                    ]),
                    Command::rcd("jited", "Dump jited image (host machine code) of the program", vec![]),
                ]),
                Command::rcd("pin", "Pin program as FILE", vec![]),
                Command::rcd("load", "Load bpf program(s) from binary OBJ and pin as PATH", vec![]),
                Command::rcd("loadall", "Load bpf program(s) from binary OBJ and pin as PATH", vec![]),
                Command::rcd("attach", "Attach bpf program", vec![]),
                Command::rcd("detach", "Detach bpf program", vec![]),
                Command::rcd("tracelog", "Dump the trace pipe of the system to stdout", vec![]),
                Command::rcd("run", "Run BPF program in the kernel testing infrastructure", vec![]),
                Command::rcd("profile", "Profile bpf program", vec![]),
                Command::rcd("help", "Print short help message", vec![])
            ])
            .with_help(&[
                ('f', "bpffs", "When showing BPF programs, show file names of pinned programs",),
                ('L', "use-loader", "Load program as a 'loader' program",),
            ]),
            Command::rcd("link", "Inspect and manipulate eBPF links", vec![
                Command::rcd("show", "Show information about active links", vec![]),
                Command::rcd("list", "Show information about active links", vec![]),
                Command::rcd("pin", "Pin link to a file in bpffs", vec![]),
                Command::rcd("detach", "Force-detach a link", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("cgroup", "Inspect and manipulate eBPF progs in cgroups", vec![
                Command::rcd("show", "List all programs attached to a specific cgroup", vec![]),
                Command::rcd("list", "List all programs attached to a specific cgroup", vec![]),
                Command::rcd("tree", "List attached programs for all cgroups in a hierarchy", vec![]),
                Command::rcd("attach", "Attach a program to a cgroup", vec![]),
                Command::rcd("detach", "Detach a program from a cgroup", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("perf", "Inspect perf-related BPF program attachments", vec![
                Command::rcd("show", "List all raw_tracepoint, tracepoint, and kprobe attachments", vec![]),
                Command::rcd("list", "List all raw_tracepoint, tracepoint, and kprobe attachments", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("net", "Inspect networking-related BPF program attachments", vec![
                Command::rcd("show", "List BPF program attachments in the kernel networking subsystem", vec![]),
                Command::rcd("list", "List BPF program attachments in the kernel networking subsystem", vec![]),
                Command::rcd("attach", "Attach a BPF program to a network interface", vec![]),
                Command::rcd("detach", "Detach a BPF program from a network interface", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("feature", "Inspect eBPF-related parameters for Linux kernel or net device", vec![
                Command::rcd("probe", "Probe and dump eBPF-related parameters", vec![]),
                Command::rcd("list_builtins", "List items known to bpftool from compilation time", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("btf", "Inspect BTF (BPF Type Format) data", vec![
                Command::rcd("show", "Show information about loaded BTF objects", vec![]),
                Command::rcd("list", "List all BTF objects currently loaded on the system", vec![]),
                Command::rcd("dump", "Dump BTF entries from a given source", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("gen", "BPF code-generation tool", vec![
                Command::rcd("object", "Statically link BPF ELF object files", vec![]),
                Command::rcd("skeleton", "Generate BPF skeleton C header file", vec![]),
                Command::rcd("subskeleton", "Generate BPF subskeleton C header file", vec![]),
                Command::rcd("min_core_btf", "Generate minimum BTF file for CO-RE relocations", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("struct_ops", "Register/unregister/introspect BPF struct_ops", vec![
                Command::rcd("show", "Show brief information about struct_ops in the system", vec![]),
                Command::rcd("list", "List all struct_ops currently existing in the system", vec![]),
                Command::rcd("dump", "Dump detailed information about struct_ops in the system", vec![]),
                Command::rcd("register", "Register BPF struct_ops from an object file", vec![]),
                Command::rcd("unregister", "Unregister a struct_ops from the kernel subsystem", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
            Command::rcd("iter", "Create BPF iterators", vec![
                Command::rcd("pin", "Create a BPF iterator from an object file and pin it to a path", vec![]),
                Command::rcd("help", "Print short help message", vec![]),
            ]),
        ],
        ..Default::default()
    }.to_rc();
    bpftree.set_children_parents();

    res += &bpftree.generate();

    std::fs::write("bpftool.fish", res).unwrap();
}
