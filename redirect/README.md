# Redirect

![Flow of a network packet][image-1]

This `BPF` program serves as a middleman who redirects all traffic from the specified (MAC, IP, Port) to another machine to handle the packet. If any response is received from the machine that handled the packet, it gets redirected to the original hard-coded (MAC, IP, Port).

This readme contains some notes and learning I had during the process.

## Notes on UDP

- UDP has a fixed-length header, which makes its parsing simple. 
- If the bits for the `u16` checksum are zeroed, we can get away with sending the package without making its computation.

## Notes on TCP

## Notes on Parsing

It would be great to have an alternative to `etherparse` with similar experience but with the ability to parse over a `&mut [u8]` and to modify fields with safe interfaces.

## Running

### Prerequisites

1. Install the `bpf-linker`: `cargo install bpf-linker`

### Build eBPF

```bash
cargo xtask build-ebpf --release
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build --release
```

### Build eBPF and Userspace

```bash
cargo xtask build --release
```

### Run

```bash
RUST_LOG=info cargo xtask run --release
```

[image-1]:	https://i.imghippo.com/files/aGvTC1720118103.png