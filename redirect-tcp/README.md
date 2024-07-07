# Redirect TCP

![Flow of a network packet][image-1]

This `BPF` program serves as a middleman who redirects all traffic from the specified (MAC, IP, Port) to another machine to handle the packet. If any response is received from the machine that handled the packet, it gets redirected to the original hard-coded (MAC, IP, Port).

This readme contains some notes and learning I had during the process.

## Notes on TCP

Re-computing the TCP checksum is not feasible since we need access to the payload of the message, and it’s difficult to communicate the boundaries to the verifier. The only way to ensure we have a correct checksum seems to be via calls to `bpf_csum_diff` and `csum_fold_helper`.

Alas, as mentioned in the [aya-rs][1] discord, computing the checksum from scratch is expensive and depends on the size of the packet.

### `bpf_csum_diff`

The [`bpf_csum_diff`][2] function according to the docs:

> Compute a checksum difference, from the raw buffer pointed by `from`, of length `from_size` (that must be a multiple of 4), towards the raw buffer pointed by to, of size `to_size` (same remark). An optional seed can be added to the value (this can be cascaded, the seed may come from a previous call to the helper).

Since I updated the IP source and address, we chain the checksum differences for both changes:

```rs
let mut csum = csum_diff(
    orig_ip_destination,
    ip4.destination_u32(),
    !(tcp.csum() as u32),
);
csum = csum_diff(orig_ip_source, ip4.source_u32(), csum as u32);
```

Note, the starting seed is the checksum the TCP header had originally.

### `csum_fold_helper`

The `csum_fold_helper` transforms the 64-bit result of the `bpf_csum_diff ` function by one-complementing summing the four 16-bit words:
- It takes a 64-bit checksum value as input.
- It repeatedly folds any bits above the lower 16 bits back into the lower 16 bits.
- This folding process is done up to 4 times to ensure all higher bits are incorporated.
- Finally, it takes the bitwise, NOT of the result.

Hence, we call the function on the final result of the `bpf_csum_diff` chains to store the final value on the TCP checksum field:

```rust
tcp.set_csum(csum_fold_helper(csum));
```

## Notes on Parsing

It would be great to have an alternative to `etherparse` with similar experience but with the ability to parse over a `&mut [u8]` and to modify fields with safe interfaces.

Edit: Created a small crate to solve the issue.

## Running

### Prerequisites

1. Install the `bpf-linker`: `cargo install bpf-linker`

### Build eBPF

```bash
cargo xtask build-ebpf --release
```

To perform a release build, you can use the `--release` flag.
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

[1]:	https://discord.com/channels/855676609003651072/855676609003651075/1234801079493857280 "Tuetuopay's message"
[2]:	https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_csum_diff/ "bpf_csum_diff"

[image-1]:	https://i.imghippo.com/files/aGvTC1720118103.png
