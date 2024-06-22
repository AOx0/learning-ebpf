gen-vmlinux:
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

compile-bpf: gen-vmlinux
    clang -O2 -g -target bpf \
        -I /usr/include/y$(uname -m)-linux-gnu \
        -c hello.bpf.c \
        -D __TARGET_ARCH_x86 \
        -o hello.bpf.o
    llvm-strip -g hello.bpf.o

setcap:
    sudo setcap 'cap_perfmon,cap_bpf+ep' hello

compile-usr: gen-bpftool && setcap
    clang -O2 hello.c -o hello -lbpf

gen-bpftool:
    bpftool gen skeleton hello.bpf.o > hello.skel.h
