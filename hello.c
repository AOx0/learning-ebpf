#include "linux/bpf.h"
#include "bpf/bpf_helpers.h"

int counters =0;

SEC("xdp")
int hello(){
  bpf_printk("Hola mundo %d", counters++);
  return XDP_PASS;
}

char LICENSE[] SEC("license")="GPL";

