#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int contador = 0;

SEC("xdp")
int xdp_test(void *ctx) {
  bpf_printk("Holaaaa %d", contador);
  contador++;
  
  return XDP_PASS;  //XDP_DROP;  Para tirarlos
}

char LICENSE[] SEC("license") = "GPL";
