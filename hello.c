#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800

unsigned char lookup_protocol(struct xdp_md *ctx) {
  unsigned char protocol = 0;
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;

  if (data + sizeof(struct ethhdr) > data_end)
    return 0; // Check that it's an IP packet
  if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
    // Return the protocol of this packet
    // 1 = ICMP
    // 6 = TCP
    // 17 = UDP
    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) {
      protocol = iph->protocol;
    }
  }
  return protocol;
}

int counters = 0;

SEC("xdp") int ping(struct xdp_md *ctx) {
  // long protocol = lookup_protocol(ctx);
  // if (protocol == 1) {
  //   bpf_printk("Hello ping %d", counters++);
  //   return XDP_DROP;
  // }

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  if (data + 1 > data_end) {
    return XDP_PASS;
  }

  bpf_printk("First byte: %d", ((u8*)data)[0]);


  return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
