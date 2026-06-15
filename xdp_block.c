#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* BPF hash map used to store blocked IPv4 source addresses. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);    // IPv4 source address.
    __type(value, __u64);   // Dropped packet counter.
} blacklist SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

  // Parse the Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

   // Process only IPv4 packets.
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

   // Parse the IPv4 header.
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __be32 src_ip = iph->saddr;

   // Check whether the source IP is present in the blacklist map.
    __u64 *pkt_count = bpf_map_lookup_elem(&blacklist, &src_ip);

    if (pkt_count) {
      // Atomically update the dropped packet counter.
        __sync_fetch_and_add(pkt_count, 1);
        
      // Drop the packet at the XDP layer.
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
