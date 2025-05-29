#include "vmlinux_local.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp/xdp_helpers.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/errno.h>

#define MAX_RULES 10
#define __u128 __uint128_t

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif


struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct ipv4_lpm_map {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u8);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, MAX_RULES);
                //__uint(pinning, LIBBPF_PIN_BY_NAME);
} ipv4_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 100);
    __type(key, __u32);
    __array(values, struct ipv4_lpm_map);
} outer_hash SEC(".maps") = {
    .values = {(void*)&ipv4_lpm_map},
};


SEC("xdp")
int xdp_fw_kern_multi_map(struct xdp_md *ctx)
{
        struct ethhdr *ether = NULL;
        struct iphdr *ipv4 = NULL;
        struct ipv4_lpm_key key4 = { .data=0, .prefixlen=0};
        __u8 value = 1;
        void *lpm_map;
        int ret;

        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        ether = data;

        if (data + sizeof(*ether) > data_end) {
                return XDP_ABORTED;
        }

        switch (bpf_ntohs(ether->h_proto)) {
                case ETH_P_IP:
                        ipv4 = (void *)ether + sizeof(*ether);
                        if (ipv4 + 1 > data_end)
                                return XDP_DROP;

                        __u32 outer_key = 0;
                        __builtin_memcpy(&outer_key, ether->h_source + 2, 4);
                        lpm_map = bpf_map_lookup_elem(&outer_hash, &outer_key);

                        if (lpm_map) {
                                key4.prefixlen = 32;
                                memcpy(&key4.data, &ipv4->saddr, 4);
                                if (bpf_map_lookup_elem(lpm_map, &key4)) {
                                        ret = XDP_PASS;
                                        break;
                                }
                        }

                        ret = XDP_DROP;
                        break;
                case ETH_P_IPV6:
                        ret = XDP_DROP;
                        break;
                default:
                        ret = XDP_PASS;
                        break;
        }

        return ret;
}
