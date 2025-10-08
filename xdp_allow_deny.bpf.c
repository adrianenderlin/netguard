// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// XDP: Allow (CIDR v4+v6, LPM) → Deny (Single-IP v4+v6, HASH) → PASS
// - enforce_allow==1: Default-Deny außerhalb Allowlist
// - enforce_allow==0: Allowlist ignorieren, nur Deny greift

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* ==================== Maps ==================== */

/* Allow v4: LPM (key = prefixlen + 4 bytes) */
struct lpm_key_v4 {
    __u32 prefixlen;
    __u8  data[4]; // network bytes
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/xdp_allow_lpm
} xdp_allow_lpm SEC(".maps");

/* Deny v4: Hash (key = 4 bytes) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, __u32);   // IPv4 saddr (network order)
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/xdp_deny_hash
} xdp_deny_hash SEC(".maps");

/* Allow v6: LPM (key = prefixlen + 16 bytes) */
struct lpm_key_v6 {
    __u32 prefixlen;
    __u8  data[16]; // network bytes
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key_v6);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/xdp_allow6_lpm
} xdp_allow6_lpm SEC(".maps");

/* Deny v6: Hash (key = 16 bytes) */
struct deny6_key {
    __u8 ip[16]; // IPv6 saddr (network bytes)
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct deny6_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/xdp_deny6_hash
} xdp_deny6_hash SEC(".maps");

/* Config: enforce_allow */
struct xdp_cfg_t {
    __u32 enforce_allow; // 0/1
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_cfg_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/xdp_cfg
} xdp_cfg SEC(".maps");

/* ==================== Minimal Header structs ==================== */


/* ==================== Parser ==================== */

static __always_inline int parse_eth(void *data, void *data_end, __u16 *proto, __u64 *off)
{
    if (data + sizeof(struct ethhdr) > data_end) return -1;
    struct ethhdr *eth = data;
    *proto = bpf_ntohs(eth->h_proto);
    *off   = sizeof(*eth);

    #pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        if (*proto == 0x8100 /* 802.1Q */ || *proto == 0x88a8 /* 802.1ad */) {
            if (data + *off + sizeof(struct vlan_hdr) > data_end) return -1;
            struct vlan_hdr *vh = data + *off;
            *proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
            *off  += sizeof(*vh);
        }
    }
    return 0;
}

/* ==================== Lookups ==================== */

static __always_inline bool in_allow_v4(__be32 saddr)
{
    struct lpm_key_v4 k = {
        .prefixlen = 32,
        .data = {
            (__u8)(saddr >> 24),
            (__u8)(saddr >> 16),
            (__u8)(saddr >> 8),
            (__u8)(saddr),
        },
    };
    return bpf_map_lookup_elem(&xdp_allow_lpm, &k) != NULL;
}

static __always_inline bool in_deny_v4(__be32 saddr)
{
    return bpf_map_lookup_elem(&xdp_deny_hash, &saddr) != NULL;
}

static __always_inline bool in_allow_v6(const __u8 *saddr)
{
    struct lpm_key_v6 k = { .prefixlen = 128 };
    __builtin_memcpy(k.data, saddr, 16);
    return bpf_map_lookup_elem(&xdp_allow6_lpm, &k) != NULL;
}

static __always_inline bool in_deny_v6(const __u8 *saddr)
{
    struct deny6_key k;
    __builtin_memcpy(k.ip, saddr, 16);
    return bpf_map_lookup_elem(&xdp_deny6_hash, &k) != NULL;
}

/* ==================== XDP prog ==================== */

SEC("xdp")
int xdp_allow_then_deny(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 proto;
    __u64 off;
    if (parse_eth(data, data_end, &proto, &off) < 0)
        return XDP_PASS;

    __u32 idx = 0;
    struct xdp_cfg_t *cfg = bpf_map_lookup_elem(&xdp_cfg, &idx);
    __u32 enforce = cfg ? cfg->enforce_allow : 0;

    if (proto == 0x0800) { // IPv4
        if (data + off + sizeof(struct iphdr) > data_end) return XDP_PASS;
        struct iphdr *iph = data + off;
        if (iph->version != 4) return XDP_PASS;
        if (data + off + iph->ihl * 4 > data_end) return XDP_PASS;

        __be32 saddr = iph->saddr;

        if (enforce && !in_allow_v4(saddr))
            return XDP_DROP;
        if (in_deny_v4(saddr))
            return XDP_DROP;

        return XDP_PASS;
    } else if (proto == 0x86DD) { // IPv6
        if (data + off + sizeof(struct ipv6hdr) > data_end) return XDP_PASS;
        struct ipv6hdr *ip6 = data + off;
        if (ip6->version != 6) return XDP_PASS;

        __u8 saddr[16];
        __builtin_memcpy(saddr, &ip6->saddr, 16);

        if (enforce && !in_allow_v6(saddr))
            return XDP_DROP;
        if (in_deny_v6(saddr))
            return XDP_DROP;

        return XDP_PASS;
    }

    return XDP_PASS; // andere EtherTypes ignorieren
}

