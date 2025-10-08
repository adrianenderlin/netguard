// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// XDP: Allow (CIDR v4+v6, LPM) -> Deny (Single-IP v4+v6, HASH) -> PASS
// - enforce_allow==1: default-deny for addresses not present in allowlist
// - enforce_allow==0: ignore allowlist, only deny list applies

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

char _license[] SEC("license") = "Dual BSD/GPL";

/* ==================== Maps ==================== */

/* Allow IPv4: LPM trie. Key consists of prefix length followed by 4 network bytes. */
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
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pinned at /sys/fs/bpf/xdp_allow_lpm
} xdp_allow_lpm SEC(".maps");

/* Deny IPv4: Hash map. Key is a 4-byte IPv4 source address (network order). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, __u32);   // IPv4 saddr (network order)
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pinned at /sys/fs/bpf/xdp_deny_hash
} xdp_deny_hash SEC(".maps");

/* Allow IPv6: LPM trie. Key consists of prefix length followed by 16 network bytes. */
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
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pinned at /sys/fs/bpf/xdp_allow6_lpm
} xdp_allow6_lpm SEC(".maps");

/* Deny IPv6: Hash map. Key is a 16-byte IPv6 source address (network bytes). */
struct deny6_key {
    __u8 ip[16]; // IPv6 saddr (network bytes)
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1048576);
    __type(key, struct deny6_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pinned at /sys/fs/bpf/xdp_deny6_hash
} xdp_deny6_hash SEC(".maps");

/* Configuration map: holds runtime settings such as enforce_allow. */
struct xdp_cfg_t {
    __u32 enforce_allow; // 0/1
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_cfg_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pinned at /sys/fs/bpf/xdp_cfg
} xdp_cfg SEC(".maps");

/* ==================== Minimal Header structs ==================== */


/* ==================== Parser ==================== */

static __always_inline int parse_eth(void *data, void *data_end, __u16 *proto, __u64 *off)
{
    /* Validate that Ethernet header is within packet bounds */
    if (data + sizeof(struct ethhdr) > data_end) return -1;
    struct ethhdr *eth = data;

    /* Read EtherType and initialize offset to the Ethernet header size */
    *proto = bpf_ntohs(eth->h_proto);
    *off   = sizeof(*eth);

    /*
     * Unroll up to two VLAN headers (Q-in-Q). If a VLAN tag is present,
     * update the EtherType and advance the offset accordingly.
     */
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

/* Check whether the IPv4 source address is contained in the allow LPM trie.
 * The LPM key requires the prefix length followed by the IPv4 address bytes
 * in network (big-endian) byte order. */
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

/* Check whether the IPv4 source address is present in the deny hash map. */
static __always_inline bool in_deny_v4(__be32 saddr)
{
    return bpf_map_lookup_elem(&xdp_deny_hash, &saddr) != NULL;
}

/* Check whether the IPv6 source address is contained in the allow LPM trie. */
static __always_inline bool in_allow_v6(const __u8 *saddr)
{
    struct lpm_key_v6 k = { .prefixlen = 128 };
    __builtin_memcpy(k.data, saddr, 16);
    return bpf_map_lookup_elem(&xdp_allow6_lpm, &k) != NULL;
}

/* Check whether the IPv6 source address is present in the deny hash map. */
static __always_inline bool in_deny_v6(const __u8 *saddr)
{
    struct deny6_key k;
    __builtin_memcpy(k.ip, saddr, 16);
    return bpf_map_lookup_elem(&xdp_deny6_hash, &k) != NULL;
}

/* ==================== XDP program ==================== */

SEC("xdp")
int xdp_allow_then_deny(struct xdp_md *ctx)
{
    /* Pointers to packet data and end for bounds checking */
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 proto;
    __u64 off;
    /* Parse Ethernet (and optional VLANs). If parsing fails, pass packet. */
    if (parse_eth(data, data_end, &proto, &off) < 0)
        return XDP_PASS;

    /* Load configuration from pinned map; default to enforce_allow=0 if missing. */
    __u32 idx = 0;
    struct xdp_cfg_t *cfg = bpf_map_lookup_elem(&xdp_cfg, &idx);
    __u32 enforce = cfg ? cfg->enforce_allow : 0;

    if (proto == 0x0800) { /* IPv4 */
        /* Validate that IPv4 header is within bounds and that version/IHL are sane. */
        if (data + off + sizeof(struct iphdr) > data_end) return XDP_PASS;
        struct iphdr *iph = data + off;
        if (iph->version != 4) return XDP_PASS;
        if (data + off + iph->ihl * 4 > data_end) return XDP_PASS;

        __be32 saddr = iph->saddr;

        /* If enforce_allow is set, drop unless the source is in the allowlist. */
        if (enforce && !in_allow_v4(saddr))
            return XDP_DROP;
        /* If the source is on the denylist, drop. */
        if (in_deny_v4(saddr))
            return XDP_DROP;

        return XDP_PASS;
    } else if (proto == 0x86DD) { /* IPv6 */
        /* Validate IPv6 header is within bounds and version is 6. */
        if (data + off + sizeof(struct ipv6hdr) > data_end) return XDP_PASS;
        struct ipv6hdr *ip6 = data + off;
        if (ip6->version != 6) return XDP_PASS;

        __u8 saddr[16];
        __builtin_memcpy(saddr, &ip6->saddr, 16);

        /* If enforce_allow is set, drop unless the source is in the allowlist. */
        if (enforce && !in_allow_v6(saddr))
            return XDP_DROP;
        /* If the source is on the denylist, drop. */
        if (in_deny_v6(saddr))
            return XDP_DROP;

        return XDP_PASS;
    }

    /* For other EtherTypes, allow the packet to pass. */
    return XDP_PASS;
}

