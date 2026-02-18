// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// XDP: Allow (CIDR v4+v6, LPM) -> Deny (Single-IP v4+v6, HASH) -> PASS
// - enforce_allow==1: default-deny for addresses not present in allowlist
// - enforce_allow==0: ignore allowlist, only deny list applies

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

/* ===== Telemetry: totals (per-cpu) ===== */
struct xdp_totals_t {
    __u64 pkts;
    __u64 bytes;

    __u64 pass;
    __u64 drop_allow;   // enforce_allow drop
    __u64 drop_deny;    // denylist drop

    __u64 v4;
    __u64 v6;

    __u64 tcp;
    __u64 udp;
    __u64 icmp;

    __u64 syn;
    __u64 synack;
    __u64 rst;

    __u64 dport_changes; // simple scan heuristic
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_totals_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/xdp_totals
} xdp_totals SEC(".maps");

/* ===== Telemetry: per-source (bounded) ===== */
struct xdp_src_stats_v4_t {
    __u64 pkts;
    __u64 bytes;

    __u64 tcp;
    __u64 udp;
    __u64 icmp;

    __u64 syn;
    __u64 synack;
    __u64 rst;

    __u64 drop_allow;
    __u64 drop_deny;

    __u64 last_seen_ns;

    __u16 last_dport;      // network order ok; just compare
    __u64 dport_changes;   // “scan-ish” signal
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);          // MVP: 131k sources
    __type(key, __u32);                   // IPv4 saddr (network order)
    __type(value, struct xdp_src_stats_v4_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // /sys/fs/bpf/xdp_src4_stats
} xdp_src4_stats SEC(".maps");

struct xdp_src_stats_v6_t {
    __u64 pkts;
    __u64 bytes;
    __u64 tcp;
    __u64 udp;
    __u64 icmp;
    __u64 syn;
    __u64 synack;
    __u64 rst;
    __u64 drop_allow;
    __u64 drop_deny;
    __u64 last_seen_ns;
    __u16 last_dport;
    __u64 dport_changes;
    __u64 last_seen_ns2;
};

struct src6_key { __u8 ip[16]; };

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct src6_key);
    __type(value, struct xdp_src_stats_v6_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);  // /sys/fs/bpf/xdp_src6_stats
} xdp_src6_stats SEC(".maps");

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

/* ==================== Helpers ==================== */

static __always_inline struct xdp_totals_t *totals_get(void) {
    __u32 k = 0;
    return bpf_map_lookup_elem(&xdp_totals, &k);
}

static __always_inline void totals_add_basic(struct xdp_totals_t *t, __u64 len) {
    if (!t) return;
    t->pkts++;
    t->bytes += len;
}

static __always_inline int src4_update_basic(__be32 saddr, __u64 len, __u64 now,
                                              bool is_tcp, bool is_udp, bool is_icmp,
                                              bool syn, bool synack, bool rst,
                                              __u16 dport,
                                              bool drop_allow, bool drop_deny)
{
    int changed = 0;

    struct xdp_src_stats_v4_t *st = bpf_map_lookup_elem(&xdp_src4_stats, &saddr);
    if (!st) {
        struct xdp_src_stats_v4_t init = {};
        init.pkts = 1;
        init.bytes = len;
        init.tcp = is_tcp ? 1 : 0;
        init.udp = is_udp ? 1 : 0;
        init.icmp = is_icmp ? 1 : 0;
        init.syn = syn ? 1 : 0;
        init.synack = synack ? 1 : 0;
        init.rst = rst ? 1 : 0;
        init.drop_allow = drop_allow ? 1 : 0;
        init.drop_deny  = drop_deny  ? 1 : 0;
        init.last_seen_ns = now;
        init.last_dport = dport;
        // dport_changes starts at 0
        bpf_map_update_elem(&xdp_src4_stats, &saddr, &init, BPF_ANY);
        return 0;
    }

    st->pkts++;
    st->bytes += len;
    if (is_tcp) st->tcp++;
    if (is_udp) st->udp++;
    if (is_icmp) st->icmp++;
    if (syn) st->syn++;
    if (synack) st->synack++;
    if (rst) st->rst++;
    if (drop_allow) st->drop_allow++;
    if (drop_deny)  st->drop_deny++;
    st->last_seen_ns = now;

    if (dport && st->last_dport != dport) {
        st->dport_changes++;
        st->last_dport = dport;
        changed = 1;
    }

    return changed;
}

static __always_inline int src6_update_basic(const __u8 *saddr16, __u64 len, __u64 now,
                                             bool is_tcp, bool is_udp, bool is_icmp,
                                             bool syn, bool synack, bool rst,
                                             __u16 dport,
                                             bool drop_allow, bool drop_deny)
{
    int changed = 0;

    struct src6_key k = {};
    __builtin_memcpy(k.ip, saddr16, 16);

    struct xdp_src_stats_v6_t *st = bpf_map_lookup_elem(&xdp_src6_stats, &k);
    if (!st) {
        struct xdp_src_stats_v6_t init = {};
        init.pkts = 1;
        init.bytes = len;
        init.tcp = is_tcp ? 1 : 0;
        init.udp = is_udp ? 1 : 0;
        init.icmp = is_icmp ? 1 : 0;
        init.syn = syn ? 1 : 0;
        init.synack = synack ? 1 : 0;
        init.rst = rst ? 1 : 0;
        init.drop_allow = drop_allow ? 1 : 0;
        init.drop_deny  = drop_deny  ? 1 : 0;
        init.last_seen_ns = now;
        init.last_dport = dport;
        bpf_map_update_elem(&xdp_src6_stats, &k, &init, BPF_ANY);
        return 0;
    }

    st->pkts++;
    st->bytes += len;
    if (is_tcp) st->tcp++;
    if (is_udp) st->udp++;
    if (is_icmp) st->icmp++;
    if (syn) st->syn++;
    if (synack) st->synack++;
    if (rst) st->rst++;
    if (drop_allow) st->drop_allow++;
    if (drop_deny)  st->drop_deny++;
    st->last_seen_ns = now;

    if (dport && st->last_dport != dport) {
        st->dport_changes++;
        st->last_dport = dport;
        changed = 1;
    }
    return changed;
}

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
    struct lpm_key_v4 k = { .prefixlen = 32 };
    __builtin_memcpy(k.data, &saddr, 4);   // bytes exakt wie im Packet
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
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 pkt_len = (__u64)((long)data_end - (long)data);
    __u64 now = bpf_ktime_get_ns();

    struct xdp_totals_t *t = totals_get();
    totals_add_basic(t, pkt_len);

    __u16 proto;
    __u64 off;
    if (parse_eth(data, data_end, &proto, &off) < 0) {
        if (t) t->pass++;
        return XDP_PASS;
    }

    __u32 idx = 0;
    struct xdp_cfg_t *cfg = bpf_map_lookup_elem(&xdp_cfg, &idx);
    __u32 enforce = cfg ? cfg->enforce_allow : 0;

    if (proto == 0x0800) { /* IPv4 */
        if (data + off + sizeof(struct iphdr) > data_end) {
            if (t) t->pass++;
            return XDP_PASS;
        }
        struct iphdr *iph = data + off;
        if (iph->version != 4) { if (t) t->pass++; return XDP_PASS; }
        if (data + off + iph->ihl * 4 > data_end) { if (t) t->pass++; return XDP_PASS; }

        if (t) t->v4++;

        __be32 saddr = iph->saddr;

        bool is_tcp=false, is_udp=false, is_icmp=false;
        bool syn=false, synack=false, rst=false;
        __u16 dport = 0;

        __u64 l4off = off + (__u64)iph->ihl * 4;

        if (iph->protocol == IPPROTO_TCP) {
            is_tcp = true;
            if (t) t->tcp++;
            if (data + l4off + sizeof(struct tcphdr) <= data_end) {
                struct tcphdr *th = data + l4off;
                dport = th->dest; // network order
                syn = th->syn;
                rst = th->rst;
                synack = th->syn && th->ack;
                if (t && syn) t->syn++;
                if (t && synack) t->synack++;
                if (t && rst) t->rst++;
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            is_udp = true;
            if (t) t->udp++;
            if (data + l4off + sizeof(struct udphdr) <= data_end) {
                struct udphdr *uh = data + l4off;
                dport = uh->dest;
            }
        } else if (iph->protocol == IPPROTO_ICMP) {
            is_icmp = true;
            if (t) t->icmp++;
        }

        bool drop_allow = false;
        bool drop_deny  = false;

        if (enforce && !in_allow_v4(saddr)) drop_allow = true;
        else if (in_deny_v4(saddr))         drop_deny  = true;

        int action = (drop_allow || drop_deny) ? XDP_DROP : XDP_PASS;

        if (t) {
            if (action == XDP_PASS) t->pass++;
            else if (drop_allow) t->drop_allow++;
            else t->drop_deny++;
        }

        int changed = src4_update_basic(saddr, pkt_len, now,
                                        is_tcp, is_udp, is_icmp,
                                        syn, synack, rst,
                                        dport,
                                        drop_allow, drop_deny);
        if (changed && t) t->dport_changes++;

        return action;
    }

    else if (proto == 0x86DD) { /* IPv6 */
        if (data + off + sizeof(struct ipv6hdr) > data_end) {
            if (t) t->pass++;
            return XDP_PASS;
        }
        struct ipv6hdr *ip6 = data + off;
        if (ip6->version != 6) { if (t) t->pass++; return XDP_PASS; }

        if (t) t->v6++;

        __u8 saddr6[16];
        __builtin_memcpy(saddr6, &ip6->saddr, 16);

        /* MVP: L4 parse only if no ext headers (best effort) */
        bool is_tcp=false, is_udp=false, is_icmp=false;
        bool syn=false, synack=false, rst=false;
        __u16 dport = 0;

        __u64 l4off = off + sizeof(struct ipv6hdr);
        __u8 nh = ip6->nexthdr;

        if (nh == IPPROTO_TCP) {
            is_tcp = true;
            if (t) t->tcp++;
            if (data + l4off + sizeof(struct tcphdr) <= data_end) {
                struct tcphdr *th = data + l4off;
                dport = th->dest;
                syn = th->syn;
                rst = th->rst;
                synack = th->syn && th->ack;
                if (t && syn) t->syn++;
                if (t && synack) t->synack++;
                if (t && rst) t->rst++;
            }
        } else if (nh == IPPROTO_UDP) {
            is_udp = true;
            if (t) t->udp++;
            if (data + l4off + sizeof(struct udphdr) <= data_end) {
                struct udphdr *uh = data + l4off;
                dport = uh->dest;
            }
        } else if (nh == IPPROTO_ICMPV6) {
            is_icmp = true;
            if (t) t->icmp++;
        }

        bool drop_allow = false;
        bool drop_deny  = false;

        if (enforce && !in_allow_v6(saddr6)) drop_allow = true;
        else if (in_deny_v6(saddr6))         drop_deny  = true;

        int action = (drop_allow || drop_deny) ? XDP_DROP : XDP_PASS;

        if (t) {
            if (action == XDP_PASS) t->pass++;
            else if (drop_allow) t->drop_allow++;
            else t->drop_deny++;
        }

        /* Optional: if you enabled src6 stats */
        // int changed = src6_update_basic(saddr6, pkt_len, now,
        //                                 is_tcp, is_udp, is_icmp,
        //                                 syn, synack, rst,
        //                                 dport,
        //                                 drop_allow, drop_deny);
        // if (changed && t) t->dport_changes++;

        return action;
    }

    if (t) t->pass++;
    return XDP_PASS;
}

