// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// tc ingress: per-source token-bucket rate limiter (packets-per-second),
// supports dual-stack (IPv4 + IPv6).
// - Global default configuration map: tc_rl_cfg
// - Optional per-IP policies: tc_rl_policy4 / tc_rl_policy6 (override defaults)
// - VLAN / QinQ aware Ethernet parser

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK   0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#define NSEC_PER_SEC 1000000000ULL

struct cfg_t {
    __u64 rate_pps;   // tokens added per second (packets/sec)
    __u64 burst;      // maximum token bucket size
};

struct state_t {
    __u64 last_ns;
    __u64 tokens;
};

/* ===================== Telemtry ===================== */

struct tc_src_stats_t {
    __u64 pkts;
    __u64 bytes;
    __u64 pass;
    __u64 drop;        // rate-limit drop
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, __u32); // IPv4 saddr (network order)
    __type(value, struct tc_src_stats_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // /sys/fs/bpf/tc_rl_src4_stats
} tc_rl_src4_stats SEC(".maps");

/* ===================== Maps ===================== */

// Debug counters (pinned at /sys/fs/bpf/tc_rl_dbg)
struct dbg_counters {
    __u64 seen_v4;
    __u64 seen_v6;
    __u64 drop_v4;
    __u64 drop_v6;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dbg_counters);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_rl_dbg SEC(".maps");


/* Global default configuration (pinned at /sys/fs/bpf/tc_rl_cfg) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cfg_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_rl_cfg SEC(".maps");

/* IPv4 state (LRU hash), pinned at /sys/fs/bpf/tc_rl_state
 * Key is a __u32 containing the IPv4 source address in network order.
 * Endianness is not critical here because both lookup and update occur in
 * the BPF program itself. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u32);
    __type(value, struct state_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_rl_state SEC(".maps");

/* IPv6 state (LRU hash), pinned at /sys/fs/bpf/tc_rl6_state */
struct key6_t {
    __u8 ip[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct key6_t);
    __type(value, struct state_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_rl6_state SEC(".maps");

/* IPv4 policy map key as 4 bytes in network order (matches userspace [4]byte) */
struct key4_t {
    __u8 ip[4];
};

/* Per-IP policy map for IPv4 (pinned at /sys/fs/bpf/tc_rl_policy4) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct key4_t);   // <-- Byte-Array statt __u32 (Endian-sicher)
    __type(value, struct cfg_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_rl_policy4 SEC(".maps");

/* Per-IP policy map for IPv6 (pinned at /sys/fs/bpf/tc_rl_policy6) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 262144);
    __type(key, struct key6_t);
    __type(value, struct cfg_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tc_rl_policy6 SEC(".maps");

/* ===================== Parser ===================== */


static __always_inline int parse_eth(void *data, void *data_end, __u16 *proto, __u64 *off)
{
    /* Validate Ethernet header is within packet bounds */
    if (data + sizeof(struct ethhdr) > data_end) return -1;
    struct ethhdr *eth = data;

    /* Read EtherType and set initial offset to Ethernet header length */
    *proto = bpf_ntohs(eth->h_proto);
    *off   = sizeof(*eth);

    /*
     * Handle up to two VLAN headers (Q-in-Q). If a VLAN tag is present,
     * update the encapsulated EtherType and advance the offset.
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

/* ===================== Token-Bucket Helpers ===================== */

static __always_inline int tb_update(struct state_t *st, const struct cfg_t *cfg, __u64 now)
{
    /* If no config or disabled (rate/burst == 0), treat as unlimited. */
    if (!cfg || cfg->rate_pps == 0 || cfg->burst == 0)
        return 0; // no limit active

    /* If there is no state entry yet, caller will create an initial entry
     * and the first packet should be allowed. */
    if (!st) return 1;

    /* Refill tokens based on elapsed nanoseconds and configured rate. */
    __u64 delta = now - st->last_ns;
    __u64 add   = (delta * cfg->rate_pps) / NSEC_PER_SEC;

    __u64 tokens = st->tokens + add;
    if (tokens > cfg->burst) tokens = cfg->burst;

    /* If no tokens available, update timestamps and indicate DROP. */
    if (tokens == 0) {
        st->last_ns = now;
        st->tokens  = 0;
        return -1; // DROP
    }

    /* Consume one token and allow the packet. */
    st->last_ns = now;
    st->tokens  = tokens - 1;
    return 1; // PASS
}

/* ===================== Program ===================== */

SEC("tc")
int tc_rl_prog(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *end  = (void *)(long)skb->data_end;

    __u16 proto;
    __u64 off;
    if (parse_eth(data, end, &proto, &off) < 0)
        return TC_ACT_OK;

    __u32 idx = 0;
    struct cfg_t *cfg_def = bpf_map_lookup_elem(&tc_rl_cfg, &idx);
    /* IMPORTANT: do not early-return here. We want per-IP policies to be
     * able to allow traffic even when the global default is disabled (0). */

    __u64 now = bpf_ktime_get_ns();

    if (proto == 0x0800) {
        /* IPv4 */
        if (data + off + sizeof(struct iphdr) > end) return TC_ACT_OK;
        struct iphdr *iph = data + off;
        if (iph->version != 4) return TC_ACT_OK;
        if (data + off + iph->ihl * 4 > end) return TC_ACT_OK;

    /* Debug: increment seen_v4 if debug map is available (optional). */
        __u32 dkey = 0;
        struct dbg_counters *dc = bpf_map_lookup_elem(&tc_rl_dbg, &dkey);
        if (dc) dc->seen_v4++;

    /* Build policy key as 4 bytes in network order (copy bytes from iph->saddr). */
        struct key4_t k4 = {};
        __builtin_memcpy(k4.ip, &iph->saddr, 4);

    /* Select which configuration to use (global default, possibly overridden by per-IP). */
        const struct cfg_t *use = NULL;
        if (cfg_def && cfg_def->rate_pps && cfg_def->burst)
            use = cfg_def;

        struct cfg_t *pc4 = bpf_map_lookup_elem(&tc_rl_policy4, &k4);
        if (pc4 && pc4->rate_pps && pc4->burst)
            use = pc4; /* per-IP überschreibt */

        if (!use)
            return TC_ACT_OK; /* neither default nor per-IP policy active */

        /* State-Map (weiter __u32-Key) */
        __u32 saddr_u32 = iph->saddr;
        struct state_t *st = bpf_map_lookup_elem(&tc_rl_state, &saddr_u32);
        if (!st) {
            /* Initialize per-source state with full bucket and current timestamp. */
            struct state_t init = { .last_ns = now, .tokens = use->burst };
            bpf_map_update_elem(&tc_rl_state, &saddr_u32, &init, BPF_ANY);
            return TC_ACT_OK;
        }

        int r = tb_update(st, use, now);
        if (r < 0) {
            if (dc) dc->drop_v4++;
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;

    } else if (proto == 0x86DD) {
        /* IPv6 */
        if (data + off + sizeof(struct ipv6hdr) > end) return TC_ACT_OK;
        struct ipv6hdr *ip6 = data + off;
        if (ip6->version != 6) return TC_ACT_OK;

    __u32 dkey = 0;
    struct dbg_counters *dc = bpf_map_lookup_elem(&tc_rl_dbg, &dkey);
    if (dc) dc->seen_v6++;

        struct key6_t k6 = {};
        __builtin_memcpy(k6.ip, &ip6->saddr, 16);

        const struct cfg_t *use = NULL;
        if (cfg_def && cfg_def->rate_pps && cfg_def->burst)
            use = cfg_def;

        struct cfg_t *pc6 = bpf_map_lookup_elem(&tc_rl_policy6, &k6);
        if (pc6 && pc6->rate_pps && pc6->burst)
            use = pc6;

        if (!use)
            return TC_ACT_OK;

        struct state_t *st6 = bpf_map_lookup_elem(&tc_rl6_state, &k6);
        if (!st6) {
            /* Initialize per-source IPv6 state with full bucket. */
            struct state_t init = { .last_ns = now, .tokens = use->burst };
            bpf_map_update_elem(&tc_rl6_state, &k6, &init, BPF_ANY);
            return TC_ACT_OK;
        }

        int r = tb_update(st6, use, now);
        if (r < 0) {
            if (dc) dc->drop_v6++;
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";

