# ADI Agent FSM (Heuristic Anomaly Detection + Progressive Enforcement)

This README documents `adi-agent-fsm`, a userspace agent that reads eBPF telemetry (XDP/TC) and applies **progressive enforcement** per source IP:

1. **OBSERVE** (no action)  
2. **RATE_LIMIT_SOFT** (TC token-bucket policy)  
3. **RATE_LIMIT_HARD** (TC token-bucket policy)  
4. **BLOCK** (XDP deny map)

It is designed for practical production use (floods, scans, noisy sources) without ML, and with NAT-safety in mind (rate-limit first, block later).

---

## 1) Architecture

### 1.1 Data plane (kernel)

**Telemetry map (per source IP)**
- Path: `/sys/fs/bpf/xdp_src4_stats`
- Key: IPv4 source (4 bytes)
- Value: monotonic counters (`pkts`, `bytes`, `syn`, `dport_changes`, …)
- Type: LRU hash (bounded)

**Enforcement maps**
- XDP deny list: `/sys/fs/bpf/xdp_deny_hash`
  - If IP exists → packets dropped at XDP (fast path).
- TC per-IP policy: `/sys/fs/bpf/tc_rl_policy4`
  - If IP exists → ingress packets token-bucket rate-limited.

**Order matters**
- XDP runs **before** TC. If you block in XDP, TC does not see that traffic.

### 1.2 Control plane (userspace: `adi-agent-fsm`)

Every `-interval` (e.g., 1s), the agent:
1. Iterates `/sys/fs/bpf/xdp_src4_stats`
2. Computes **deltas** vs previous snapshot
3. Converts deltas to **rates** (pps, syn/s, scan/s, Bps)
4. Computes **Severity** (weighted score)
5. Updates **Strikes**
6. Applies **FSM transitions** (cooldown + TTL + escalation)
7. Writes/cleans enforcement maps (TC policies, XDP deny)

---

## 2) Metrics (how they are computed)

All counters in the BPF map are **monotonic** (only increase).  
The agent computes per-IP deltas over time:

Let `sec = now - prev_time`.

### 2.1 PPS (packets per second)

```
delta_pkts = curr.pkts - prev.pkts
pps = delta_pkts / sec
```

### 2.2 Bps (bytes per second)

```
delta_bytes = curr.bytes - prev.bytes
Bps = delta_bytes / sec
```

### 2.3 SYN rate (syn/s)

```
delta_syn = curr.syn - prev.syn
syn/s = delta_syn / sec
```

> Note: On **ingress-only** sensors, SYNACK ratios are not reliable unless you also instrument egress.

### 2.4 Scan rate (scan/s) via `dport_changes`

Your XDP code increments `dport_changes` when a source changes destination ports (TCP/UDP).

```
delta_scan = curr.dport_changes - prev.dport_changes
scan/s = delta_scan / sec
```

This is a cheap “scan-ish” signal; it’s not proof of scanning, but very useful.

---

## 3) Severity (Weighting)

Severity is a **weighted, normalized score** computed per tick per IP.

### 3.1 Normalization

Each metric is normalized by its trigger threshold:

```
n_pps  = min(pps   / trig_pps,  sev_cap)
n_syn  = min(syn/s / trig_syn,  sev_cap)
n_scan = min(scan/s/ trig_scan, sev_cap)
```

### 3.2 Weighted severity

```
severity = w_pps*n_pps + w_syn*n_syn + w_scan*n_scan
```

Recommended defaults (public controller, NAT-friendly):
- `w_pps = 0.50`
- `w_syn = 0.30`
- `w_scan = 0.20`
- `sev_cap = 3.0`

---

## 4) Strikes (how signals “pay into strikes”)

**Strikes** are a short-term suspicion memory.  
They rise when severity is high, and decay when the IP is quiet.

### 4.1 Severity → strike deltas (configurable)

The agent maps severity into strike deltas using 3 steps:

- if `severity >= sev-step3` → add `sev-delta3`
- else if `severity >= sev-step2` → add `sev-delta2`
- else if `severity >= sev-step1` → add `sev-delta1`
- else → add `0`

Defaults:
- `sev-step1=1.0` with `sev-delta1=1`
- `sev-step2=2.0` with `sev-delta2=2`
- `sev-step3=3.0` with `sev-delta3=3`

### 4.2 Decay

If `severity < sev-decay-below` and `strikes > 0`, then:

- `strikes -= 1` per tick.

Default:
- `sev-decay-below = 0.25`

---

## 5) FSM (levels, TTL, cooldown)

### 5.1 Levels

1. **OBSERVE**  
   - No enforcement entries.

2. **RATE_SOFT**  
   - Writes a TC per-IP policy with `soft-rate/soft-burst`.

3. **RATE_HARD**  
   - Writes a TC per-IP policy with `hard-rate/hard-burst`.

4. **BLOCK**  
   - Writes an XDP deny entry (removes TC policy, since XDP dominates).

### 5.2 Escalation thresholds (strikes)

- `strikes >= soft-at`  → SOFT
- `strikes >= hard-at`  → HARD
- `strikes >= block-at` → BLOCK (subject to block gating)

### 5.3 Cooldown (anti-flapping)

After any level change:
- `CooldownUntil = now + cooldown`

While in cooldown, the agent does not change levels again for that IP.

Typical:
- testing: 2–5s
- production: 10–60s

### 5.4 TTL (time-to-live per level)

Each enforcement level has a TTL:
- `soft-ttl`, `hard-ttl`, `block-ttl`

When TTL expires, the agent steps down one level:
- BLOCK → HARD → SOFT → OBSERVE

**Important:** TTL cleanup runs for **all state entries**, even if the IP is not in the current top-N candidates.

---

## 6) Block gating (NAT-friendly “only block if sustained”)

Blocking a public source IP may impact multiple users behind NAT.  
To reduce collateral damage, `adi-agent-fsm` can require sustained high severity.

Flags:
- `-block-min-sev` (default `2.5`)
- `-block-min-dur` (default `10s`)

Rule:
- An IP may enter **BLOCK** only if:
  - `strikes >= block-at`, **and**
  - `severity >= block-min-sev` continuously for at least `block-min-dur`.

Disable gating:
- set `-block-min-sev 0` or `-block-min-dur 0`

---

## 7) Candidate selection and sorting

The agent:
1. Builds candidates from telemetry deltas
2. Computes severity per candidate
3. Sorts candidates by **Severity desc** (tie-breaker: PPS)
4. Evaluates only `-top N` candidates per tick

Filters:
- `-min-pps` filters low PPS sources
- `-min-sev` allows scan-only / syn-only offenders through even if PPS is low

---

## 8) Flags Reference

### 8.1 Timing and performance
- `-interval 1s`  
- `-top 50`  
- `-min-pps 10`  
- `-min-sev 0.0`

### 8.2 Severity normalization
- `-trig-pps 2000`
- `-trig-syn 500`
- `-trig-scan 200`
- `-w-pps 0.50`
- `-w-syn 0.30`
- `-w-scan 0.20`
- `-sev-cap 3.0`

### 8.3 Severity → strikes
- `-sev-step1 1.0 -sev-delta1 1`
- `-sev-step2 2.0 -sev-delta2 2`
- `-sev-step3 3.0 -sev-delta3 3`
- `-sev-decay-below 0.25`

### 8.4 Escalation thresholds
- `-soft-at 2`
- `-hard-at 5`
- `-block-at 9`

### 8.5 Enforcement parameters
- `-soft-rate 2000 -soft-burst 4000 -soft-ttl 2m`
- `-hard-rate 300  -hard-burst 600  -hard-ttl 10m`
- `-block-ttl 30m`
- `-cooldown 10s`
- `-dry-run true|false`

### 8.6 Housekeeping
- `-prev-ttl 10m`
- `-state-ttl 60m`

### 8.7 Block gating
- `-block-min-sev 2.5`
- `-block-min-dur 10s`

---

## 9) Example Runs

### 9.1 Public node (NAT-friendly baseline)

```bash
sudo ./adi-agent-fsm -interval 1s -dry-run=false \
  -top 200 -min-pps 50 -min-sev 1.0 \
  -trig-pps 3000 -trig-syn 800 -trig-scan 300 \
  -w-pps 0.50 -w-syn 0.30 -w-scan 0.20 -sev-cap 3.0 \
  -soft-at 2 -hard-at 5 -block-at 12 \
  -soft-rate 1500 -soft-burst 5000 -soft-ttl 60s \
  -hard-rate 300  -hard-burst 1200 -hard-ttl 10m \
  -block-ttl 10m \
  -block-min-sev 2.5 -block-min-dur 15s \
  -cooldown 10s
```

### 9.2 Lab testing (aggressive)

```bash
sudo ./adi-agent-fsm -interval 1s -dry-run=false \
  -top 500 -min-pps 0 -min-sev 0.0 \
  -trig-pps 200 -trig-syn 50 -trig-scan 30 \
  -soft-at 1 -hard-at 3 -block-at 6 \
  -soft-rate 200 -soft-burst 400 -soft-ttl 10s \
  -hard-rate 50  -hard-burst 100 -hard-ttl 20s \
  -block-ttl 30s \
  -block-min-sev 0 -block-min-dur 0 \
  -cooldown 2s
```

---

## 10) Troubleshooting

### 10.1 “I see 0 PPS / no candidates”

- Ensure XDP is attached to the correct interface.
- Verify the telemetry map is populated:
  ```bash
  bpftool map dump pinned /sys/fs/bpf/xdp_src4_stats | head
  ```

### 10.2 “Block TTL doesn’t remove deny entry”

- TTL cleanup must process **all state entries**, not only “active” top-N candidates.
- This agent includes a full-state TTL cleanup loop.
- Check deny map:
  ```bash
  bpftool map dump pinned /sys/fs/bpf/xdp_deny_hash | head
  ```

### 10.3 “Agent stopped but blocks remain”

Because TTL removal is done in userspace, a stopped agent will not expire blocks.
Manual cleanup:
```bash
sudo ./net-guard del-deny-ip <ip>
sudo ./net-guard tc-unset-ip <ip>
```

---

## 11) Glossary

- **XDP**: fast packet processing hook early in the network stack
- **TC**: Traffic Control (ingress filters + token bucket)
- **PPS**: packets per second
- **SYN/s**: TCP SYN packets per second
- **scan/s**: destination port-change heuristic per second
- **Severity**: weighted, normalized suspicion score
- **Strikes**: short-term suspicion accumulator used for escalation
- **TTL**: time-to-live for an enforcement level
- **Cooldown**: minimum time between level changes per IP
