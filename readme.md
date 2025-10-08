# 🛡️ NetGuard — eBPF-based Network Guard (XDP + TC)

**NetGuard** is a Go-based CLI tool that manages eBPF-powered firewall and rate-limiting mechanisms on Linux.  
It combines two eBPF programs:

- **XDP:** ultra-fast packet filtering (IPv4 + IPv6) using allow/deny lists  
- **TC:** per-IP ingress rate limiting with token-bucket logic

---

## 🚀 Features

✅ **XDP Layer (L2) — High-Speed Filtering**
- Dual-stack support (IPv4 + IPv6)
- Allowlist (CIDR via LPM-Trie)
- Denylist (single IPs via hash)
- Enforce mode ("default deny outside allowlist")

✅ **TC Layer (L3) — Rate Limiting**
- Token-bucket algorithm (`rate` + `burst`)
- Per-IP override policies (IPv4 + IPv6)
- VLAN/QinQ-aware parser
- Works with `tc clsact` ingress hook

✅ **Dynamic CLI**
- Attach/detach programs easily
- Modify maps live (no reload required)
- Integrated debugging and stats via `bpftool`

---

## 🧩 Requirements

- Linux Kernel **≥ 5.10** with eBPF, XDP, and TC support  
- `clang`, `llvm`, `libbpf`, `bpftool`
- Go ≥ 1.21  
- Root privileges (`CAP_SYS_ADMIN`)
- BPF and debug filesystems mounted:
  ```bash
  sudo mount -t bpf bpffs /sys/fs/bpf
  sudo mount -t debugfs none /sys/kernel/debug

🧠 Note (WSL2 users): You must manually mount bpffs inside WSL:
sudo mkdir -p /sys/fs/bpf && sudo mount -t bpf bpffs /sys/fs/bpf


# Build & Run
```bash
# 1) Build eBPF objects
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c xdp_allow_deny.bpf.c -o xdp_allow_deny.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c tc_rl.bpf.c -o tc_rl.bpf.o

# 2) Build the CLI
go build -o net-guard main.go

# 3) Mount BPF FS (if not already)
sudo mount -t bpf bpffs /sys/fs/bpf

# 4) Attach the programs
sudo ./net-guard attach-xdp -iface eth0
sudo ./net-guard attach-tc -iface eth0

```


# XDP - Allow/Deny Filtering
```bash
# Manage allow/deny lists (IPv4 + IPv6)
sudo ./net-guard add-allow-cidr 192.168.0.0/24
sudo ./net-guard add-allow-cidr 2a02:120::/48
sudo ./net-guard add-deny-ip 203.0.113.7
sudo ./net-guard list-allow
sudo ./net-guard list-deny

# Enable default-deny mode
sudo ./net-guard enforce-allow on

```

# TC - per IP rate limiting
```bash
# Attach TC ingress program
sudo ./net-guard attach-tc -iface eth0

# Default global limit
sudo ./net-guard tc-set -rate 2000 -burst 10000

# Per-IP override
sudo ./net-guard tc-set-ip -rate 1 -burst 5 192.168.2.37
sudo ./net-guard tc-unset-ip 192.168.2.37

```
Rate Limiting Parameters
rate	Tokens regenerated per second (avg packets/sec)
burst	Maximum number of packets allowed instantly (bucket size)

Example:
-rate 10 -burst 100 → allows bursts of 100 packets, then refills 10 per second.


# Debugging & Monitoring
```bash
# Show loaded programs and maps
sudo bpftool prog show
sudo bpftool map show

# Inspect debug counters
sudo bpftool map lookup pinned /sys/fs/bpf/tc_rl_dbg key hex 00 00 00 00
```

# Cleanup
```bash
sudo tc filter del dev eth0 ingress
sudo rm -f /sys/fs/bpf/tc_rl_prog /sys/fs/bpf/xdp_* /sys/fs/bpf/tc_rl_*

```


# License
Dual BSD/GPL
Author: Adrian Enderlin
Built with libbpf and Cilium eBPF

