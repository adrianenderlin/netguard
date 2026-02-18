package main

// net-guard: CLI to manage pinned eBPF programs and maps.
//
// Features:
// - XDP allow/deny: CIDR-based allow LPM (v4/v6) and per-IP deny hashes.
// - TC per-source token-bucket: per-IP policies with LRU state maps.
//
// The CLI loads eBPF object files, pins programs/maps under /sys/fs/bpf
// (or expects them pinned), and provides commands to modify the maps from
// userspace so the eBPF programs can act on updated data immediately.

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	// eBPF object files
	objXDP = "xdp_allow_deny.bpf.o" // expects prog: xdp_allow_then_deny
	objTC  = "tc_rl.bpf.o"          // expects SEC("tc")

	// Pinned map paths (MUST match the BPF C map names)
	// IPv4
	mapPinAllow4LPM = "/sys/fs/bpf/xdp_allow_lpm"
	mapPinDeny4Hash = "/sys/fs/bpf/xdp_deny_hash"
	// IPv6
	mapPinAllow6LPM = "/sys/fs/bpf/xdp_allow6_lpm"
	mapPinDeny6Hash = "/sys/fs/bpf/xdp_deny6_hash"

	// Config (shared)
	mapPinXDPCfg = "/sys/fs/bpf/xdp_cfg"

	// tc rate-limiter 
	mapPinTCCfg   = "/sys/fs/bpf/tc_rl_cfg"
	mapPinTCState = "/sys/fs/bpf/tc_rl_state"
	mapPinTCPolicy4 = "/sys/fs/bpf/tc_rl_policy4"
        mapPinTCPolicy6 = "/sys/fs/bpf/tc_rl_policy6"

	mapPinXDPTotals = "/sys/fs/bpf/xdp_totals"
    mapPinXDPSrc4   = "/sys/fs/bpf/xdp_src4_stats"
    mapPinXDPSrc6   = "/sys/fs/bpf/xdp_src6_stats" // optional
)

type xdpTotals struct {
  Pkts, Bytes uint64

  Pass, DropAllow, DropDeny uint64

  V4, V6 uint64

  Tcp, Udp, Icmp uint64

  Syn, Synack, Rst uint64

  DportChanges uint64
}

type xdpSrcStatsV4 struct {
  Pkts, Bytes uint64
  Tcp, Udp, Icmp uint64
  Syn, Synack, Rst uint64
  DropAllow, DropDeny uint64
  LastSeenNs uint64
  LastDport uint16
  _pad      uint16 // Alignment (wichtig!)
  DportChanges uint64
}


/* ==================== Helpers ==================== */

// waitForSignal blocks until SIGINT or SIGTERM is received. Used to keep
// long-running attach commands alive until the user requests shutdown.
func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
// ipToKeys parses a textual IP and returns:
// - isV4: true if IPv4
// - k4:  4-byte key for IPv4 maps (network order)
// - k6:  16-byte key for IPv6 maps
// This helper is used when inserting/deleting per-IP entries in maps.
func ipToKeys(ipstr string) (isV4 bool, k4 [4]byte, k6 [16]byte, err error) {
    ip := net.ParseIP(ipstr)
    if ip == nil {
        return false, k4, k6, fmt.Errorf("invalid IP: %s", ipstr)
    }
    if v4 := ip.To4(); v4 != nil {
        copy(k4[:], v4)
        return true, k4, k6, nil
    }
    v6 := ip.To16()
    if v6 == nil {
        return false, k4, k6, fmt.Errorf("invalid IPv6")
    }
    copy(k6[:], v6)
    return false, k4, k6, nil
}


// must is a small helper that exits the program on error with a message.
// It keeps the command code concise by handling fatal errors in a single place.
func must(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", msg, err)
		os.Exit(1)
	}
}

// openPinnedMap opens a map that was pinned under /sys/fs/bpf by the
// BPF loader or by this CLI previously. The function returns the Go
// representation of the map which must be closed by the caller when done.
func openPinnedMap(path string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(path, nil)
}

// ifaceIndexByName returns the kernel interface index for a given name.
// It calls must() internally to exit on error since index lookup is
// required for attaching XDP programs.
func ifaceIndexByName(name string) int {
	ifi, err := net.InterfaceByName(name)
	must(err, "InterfaceByName")
	return ifi.Index
}

/* ==================== XDP: Allow (CIDR) + Deny (IP) ==================== */

type lpmKey4 struct {
	Prefixlen uint32
	IPv4      [4]byte // network bytes
}
type lpmKey6 struct {
	Prefixlen uint32
	IPv6      [16]byte // network bytes
}

type xdpCfg struct {
	EnforceAllow uint32 // 0=off, 1=on (default-deny for addresses outside the allowlist)
}

func cmdAttachXDP(iface string) {
	// Attach the pre-compiled XDP program to `iface`.
	// This loads the eBPF object, which may also create and pin maps under
	// /sys/fs/bpf if they are declared with pinning. The XDP program name
	// expected in the object is "xdp_allow_then_deny".
	//
	// Note: ensure bpffs is mounted if not already: sudo mount -t bpf bpf /sys/fs/bpf || true
	spec, err := ebpf.LoadCollectionSpec(objXDP)
	must(err, "load xdp spec")

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf", // required for LIBBPF_PIN_BY_NAME in v0.19
		},
	})
	must(err, "new xdp collection (with PinPath)")
	defer coll.Close()

	prog, ok := coll.Programs["xdp_allow_then_deny"]
	if !ok {
		must(errors.New("program not found"), "prog xdp_allow_then_deny")
	}

	ifIndex := ifaceIndexByName(iface)
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifIndex,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		lnk, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifIndex,
			Flags:     link.XDPGenericMode,
		})
	}
	must(err, "attach XDP")
	defer lnk.Close()

	fmt.Printf("XDP (allow→deny, v4+v6) attached on %s. Ctrl+C to detach.\n", iface)
	waitForSignal()
}

/* ---------- Allow CIDR (v4+v6, auto-detect) ---------- */

func cmdAddAllowCIDR(cidr string) {
	// Add the given CIDR to the XDP allow LPM trie. The function auto-detects
	// IPv4 vs IPv6 and writes the proper key format expected by the kernel
	// LPM trie (prefixlen followed by network bytes in big-endian order).
	_, ipnet, err := net.ParseCIDR(cidr)
	must(err, "parse CIDR")

	ip := ipnet.IP
	ones, _ := ipnet.Mask.Size()

	if ip4 := ip.To4(); ip4 != nil {
		var key lpmKey4
		key.Prefixlen = uint32(ones)
		copy(key.IPv4[:], ip4)

		val := uint8(1)
		m, err := openPinnedMap(mapPinAllow4LPM)
		must(err, "open allow4 LPM")
		defer m.Close()
		must(m.Update(&key, &val, ebpf.UpdateAny), "add allow4 CIDR")
		fmt.Printf("Allow4: + %s\n", cidr)
		return
	}

	ip6 := ip.To16()
	if ip6 == nil {
		must(errors.New("invalid IP in CIDR"), "cidr")
	}
	var key6 lpmKey6
	key6.Prefixlen = uint32(ones)
	copy(key6.IPv6[:], ip6)

	val := uint8(1)
	m6, err := openPinnedMap(mapPinAllow6LPM)
	must(err, "open allow6 LPM")
	defer m6.Close()
	must(m6.Update(&key6, &val, ebpf.UpdateAny), "add allow6 CIDR")
	fmt.Printf("Allow6: + %s\n", cidr)
}

func cmdDelAllowCIDR(cidr string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	must(err, "parse CIDR")

	ip := ipnet.IP
	ones, _ := ipnet.Mask.Size()

	if ip4 := ip.To4(); ip4 != nil {
		var key lpmKey4
		key.Prefixlen = uint32(ones)
		copy(key.IPv4[:], ip4)
		m, err := openPinnedMap(mapPinAllow4LPM)
		must(err, "open allow4 LPM")
		defer m.Close()
		must(m.Delete(&key), "del allow4 CIDR")
		fmt.Printf("Allow4: - %s\n", cidr)
		return
	}

	ip6 := ip.To16()
	if ip6 == nil {
		must(errors.New("invalid IP in CIDR"), "cidr")
	}
	var key6 lpmKey6
	key6.Prefixlen = uint32(ones)
	copy(key6.IPv6[:], ip6)
	m6, err := openPinnedMap(mapPinAllow6LPM)
	must(err, "open allow6 LPM")
	defer m6.Close()
	must(m6.Delete(&key6), "del allow6 CIDR")
	fmt.Printf("Allow6: - %s\n", cidr)
}

func cmdListAllow() {
	var out []string

	// v4
	if m4, err := openPinnedMap(mapPinAllow4LPM); err == nil {
		defer m4.Close()
		it := m4.Iterate()
		var k lpmKey4
		var v uint8
		for it.Next(&k, &v) {
			ip := net.IPv4(k.IPv4[0], k.IPv4[1], k.IPv4[2], k.IPv4[3]).String()
			out = append(out, fmt.Sprintf("%s/%d", ip, k.Prefixlen))
		}
		must(it.Err(), "iterate allow4 LPM")
	}

	// v6
	if m6, err := openPinnedMap(mapPinAllow6LPM); err == nil {
		defer m6.Close()
		it := m6.Iterate()
		var k lpmKey6
		var v uint8
		for it.Next(&k, &v) {
			ip := net.IP(k.IPv6[:]).String()
			out = append(out, fmt.Sprintf("%s/%d", ip, k.Prefixlen))
		}
		must(it.Err(), "iterate allow6 LPM")
	}

	if len(out) == 0 {
		fmt.Println("(empty)")
		return
	}
	fmt.Println(strings.Join(out, "\n"))
}

/* ---------- Deny IP (v4+v6, auto-detect) ---------- */

func cmdAddDenyIP(ipstr string) {
	ip := net.ParseIP(ipstr)
	must(func() error {
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", ipstr)
		}
		return nil
	}(), "parse IP")

	if ip4 := ip.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		val := uint8(1)
		m, err := openPinnedMap(mapPinDeny4Hash)
		must(err, "open deny4 HASH")
		defer m.Close()
		must(m.Update(&key, &val, ebpf.UpdateAny), "add deny4 IP")
		fmt.Printf("Deny4: + %s\n", ipstr)
		return
	}

	ip6 := ip.To16()
	if ip6 == nil {
		must(errors.New("invalid IPv6"), "add deny IP")
	}
	var key6 [16]byte
	copy(key6[:], ip6)
	val := uint8(1)
	m6, err := openPinnedMap(mapPinDeny6Hash)
	must(err, "open deny6 HASH")
	defer m6.Close()
	must(m6.Update(&key6, &val, ebpf.UpdateAny), "add deny6 IP")
	fmt.Printf("Deny6: + %s\n", ipstr)
}

func cmdDelDenyIP(ipstr string) {
	ip := net.ParseIP(ipstr)
	must(func() error {
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", ipstr)
		}
		return nil
	}(), "parse IP")

	if ip4 := ip.To4(); ip4 != nil {
		var key [4]byte
		copy(key[:], ip4)
		m, err := openPinnedMap(mapPinDeny4Hash)
		must(err, "open deny4 HASH")
		defer m.Close()
		must(m.Delete(&key), "del deny4 IP")
		fmt.Printf("Deny4: - %s\n", ipstr)
		return
	}

	ip6 := ip.To16()
	if ip6 == nil {
		must(errors.New("invalid IPv6"), "del deny IP")
	}
	var key6 [16]byte
	copy(key6[:], ip6)
	m6, err := openPinnedMap(mapPinDeny6Hash)
	must(err, "open deny6 HASH")
	defer m6.Close()
	must(m6.Delete(&key6), "del deny6 IP")
	fmt.Printf("Deny6: - %s\n", ipstr)
}

func cmdListDeny() {
	var out []string

	// v4
	if m4, err := openPinnedMap(mapPinDeny4Hash); err == nil {
		defer m4.Close()
		it := m4.Iterate()
		var k [4]byte
		var v uint8
		for it.Next(&k, &v) {
			ip := net.IPv4(k[0], k[1], k[2], k[3]).String()
			out = append(out, ip)
		}
		must(it.Err(), "iterate deny4 HASH")
	}

	// v6
	if m6, err := openPinnedMap(mapPinDeny6Hash); err == nil {
		defer m6.Close()
		it := m6.Iterate()
		var k [16]byte
		var v uint8
		for it.Next(&k, &v) {
			ip := net.IP(k[:]).String()
			out = append(out, ip)
		}
		must(it.Err(), "iterate deny6 HASH")
	}

	if len(out) == 0 {
		fmt.Println("(empty)")
		return
	}
	fmt.Println(strings.Join(out, "\n"))
}

/* ==================== Enforce toggle ==================== */

func cmdEnforceAllow(set bool) {
	m, err := openPinnedMap(mapPinXDPCfg)
	must(err, "open xdp cfg (ARRAY[1])")
	defer m.Close()

	var k uint32 = 0
	val := xdpCfg{EnforceAllow: 0}
	if set {
		val.EnforceAllow = 1
	}
	must(m.Update(&k, &val, ebpf.UpdateAny), "update enforce_allow")
	state := "OFF"
	if set {
		state = "ON"
	}
	fmt.Printf("enforce_allow = %s\n", state)
}

func cmdShowEnforce() {
	m, err := openPinnedMap(mapPinXDPCfg)
	must(err, "open xdp cfg")
	defer m.Close()

	var k uint32 = 0
	var v xdpCfg
	err = m.Lookup(&k, &v)
	must(err, "lookup cfg")
	fmt.Printf("enforce_allow = %v\n", v.EnforceAllow == 1)
}

/* ==================== TC limiter (weiterhin v4) ==================== */

type cfgT struct {
	RatePPS uint64
	Burst   uint64
}

func ensureClsact(iface string) error {
	_ = exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").Run()
	return nil
}

func cmdAttachTC(iface string) {
	// Attach the TC (clsact) filter using the pinned program.
	// This sequence loads the BPF object, ensures maps are pinned (via
	// MapOptions.PinPath) and pins the program itself, then installs a
	// clsact ingress filter pointing at the pinned program path.

	// Absolute path is more robust
    obj := objTC
    if !strings.HasPrefix(obj, "/") {
        wd, _ := os.Getwd()
        obj = wd + "/" + objTC
    }

	// 1) Load BPF object and automatically pin maps
    spec, err := ebpf.LoadCollectionSpec(obj)
    must(err, "load tc spec")

    coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
	Maps: ebpf.MapOptions{ PinPath: "/sys/fs/bpf" }, // <- important!
    })
	must(err, "new tc collection (pin maps)")
	// Do not defer coll.Close() immediately — wait until everything is pinned

	// 2) Retrieve program and pin it manually
    prog, ok := coll.Programs["tc_rl_prog"]
    if !ok { must(errors.New("prog tc_rl_prog not found"), "prog tc") }
	must(prog.Pin("/sys/fs/bpf/tc_rl_prog"), "pin tc program")

	// (Maps are already pinned thanks to MapOptions)
	coll.Close() // free FDs; pins remain

	// 3) clsact + filter using the *pinned* program
    _ = exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").Run()
	cmd := exec.Command("tc", "filter", "replace",
        "dev", iface,
        "ingress",
        "bpf", "direct-action",
        "pinned", "/sys/fs/bpf/tc_rl_prog",
    )
    out, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Fprintf(os.Stderr, "ERROR: tc attach failed: %v\n%s", err, string(out))
        os.Exit(1)
    }

    fmt.Printf("TC rate limiter attached on %s (ingress). Ctrl+C to exit.\n", iface)
    waitForSignal()

	// Cleanup (optional)
    _ = exec.Command("tc", "filter", "del", "dev", iface, "ingress").Run()
    _ = os.Remove("/sys/fs/bpf/tc_rl_prog")
}


func cmdTCSet(rate, burst uint64) {
	m, err := openPinnedMap(mapPinTCCfg)
	must(err, "open tc cfg map")
	defer m.Close()
	var k uint32 = 0
	v := cfgT{RatePPS: rate, Burst: burst}
	must(m.Update(&k, &v, ebpf.UpdateAny), "update tc cfg")
	fmt.Printf("TC cfg: rate=%d pps, burst=%d\n", rate, burst)
}

func cmdTCSetIP(ip string, rate, burst uint64) {
    isV4, k4, k6, err := ipToKeys(ip)
    must(err, "parse ip")

    val := cfgT{RatePPS: rate, Burst: burst}
    if isV4 {
        m, err := openPinnedMap(mapPinTCPolicy4)
        must(err, "open tc policy4 map")
        defer m.Close()
        must(m.Update(&k4, &val, ebpf.UpdateAny), "update policy4")
        fmt.Printf("TC per-IP (v4): %s rate=%d pps burst=%d\n", ip, rate, burst)
        return
    }
    m, err := openPinnedMap(mapPinTCPolicy6)
    must(err, "open tc policy6 map")
    defer m.Close()
    must(m.Update(&k6, &val, ebpf.UpdateAny), "update policy6")
    fmt.Printf("TC per-IP (v6): %s rate=%d pps burst=%d\n", ip, rate, burst)
}

func cmdTCUnsetIP(ip string) {
    isV4, k4, k6, err := ipToKeys(ip)
    must(err, "parse ip")
    if isV4 {
        m, err := openPinnedMap(mapPinTCPolicy4)
        must(err, "open tc policy4 map")
        defer m.Close()
        must(m.Delete(&k4), "delete policy4")
        fmt.Printf("TC per-IP (v4) removed: %s\n", ip)
        return
    }
    m, err := openPinnedMap(mapPinTCPolicy6)
    must(err, "open tc policy6 map")
    defer m.Close()
    must(m.Delete(&k6), "delete policy6")
    fmt.Printf("TC per-IP (v6) removed: %s\n", ip)
}

func cmdXDPTotals() {
  m, err := openPinnedMap(mapPinXDPTotals)
  must(err, "open xdp_totals")
  defer m.Close()

  ncpu, err := ebpf.PossibleCPU()
  must(err, "PossibleCPU")

  key := uint32(0)
  vals := make([]xdpTotals, ncpu)

  must(m.Lookup(&key, &vals), "lookup percpu totals")

  var sum xdpTotals
  for _, v := range vals {
    sum.Pkts += v.Pkts
    sum.Bytes += v.Bytes
    sum.Pass += v.Pass
    sum.DropAllow += v.DropAllow
    sum.DropDeny += v.DropDeny
    sum.V4 += v.V4
    sum.V6 += v.V6
    sum.Tcp += v.Tcp
    sum.Udp += v.Udp
    sum.Icmp += v.Icmp
    sum.Syn += v.Syn
    sum.Synack += v.Synack
    sum.Rst += v.Rst
    sum.DportChanges += v.DportChanges
  }

  fmt.Printf("pkts=%d bytes=%d pass=%d drop_allow=%d drop_deny=%d syn=%d synack=%d rst=%d dport_changes=%d\n",
    sum.Pkts, sum.Bytes, sum.Pass, sum.DropAllow, sum.DropDeny, sum.Syn, sum.Synack, sum.Rst, sum.DportChanges)
}



/* ==================== CLI ==================== */

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:

  # Attach XDP (allow → deny → pass, v4+v6)
  sudo ./net-guard attach-xdp -iface eth0

	# Allowlist (CIDR; v4 and v6 are auto-detected)
  sudo ./net-guard add-allow-cidr 203.0.113.0/24
  sudo ./net-guard add-allow-cidr 2a02:120:34::/48
  sudo ./net-guard del-allow-cidr 203.0.113.0/24
  sudo ./net-guard del-allow-cidr 2a02:120:34::/48
  sudo ./net-guard list-allow

	# Denylist (Single IP; v4/v6 auto-detected)
  sudo ./net-guard add-deny-ip 203.0.113.7
  sudo ./net-guard add-deny-ip 2a02:120:34::dead
  sudo ./net-guard del-deny-ip 203.0.113.7
  sudo ./net-guard del-deny-ip 2a02:120:34::dead
  sudo ./net-guard list-deny

	# Enforce allowlist (default-deny for addresses outside the allowlist)
	sudo ./net-guard enforce-allow on|off|show

  # TC per-IP rate limiter (ingress)
  sudo ./net-guard attach-tc -iface eth0
  sudo ./net-guard tc-set -rate 5000 -burst 20000

  # TC per-IP Limits (override default)
  sudo ./net-guard tc-set-ip -rate 200 -burst 500 192.168.0.55
  sudo ./net-guard tc-set-ip -rate 100 -burst 300 <ipv6>
  sudo ./net-guard tc-unset-ip 192.0.2.55
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "xdp-totals":
  		cmdXDPTotals()

	case "attach-xdp":
		fs := flag.NewFlagSet("attach-xdp", flag.ExitOnError)
		iface := fs.String("iface", "eth0", "Interface")
		_ = fs.Parse(os.Args[2:])
		cmdAttachXDP(*iface)

	case "add-allow-cidr":
		if len(os.Args) != 3 {
			fmt.Println("add-allow-cidr <cidr>")
			os.Exit(2)
		}
		cmdAddAllowCIDR(os.Args[2])
	case "del-allow-cidr":
		if len(os.Args) != 3 {
			fmt.Println("del-allow-cidr <cidr>")
			os.Exit(2)
		}
		cmdDelAllowCIDR(os.Args[2])
	case "list-allow":
		cmdListAllow()

	case "add-deny-ip":
		if len(os.Args) != 3 {
			fmt.Println("add-deny-ip <IP>")
			os.Exit(2)
		}
		cmdAddDenyIP(os.Args[2])
	case "del-deny-ip":
		if len(os.Args) != 3 {
			fmt.Println("del-deny-ip <IP>")
			os.Exit(2)
		}
		cmdDelDenyIP(os.Args[2])
	case "list-deny":
		cmdListDeny()

	case "enforce-allow":
		if len(os.Args) < 3 {
			fmt.Println("enforce-allow <on|off|show>")
			os.Exit(2)
		}
		switch os.Args[2] {
		case "on":
			cmdEnforceAllow(true)
		case "off":
			cmdEnforceAllow(false)
		case "show":
			cmdShowEnforce()
		default:
			fmt.Println("enforce-allow <on|off|show>")
			os.Exit(2)
		}

	case "attach-tc":
		fs := flag.NewFlagSet("attach-tc", flag.ExitOnError)
		iface := fs.String("iface", "eth0", "Interface")
		_ = fs.Parse(os.Args[2:])
		cmdAttachTC(*iface)
	case "tc-set":
		fs := flag.NewFlagSet("tc-set", flag.ExitOnError)
		r := fs.Uint64("rate", 2000, "packets per second")
		b := fs.Uint64("burst", 10000, "max tokens")
		_ = fs.Parse(os.Args[2:])
		cmdTCSet(*r, *b)
        case "tc-set-ip":
	        fs := flag.NewFlagSet("tc-set-ip", flag.ExitOnError)
 	        r := fs.Uint64("rate", 1000, "packets per second")
   	        b := fs.Uint64("burst", 10000, "max tokens")
  	        _ = fs.Parse(os.Args[2:])
                if fs.NArg() != 1 {
                    fmt.Println("tc-set-ip [-rate N] [-burst N] <IP>")
                    os.Exit(2)
                }
                cmdTCSetIP(fs.Arg(0), *r, *b)

        case "tc-unset-ip":
                if len(os.Args) != 3 {
                    fmt.Println("tc-unset-ip <IP>")
                    os.Exit(2)
                }
                cmdTCUnsetIP(os.Args[2])

	default:
		usage()
		os.Exit(2)
	}
}

