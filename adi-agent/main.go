package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"github.com/cilium/ebpf"
)

const (
	mapPinXDPSrc4 = "/sys/fs/bpf/xdp_src4_stats"
	mapPinDeny4   = "/sys/fs/bpf/xdp_deny_hash" // optional fürs blocken
)

type xdpSrcStatsV4 struct {
	Pkts       uint64
	Bytes      uint64
	Tcp        uint64
	Udp        uint64
	Icmp       uint64
	Syn        uint64
	Synack     uint64
	Rst        uint64
	DropAllow  uint64
	DropDeny   uint64
	LastSeenNs uint64
	LastDport  uint16
	_          [6]byte
	DportChanges uint64
}

type prevV4 struct {
	Pkts, Bytes, Syn, DportChanges uint64
	LastSeenNs                     uint64
}

type cand struct {
	IP        [4]byte
	PPS       float64
	BPS       float64
	SynRate   float64
	ScanRate  float64
	LastSeen  uint64
}

func openPinnedMap(path string) (*ebpf.Map, error) { return ebpf.LoadPinnedMap(path, nil) }

func ip4String(k [4]byte) string { return net.IPv4(k[0], k[1], k[2], k[3]).String() }

func main() {
	interval := flag.Duration("interval", 1*time.Second, "poll interval")
	topN := flag.Int("top", 20, "top N src IPs")

	// Heuristik-Schwellen (MVP)
	ppsBlock := flag.Float64("pps-block", 0, "if >0, block src when PPS exceeds threshold")
	synBlock := flag.Float64("syn-block", 0, "if >0, block src when SYN/s exceeds threshold")
	scanBlock := flag.Float64("scan-block", 0, "if >0, block src when dport_changes/s exceeds threshold")
	blockTTL := flag.Duration("block-ttl", 10*time.Minute, "block TTL (userspace managed)")

	flag.Parse()

	srcMap, err := openPinnedMap(mapPinXDPSrc4)
	if err != nil {
		log.Fatalf("open %s: %v", mapPinXDPSrc4, err)
	}
	defer srcMap.Close()

	var denyMap *ebpf.Map
	if *ppsBlock > 0 || *synBlock > 0 || *scanBlock > 0 {
		denyMap, err = openPinnedMap(mapPinDeny4)
		if err != nil {
			log.Fatalf("open %s: %v", mapPinDeny4, err)
		}
		defer denyMap.Close()
	}

	prev := make(map[[4]byte]prevV4, 64_000)
	blockedUntil := make(map[[4]byte]time.Time)

	t := time.NewTicker(*interval)
	defer t.Stop()

	for range t.C {
		sec := interval.Seconds()

		// TTL cleanup (userspace)
		nowT := time.Now()
		for ip, until := range blockedUntil {
			if nowT.After(until) {
				if denyMap != nil {
					_ = denyMap.Delete(&ip) // ignore err if already gone
				}
				delete(blockedUntil, ip)
			}
		}

		cands := make([]cand, 0, 1024)

		it := srcMap.Iterate()
		var k [4]byte
		var v xdpSrcStatsV4

		for it.Next(&k, &v) {
			p, ok := prev[k]
			dPkts := v.Pkts
			dBytes := v.Bytes
			dSyn := v.Syn
			dScan := v.DportChanges

			if ok {
				dPkts = v.Pkts - p.Pkts
				dBytes = v.Bytes - p.Bytes
				dSyn = v.Syn - p.Syn
				dScan = v.DportChanges - p.DportChanges
			}

			pps := float64(dPkts) / sec
			bps := float64(dBytes) / sec
			synRate := float64(dSyn) / sec
			scanRate := float64(dScan) / sec

			// prev updaten
			prev[k] = prevV4{
				Pkts: v.Pkts, Bytes: v.Bytes, Syn: v.Syn, DportChanges: v.DportChanges, LastSeenNs: v.LastSeenNs,
			}

			// Skip fast: sehr kleine pps ignorieren
			if pps < 1 && synRate < 1 && scanRate < 1 {
				continue
			}

			cands = append(cands, cand{
				IP: k, PPS: pps, BPS: bps, SynRate: synRate, ScanRate: scanRate, LastSeen: v.LastSeenNs,
			})
		}
		if err := it.Err(); err != nil {
			log.Printf("iterate err: %v", err)
			continue
		}

		// Sort nach PPS (du kannst auch SynRate oder ScanRate priorisieren)
		sort.Slice(cands, func(i, j int) bool { return cands[i].PPS > cands[j].PPS })

		limit := *topN
		if limit > len(cands) {
			limit = len(cands)
		}

		fmt.Printf("\nTOP %d src (interval=%s)\n", limit, interval.String())
		for i := 0; i < limit; i++ {
			c := cands[i]
			fmt.Printf("%2d) %-15s pps=%8.0f  Bps=%10.0f  syn/s=%6.0f  scan/s=%6.0f\n",
				i+1, ip4String(c.IP), c.PPS, c.BPS, c.SynRate, c.ScanRate)
		}

		// Optional: blocken (MVP)
		if denyMap != nil {
			for _, c := range cands[:limit] {
				if blockedUntil[c.IP].After(nowT) {
					continue
				}
				shouldBlock := false
				if *ppsBlock > 0 && c.PPS >= *ppsBlock {
					shouldBlock = true
				}
				if *synBlock > 0 && c.SynRate >= *synBlock {
					shouldBlock = true
				}
				if *scanBlock > 0 && c.ScanRate >= *scanBlock {
					shouldBlock = true
				}
				if shouldBlock {
					val := uint8(1)
					if err := denyMap.Update(&c.IP, &val, ebpf.UpdateAny); err != nil {
						log.Printf("block %s failed: %v", ip4String(c.IP), err)
						continue
					}
					blockedUntil[c.IP] = nowT.Add(*blockTTL)
					log.Printf("BLOCK %s ttl=%s (pps=%.0f syn/s=%.0f scan/s=%.0f)",
						ip4String(c.IP), blockTTL.String(), c.PPS, c.SynRate, c.ScanRate)
				}
			}
		}
	}
}
