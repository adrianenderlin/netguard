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
	mapPinXDPSrc4  = "/sys/fs/bpf/xdp_src4_stats"
	mapPinDeny4    = "/sys/fs/bpf/xdp_deny_hash"
	mapPinTCPolicy = "/sys/fs/bpf/tc_rl_policy4"
)

type xdpSrcStatsV4 struct {
	Pkts         uint64
	Bytes        uint64
	Tcp          uint64
	Udp          uint64
	Icmp         uint64
	Syn          uint64
	Synack       uint64
	Rst          uint64
	DropAllow    uint64
	DropDeny     uint64
	LastSeenNs   uint64
	LastDport    uint16
	_            [6]byte // padding for 8-byte align
	DportChanges uint64
}

type tcCfg struct {
	RatePPS uint64
	Burst   uint64
}

// ---- state machine ----
type Level int

const (
	LObserve Level = iota
	LSoft
	LHard
	LBlock
)

func (l Level) String() string {
	switch l {
	case LObserve:
		return "OBSERVE"
	case LSoft:
		return "RATE_SOFT"
	case LHard:
		return "RATE_HARD"
	case LBlock:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

type ipState struct {
	Level            Level
	Strikes          int
	ExpiresAt        time.Time
	CooldownUntil    time.Time
	LastTrigger      time.Time
	HighSevSince     time.Time // used for "block only if severity sustained"
	LastSeenWallTime time.Time // bookkeeping (optional)
}

// ---- prev deltas ----
type prevV4 struct {
	Pkts, Bytes, Syn, Scan uint64
	LastWall               time.Time
}

type metrics struct {
	IP       [4]byte
	PPS      float64
	Bps      float64
	SynRate  float64
	ScanRate float64
	Severity float64
}

func openPinnedMap(path string) (*ebpf.Map, error) { return ebpf.LoadPinnedMap(path, nil) }
func ip4String(k [4]byte) string                   { return net.IPv4(k[0], k[1], k[2], k[3]).String() }

func main() {
	interval := flag.Duration("interval", 1*time.Second, "poll interval (suggest 0.5s-1s)")
	topN := flag.Int("top", 50, "evaluate top N sources by SEVERITY")
	minPPS := flag.Float64("min-pps", 10, "ignore sources below this PPS (perf)")

	// Triggers (used to normalize severity)
	trigPPS := flag.Float64("trig-pps", 2000, "PPS trigger threshold (for severity normalization)")
	trigSyn := flag.Float64("trig-syn", 500, "SYN/s trigger threshold (for severity normalization)")
	trigScan := flag.Float64("trig-scan", 200, "scan/s trigger threshold (for severity normalization)")

	// Escalation thresholds (strikes)
	softAt := flag.Int("soft-at", 2, "strikes >= soft-at -> rate limit soft")
	hardAt := flag.Int("hard-at", 5, "strikes >= hard-at -> rate limit hard")
	blockAt := flag.Int("block-at", 9, "strikes >= block-at -> block (subject to block gates)")

	// Actions per level
	softRate := flag.Uint64("soft-rate", 2000, "soft rate limit pps")
	softBurst := flag.Uint64("soft-burst", 4000, "soft burst tokens")
	softTTL := flag.Duration("soft-ttl", 2*time.Minute, "soft TTL")

	hardRate := flag.Uint64("hard-rate", 300, "hard rate limit pps")
	hardBurst := flag.Uint64("hard-burst", 600, "hard burst tokens")
	hardTTL := flag.Duration("hard-ttl", 10*time.Minute, "hard TTL")

	blockTTL := flag.Duration("block-ttl", 30*time.Minute, "block TTL")

	cooldown := flag.Duration("cooldown", 10*time.Second, "min time between level changes for same IP")

	// housekeeping
	prevTTL := flag.Duration("prev-ttl", 10*time.Minute, "forget prev entries if not seen (bounds mem)")
	stateTTL := flag.Duration("state-ttl", 60*time.Minute, "forget OBSERVE-only state if not seen for this long")
	dryRun := flag.Bool("dry-run", true, "if true: no enforcement, only logs")

	// severity weighting
	wPPS := flag.Float64("w-pps", 0.50, "weight for PPS")
	wSyn := flag.Float64("w-syn", 0.30, "weight for SYN/s")
	wScan := flag.Float64("w-scan", 0.20, "weight for scan/s")
	sevCap := flag.Float64("sev-cap", 3.0, "cap for normalized metrics")
	minSev := flag.Float64("min-sev", 0.0, "also include candidates with severity >= min-sev even if PPS is low")

	// severity->strikes mapping (configurable steps)
	sevStep1 := flag.Float64("sev-step1", 1.0, "severity >= step1 -> add delta1 strikes")
	sevStep2 := flag.Float64("sev-step2", 2.0, "severity >= step2 -> add delta2 strikes")
	sevStep3 := flag.Float64("sev-step3", 3.0, "severity >= step3 -> add delta3 strikes")
	sevDelta1 := flag.Int("sev-delta1", 1, "strike delta at step1")
	sevDelta2 := flag.Int("sev-delta2", 2, "strike delta at step2")
	sevDelta3 := flag.Int("sev-delta3", 3, "strike delta at step3")
	sevDecayBelow := flag.Float64("sev-decay-below", 0.25, "if severity < this, strikes decay by 1 per tick")

	// block gating (NAT-friendly): require sustained severity before blocking
	blockMinSev := flag.Float64("block-min-sev", 2.5, "only allow BLOCK if severity >= this (set 0 to disable)")
	blockMinDur := flag.Duration("block-min-dur", 10*time.Second, "require severity >= block-min-sev for at least this duration before BLOCK (set 0 to disable)")

	flag.Parse()

	srcMap, err := openPinnedMap(mapPinXDPSrc4)
	if err != nil {
		log.Fatalf("open %s: %v", mapPinXDPSrc4, err)
	}
	defer srcMap.Close()

	var denyMap *ebpf.Map
	var tcMap *ebpf.Map
	if !*dryRun {
		denyMap, err = openPinnedMap(mapPinDeny4)
		if err != nil {
			log.Fatalf("open %s: %v", mapPinDeny4, err)
		}
		defer denyMap.Close()

		tcMap, err = openPinnedMap(mapPinTCPolicy)
		if err != nil {
			log.Fatalf("open %s: %v", mapPinTCPolicy, err)
		}
		defer tcMap.Close()
	}

	prev := make(map[[4]byte]prevV4, 64_000)
	state := make(map[[4]byte]ipState, 64_000)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf(
		"ADI FSM started interval=%s dry_run=%v top=%d trig{pps=%.0f syn=%.0f scan=%.0f} weights{pps=%.2f syn=%.2f scan=%.2f} cap=%.1f steps{%.2f/%.2f/%.2f} blockGate{sev>=%.2f for %s}",
		interval.String(), *dryRun, *topN,
		*trigPPS, *trigSyn, *trigScan,
		*wPPS, *wSyn, *wScan, *sevCap,
		*sevStep1, *sevStep2, *sevStep3,
		*blockMinSev, blockMinDur.String(),
	)

	for range ticker.C {
		nowWall := time.Now()

		// 1) read metrics, build candidates
		cands := make([]metrics, 0, 2048)

		it := srcMap.Iterate()
		var k [4]byte
		var v xdpSrcStatsV4

		for it.Next(&k, &v) {
			p, ok := prev[k]

			// First time we see this IP: store baseline and skip (avoid huge deltas).
			if !ok {
				prev[k] = prevV4{Pkts: v.Pkts, Bytes: v.Bytes, Syn: v.Syn, Scan: v.DportChanges, LastWall: nowWall}
				continue
			}

			sec := nowWall.Sub(p.LastWall).Seconds()
			if sec <= 0 {
				sec = interval.Seconds()
				if sec <= 0 {
					sec = 1
				}
			}

			// deltas
			dPkts := v.Pkts - p.Pkts
			dBytes := v.Bytes - p.Bytes
			dSyn := v.Syn - p.Syn
			dScan := v.DportChanges - p.Scan

			pps := float64(dPkts) / sec
			bps := float64(dBytes) / sec
			synRate := float64(dSyn) / sec
			scanRate := float64(dScan) / sec

			sev := calcSeverity(
				pps, synRate, scanRate,
				*trigPPS, *trigSyn, *trigScan,
				*wPPS, *wSyn, *wScan,
				*sevCap,
			)

			// Filter AFTER severity is computed (so min-sev works)
			if pps < *minPPS && sev < *minSev {
				prev[k] = prevV4{Pkts: v.Pkts, Bytes: v.Bytes, Syn: v.Syn, Scan: v.DportChanges, LastWall: nowWall}
				continue
			}

			cands = append(cands, metrics{
				IP:       k,
				PPS:      pps,
				Bps:      bps,
				SynRate:  synRate,
				ScanRate: scanRate,
				Severity: sev,
			})

			// update prev snapshot
			prev[k] = prevV4{Pkts: v.Pkts, Bytes: v.Bytes, Syn: v.Syn, Scan: v.DportChanges, LastWall: nowWall}
		}

		if err := it.Err(); err != nil {
			log.Printf("iterate src map err: %v", err)
			continue
		}

		// 2) keep only topN by SEVERITY (perf)
		sort.Slice(cands, func(i, j int) bool {
			if cands[i].Severity == cands[j].Severity {
				return cands[i].PPS > cands[j].PPS // tie-breaker
			}
			return cands[i].Severity > cands[j].Severity
		})
		if *topN < len(cands) {
			cands = cands[:*topN]
		}

		// 3) apply FSM updates for candidates
		for _, m := range cands {
			ip := m.IP
			st := state[ip] // zero value => Observe

			st.LastSeenWallTime = nowWall

			// Track sustained high severity for block gating.
			if *blockMinSev > 0 && m.Severity >= *blockMinSev {
				if st.HighSevSince.IsZero() {
					st.HighSevSince = nowWall
				}
			} else {
				st.HighSevSince = time.Time{}
			}

			// strikes update from severity (already weighted & capped)
			strikeDelta := 0
			switch {
			case m.Severity >= *sevStep3:
				strikeDelta = *sevDelta3
			case m.Severity >= *sevStep2:
				strikeDelta = *sevDelta2
			case m.Severity >= *sevStep1:
				strikeDelta = *sevDelta1
			default:
				strikeDelta = 0
			}

			if strikeDelta > 0 {
				st.Strikes += strikeDelta
				st.LastTrigger = nowWall
			} else if st.Strikes > 0 && m.Severity < *sevDecayBelow {
				st.Strikes--
			}

			// TTL expiry -> de-escalate if quiet (candidate loop)
			if st.Level > LObserve && !st.ExpiresAt.IsZero() && nowWall.After(st.ExpiresAt) {
				if nowWall.After(st.CooldownUntil) {
					newLevel := st.Level - 1
					st = transition(ip, st, newLevel, nowWall, *cooldown, *dryRun, denyMap, tcMap,
						*softRate, *softBurst, *softTTL,
						*hardRate, *hardBurst, *hardTTL,
						*blockTTL,
					)
				}
			}

			// determine target level based on strikes
			target := LObserve
			if st.Strikes >= *hardAt {
				target = LHard
			}
			if st.Strikes >= *softAt && target < LSoft {
				target = LSoft
			}

			// Block condition: strikes must be high AND (optional) severity must be sustained.
			blockEligible := st.Strikes >= *blockAt
			if blockEligible && *blockMinSev > 0 {
				if st.HighSevSince.IsZero() {
					blockEligible = false
				} else if *blockMinDur > 0 && nowWall.Sub(st.HighSevSince) < *blockMinDur {
					blockEligible = false
				}
			}
			if blockEligible {
				target = LBlock
			}

			// If not eligible for block but strikes>=blockAt, clamp to HARD
			if st.Strikes >= *blockAt && target == LObserve {
				target = LHard
			}
			if st.Strikes >= *blockAt && target == LSoft {
				target = LHard
			}

			if target != st.Level && nowWall.After(st.CooldownUntil) {
				prevLevel := st.Level
				st = transition(ip, st, target, nowWall, *cooldown, *dryRun, denyMap, tcMap,
					*softRate, *softBurst, *softTTL,
					*hardRate, *hardBurst, *hardTTL,
					*blockTTL,
				)
				log.Printf("STATE %s %s->%s strikes=%d sev=%.2f pps=%.0f syn=%.0f scan=%.0f (blockEligible=%v)",
					ip4String(ip), prevLevel.String(), st.Level.String(), st.Strikes, m.Severity, m.PPS, m.SynRate, m.ScanRate, blockEligible)
			}

			state[ip] = st
		}

		// 4) housekeeping: remove old prev entries to bound memory
		for ip, p := range prev {
			if nowWall.Sub(p.LastWall) > *prevTTL {
				delete(prev, ip)
			}
		}

		// 5) TTL cleanup for ALL state entries (even if not in cands)
		for ip, st := range state {
			// forget OBSERVE-only states that haven't been seen in a while
			if st.Level == LObserve && st.Strikes == 0 && !st.LastSeenWallTime.IsZero() && nowWall.Sub(st.LastSeenWallTime) > *stateTTL {
				delete(state, ip)
				continue
			}

			if st.Level <= LObserve || st.ExpiresAt.IsZero() || nowWall.Before(st.ExpiresAt) {
				continue
			}
			if nowWall.Before(st.CooldownUntil) {
				continue
			}

			oldExp := st.ExpiresAt
			newLevel := st.Level - 1
			st = transition(ip, st, newLevel, nowWall, *cooldown, *dryRun, denyMap, tcMap,
				*softRate, *softBurst, *softTTL,
				*hardRate, *hardBurst, *hardTTL,
				*blockTTL,
			)

			log.Printf("TTL STEP-DOWN %s -> %s (expired at %s)",
				ip4String(ip), st.Level.String(), oldExp.Format(time.RFC3339))

			if st.Level == LObserve && st.Strikes == 0 {
				// keep around until state-ttl handles it, unless you want immediate delete:
				// delete(state, ip)
				state[ip] = st
			} else {
				state[ip] = st
			}
		}

		// Optional: print a compact top line
		if len(cands) > 0 {
			top := cands[0]
			fmt.Printf("TOP %-15s sev=%.2f pps=%.0f Bps=%.0f syn=%.0f scan=%.0f\n",
				ip4String(top.IP), top.Severity, top.PPS, top.Bps, top.SynRate, top.ScanRate)
		}
	}
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func calcSeverity(
	pps, synps, scanps float64,
	trigPPS, trigSyn, trigScan float64,
	wPPS, wSyn, wScan float64,
	cap float64,
) float64 {
	nPPS := 0.0
	if trigPPS > 0 {
		nPPS = minf(pps/trigPPS, cap)
	}
	nSyn := 0.0
	if trigSyn > 0 {
		nSyn = minf(synps/trigSyn, cap)
	}
	nScan := 0.0
	if trigScan > 0 {
		nScan = minf(scanps/trigScan, cap)
	}
	return wPPS*nPPS + wSyn*nSyn + wScan*nScan
}

func transition(
	ip [4]byte,
	st ipState,
	target Level,
	now time.Time,
	cooldown time.Duration,
	dry bool,
	denyMap, tcMap *ebpf.Map,
	softRate, softBurst uint64, softTTL time.Duration,
	hardRate, hardBurst uint64, hardTTL time.Duration,
	blockTTL time.Duration,
) ipState {
	apply := func() {
		if dry {
			return
		}
		switch target {
		case LObserve:
			if tcMap != nil {
				_ = tcMap.Delete(&ip)
			}
			if denyMap != nil {
				_ = denyMap.Delete(&ip)
			}
		case LSoft:
			if denyMap != nil {
				_ = denyMap.Delete(&ip)
			}
			if tcMap != nil {
				val := tcCfg{RatePPS: softRate, Burst: softBurst}
				_ = tcMap.Update(&ip, &val, ebpf.UpdateAny)
			}
		case LHard:
			if denyMap != nil {
				_ = denyMap.Delete(&ip)
			}
			if tcMap != nil {
				val := tcCfg{RatePPS: hardRate, Burst: hardBurst}
				_ = tcMap.Update(&ip, &val, ebpf.UpdateAny)
			}
		case LBlock:
			// XDP dominates; remove TC policy then add deny entry
			if tcMap != nil {
				_ = tcMap.Delete(&ip)
			}
			if denyMap != nil {
				v := uint8(1)
				_ = denyMap.Update(&ip, &v, ebpf.UpdateAny)
			}
		}
	}

	apply()

	st.Level = target
	st.CooldownUntil = now.Add(cooldown)

	switch target {
	case LObserve:
		st.ExpiresAt = time.Time{}
	case LSoft:
		st.ExpiresAt = now.Add(softTTL)
	case LHard:
		st.ExpiresAt = now.Add(hardTTL)
	case LBlock:
		st.ExpiresAt = now.Add(blockTTL)
	}
	return st
}
