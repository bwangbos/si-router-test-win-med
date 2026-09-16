package dhcp4

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"router/internal/platform"
	"router/pkg/models"
)

func simConfig(ip, gw string) *Sim {
	return &Sim{
		IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32),
		GW: net.ParseIP(gw), DNS: []string{"198.18.0.1", "9.9.9.9"},
		Lease: time.Hour,
	}
}

func wanCfg(iface, mode string) models.Config {
	enabled := true
	return models.Config{
		WANs: []models.WAN{{ID: "wan", Name: "wan", Interface: iface,
			Mode: models.WANMode(mode), Metric: 100, Enabled: &enabled}},
	}
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (e *eventLog) add(k, d string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, k+" "+d)
}

func (e *eventLog) has(sub string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.events {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func (e *eventLog) count(sub string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, s := range e.events {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timeout: " + msg)
}

func TestManagerBoundLifecycle(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1"})
	sim := simConfig("198.18.7.50", "198.18.7.1")
	ev := &eventLog{}
	changes := make(chan struct{}, 64)
	reg := NewRegistry(func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	})
	m := NewManager(Deps{Exec: f, Reg: reg, Make: sim.Factory(),
		Event: ev.add, Hostname: "routerd"})

	m.Sync(wanCfg("eth0", "dhcp"))
	waitFor(t, 5*time.Second, func() bool { return reg.Get("eth0") != nil }, "lease not acquired")
	l := reg.Get("eth0")
	if l.Addr.String() != "198.18.7.50/24" || l.Gateway.String() != "198.18.7.1" {
		t.Fatalf("lease=%v", l)
	}
	if len(l.DNS) != 2 || !ev.has("dhcp.bound") {
		t.Fatalf("dns=%v events=%v", l.DNS, ev.events)
	}
	<-changes // reconcile nudge fired

	// WANStatus adapter
	st := reg.WANStatus("eth0")
	if st.Address != "198.18.7.50/24" || st.Gateway != "198.18.7.1" || st.Lease == nil {
		t.Fatalf("wanstatus=%+v", st)
	}

	// Sync away (mode change) releases and clears
	c := wanCfg("eth0", "static")
	c.WANs[0].Static = &models.StaticWAN{Address: "203.0.113.5/24", Gateway: "203.0.113.1"}
	m.Sync(c)
	waitFor(t, 5*time.Second, func() bool { return reg.Get("eth0") == nil }, "lease not released")
	if !ev.has("dhcp.released") {
		t.Fatalf("no release event: %v", ev.events)
	}
	m.Shutdown()
}

func TestManagerUsesLinkMAC(t *testing.T) {
	f := platform.NewFake([]string{"eth0"})
	f.SetLinkMAC("eth0", "02:aa:bb:cc:dd:ee")
	if got := f.LinkMAC("eth0"); got != "02:aa:bb:cc:dd:ee" {
		t.Fatalf("fake mac=%q", got)
	}
	// the client reads the MAC through the executor: a fake link must
	// expose one at all (dhcp4 would fall back to nil otherwise)
	mac := (&Manager{deps: Deps{Exec: f}}).linkMAC(t.Context(), "eth0", models.WAN{})
	if mac == nil {
		t.Fatal("manager could not read MAC through fake executor")
	}
}

func TestRegistryUpstreams(t *testing.T) {
	reg := NewRegistry(nil)
	reg.set(&Lease{Iface: "eth0", Addr: &net.IPNet{IP: net.IPv4(1, 1, 1, 1), Mask: net.CIDRMask(24, 32)},
		DNS: []string{"198.18.0.1", "9.9.9.9"}})
	c := wanCfg("eth0", "dhcp")
	c.WANs[0].DNS = []string{"1.1.1.1"}
	c.DNS.Upstreams = []string{"9.9.9.9", "8.8.8.8"}
	got := reg.Upstreams(c)
	want := []string{"198.18.0.1", "9.9.9.9", "1.1.1.1", "8.8.8.8"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("upstreams=%v want=%v", got, want)
	}
}

func TestRetryOnSilence(t *testing.T) {
	f := platform.NewFake([]string{"eth0"})
	sim := simConfig("198.18.7.5", "198.18.7.1")
	sim.Silent = true
	ev := &eventLog{}
	reg := NewRegistry(nil)
	m := NewManager(Deps{Exec: f, Reg: reg, Make: sim.Factory(), Event: ev.add})
	m.Sync(wanCfg("eth0", "dhcp"))
	waitFor(t, 16*time.Second, func() bool { return ev.count("dhcp.retry") >= 2 }, "no retries")
	m.Shutdown()
}
