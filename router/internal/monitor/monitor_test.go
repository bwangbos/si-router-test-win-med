package monitor

import (
	"context"
	"testing"

	"router/internal/config"
	"router/internal/platform"
	"router/pkg/models"
)

func baseCfg() models.Config {
	c := config.Default()
	c.Networks = append(c.Networks, models.Network{
		ID: "iot", Name: "iot", Interface: "br-iot", Subnet: "192.168.20.1/24", Zone: "IOT",
	})
	return c
}

func TestDevicesMergeLeasesNeighAliases(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1"})
	f.SimulateLease("br-lan", "192.168.1.123", "AA:BB:CC:11:22:33", "laptop", 3600)
	f.SimulateLease("br-iot", "192.168.20.42", "aa:bb:cc:dd:ee:ff", "tv", 3600)
	f.AddNeigh("br-lan", "192.168.1.200", "de:ad:be:ef:00:01")
	m := New(f, nil)
	aliases := map[string]string{"aa:bb:cc:dd:ee:ff": "Living Room TV"}
	m.SetAliases(aliases)
	devs := m.Devices(baseCfg())
	if len(devs) != 3 {
		t.Fatalf("want 3 devices got %d: %+v", len(devs), devs)
	}
	byMAC := map[string]Device{}
	for _, d := range devs {
		byMAC[d.MAC] = d
	}
	tv := byMAC["aa:bb:cc:dd:ee:ff"]
	if tv.Name != "Living Room TV" || tv.IPv4 != "192.168.20.42" || tv.Network != "iot" {
		t.Fatalf("alias/lease merge wrong: %+v", tv)
	}
	lap := byMAC["aa:bb:cc:11:22:33"]
	if lap.Hostname != "laptop" || lap.Network != "lan" {
		t.Fatalf("lease merge wrong: %+v", lap)
	}
	neigh := byMAC["de:ad:be:ef:00:01"]
	if neigh.IPv4 != "192.168.1.200" {
		t.Fatalf("neigh merge wrong: %+v", neigh)
	}
	for _, d := range devs {
		if d.FirstSeen.IsZero() || d.LastSeen.IsZero() {
			t.Fatalf("timestamps missing: %+v", d)
		}
	}
}

func TestWANStatusDHCP(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1"})
	m := New(f, nil)
	c := baseCfg()
	st := m.WANStatus(c)[0]
	if st.Up {
		t.Fatal("wan should start down")
	}
	f.SimulateWANUp("eth0", "198.51.100.66/24", "198.51.100.1", []string{"8.8.8.8"})
	st = m.WANStatus(c)[0]
	if !st.Up || st.Address != "198.51.100.66/24" || st.Gateway != "198.51.100.1" {
		t.Fatalf("wan status wrong: %+v", st)
	}
	if len(st.DNS) != 1 || st.DNS[0] != "8.8.8.8" {
		t.Fatalf("wan dns wrong: %+v", st.DNS)
	}
	if st.Uptime == "" {
		t.Fatal("uptime missing")
	}
}

func TestWANStatusStatic(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1"})
	c := baseCfg()
	c.WANs = []models.WAN{{
		ID: "wan2", Name: "wan2", Interface: "eth1", Mode: models.WANModeStatic,
		Enabled: models.Bool(true), Metric: 60,
		Static: &models.StaticWAN{Address: "203.0.113.10/24", Gateway: "203.0.113.1"},
	}}
	f.Run(context.Background(), nil, "ip", "link", "set", "dev", "eth1", "up")
	f.Run(context.Background(), nil, "ip", "addr", "add", "203.0.113.10/24", "dev", "eth1")
	m := New(f, nil)
	st := m.WANStatus(c)[0]
	if !st.Up || st.Address != "203.0.113.10/24" || st.Gateway != "203.0.113.1" {
		t.Fatalf("static wan status wrong: %+v", st)
	}
}

func TestHealth(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1"})
	m := New(f, nil)
	c := baseCfg()
	h := m.Health(c)
	if h.Status != StatusDegraded {
		t.Fatalf("WAN down should be degraded: %+v", h)
	}
	f.SimulateWANUp("eth0", "198.51.100.5/24", "198.51.100.1", nil)
	h = m.Health(c)
	if h.Status != StatusHealthy {
		t.Fatalf("wan up should be healthy: %+v", h)
	}
	if len(h.Checks) == 0 {
		t.Fatal("health checks missing")
	}
	// DHCP dead + wan up => degraded
	m.SetServiceDown("dnsmasq")
	h = m.Health(c)
	if h.Status != StatusDegraded {
		t.Fatalf("service down should degrade: %+v", h)
	}
}

func TestExpiredLeasesGone(t *testing.T) {
	f := platform.NewFake([]string{"br-lan"})
	f.SimulateLease("br-lan", "192.168.1.5", "aa:aa:aa:aa:aa:aa", "old", -10)
	m := New(f, nil)
	devs := m.Devices(baseCfg())
	for _, d := range devs {
		if d.IPv4 == "192.168.1.5" {
			t.Fatal("expired lease still present")
		}
	}
}
