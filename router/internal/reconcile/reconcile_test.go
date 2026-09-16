package reconcile

import (
	"context"
	"sort"
	"strings"
	"testing"

	"router/internal/dhcp"
	"router/internal/platform"
	"router/internal/state"
	"router/pkg/models"
)

func tcShow(t *testing.T, f *platform.Fake, dev string) string {
	t.Helper()
	out, err := f.Run(t.Context(), nil, "tc", "-s", "qdisc", "show", "dev", dev)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func dhcpConfPath() string { return dhcp.ConfPathFor() }

func richConfig() models.Config {
	return models.Config{
		Version: 1,
		WANs: []models.WAN{
			{Name: "wan", ID: "wan", Interface: "eth0", Mode: models.WANModeDHCP, Enabled: models.Bool(true), Metric: 50},
			{Name: "wan2", ID: "wan2", Interface: "eth1", Mode: models.WANModeStatic, Enabled: models.Bool(true), Metric: 60,
				Static: &models.StaticWAN{Address: "203.0.113.10/24", Gateway: "203.0.113.1"}},
		},
		Networks: []models.Network{
			{ID: "lan", Name: "lan", Interface: "br-lan", Subnet: "192.168.1.1/24", Zone: "LAN", Members: []string{"eth2"},
				IPv6Subnet: "fd12:1::1/64", IPv6RA: true},
			{ID: "iot", Name: "iot", Interface: "br-iot", Subnet: "192.168.20.1/24", Zone: "IOT",
				VLAN: &models.VLANConfig{Parent: "eth2", ID: 20}},
		},
		WireGuard: []models.WireGuardTunnel{{
			Name: "wg-vpn", PrivateKey: "priv==", ListenPort: 51820, Address: "10.8.0.1/24",
			Peers: []models.WireGuardPeer{{Name: "laptop", PublicKey: strings.Repeat("A", 43) + "=", AllowedIPs: []string{"10.8.0.2/32"}}},
		}},
		TrafficPolicies: []models.TrafficPolicy{{Name: "wan", Interface: "eth0", UpMbps: 40, SQM: true, Qdisc: "cake"}},
		StaticRoutes:    []models.StaticRoute{{ID: "r1", Destination: "10.50.0.0/24", Via: "192.168.1.254", Metric: 100}},
	}
}

func TestBuildDesiredLinks(t *testing.T) {
	d, err := Build(richConfig())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DesiredLink{}
	for _, l := range d.Links {
		byName[l.Name] = l
	}
	if _, ok := byName["br-lan"]; !ok || byName["br-lan"].Type != "bridge" || !byName["br-lan"].Up {
		t.Fatalf("br-lan missing: %+v", d.Links)
	}
	if _, ok := byName["br-iot"]; !ok {
		t.Fatal("br-iot missing")
	}
	v := byName["eth2.20"]
	if v.Name == "" || v.Type != "vlan" || v.Parent != "eth2" || v.VLANID != 20 || v.Master != "br-iot" {
		t.Fatalf("vlan link wrong: %+v", v)
	}
	if byName["eth2"].Master != "br-lan" {
		t.Fatalf("member enslaved wrong: %+v", byName["eth2"])
	}
	if !byName["eth0"].Up {
		t.Fatal("wan link should be up")
	}
	wg := byName["wg-vpn"]
	if wg.Type != "wireguard" || !wg.Up {
		t.Fatalf("wg link missing: %+v", wg)
	}
}

func TestBuildDesiredAddresses(t *testing.T) {
	d, _ := Build(richConfig())
	if !containsStr(d.Addrs["br-lan"], "192.168.1.1/24") {
		t.Fatalf("lan addr missing: %v", d.Addrs)
	}
	if !containsStr(d.Addrs["br-lan"], "fd12:1::1/64") {
		t.Fatal("lan ipv6 addr missing")
	}
	if !containsStr(d.Addrs["br-iot"], "192.168.20.1/24") {
		t.Fatal("iot addr missing")
	}
	if !containsStr(d.Addrs["eth1"], "203.0.113.10/24") {
		t.Fatal("static wan addr missing")
	}
	if !containsStr(d.Addrs["wg-vpn"], "10.8.0.1/24") {
		t.Fatal("wg addr missing")
	}
}

func TestBuildDesiredRoutes(t *testing.T) {
	d, _ := Build(richConfig())
	var have2 bool
	for _, r := range d.Routes {
		if r.Dst == "203.0.113.0/24" {
			t.Fatal("connected route should be left to kernel")
		}
		if r.Dst == "0.0.0.0/0" && r.Via == "203.0.113.1" && r.Dev == "eth1" && r.Metric == 60 {
			have2 = true
		}
		if r.Dst == "10.50.0.0/24" && r.Via == "192.168.1.254" {
			haveStatic := true
			_ = haveStatic
		}
		if r.Dst == "10.8.0.2/32" && r.Dev != "wg-vpn" {
			t.Fatal("wg peer route dev wrong")
		}
	}
	if !have2 {
		t.Fatalf("static WAN default route missing: %+v", d.Routes)
	}
}

func TestBuildDesiredArtifacts(t *testing.T) {
	d, err := Build(richConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.NftScript, "table inet router") {
		t.Fatal("nft script missing")
	}
	if !strings.Contains(d.DnsmasqConf, "interface=br-lan") {
		t.Fatal("dnsmasq conf missing")
	}
	if !strings.Contains(d.WGConf["wg-vpn"], "PrivateKey = priv==") {
		t.Fatal("wg conf missing")
	}
	if !containsStr(d.TC["eth0"], "tc qdisc replace dev eth0 root handle 1: cake bandwidth 40mbit") {
		t.Fatalf("tc plan missing: %v", d.TC)
	}
}

func observe(t *testing.T, f *platform.Fake) *Actual {
	t.Helper()
	a, err := Observe(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLinkReconcilerPlanApply(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	actual := observe(t, f)
	ops := PlanLinks(d, actual)
	if len(ops) == 0 {
		t.Fatal("expected ops from empty state")
	}
	if err := ApplyOps(context.Background(), f, ops); err != nil {
		t.Fatal(err)
	}
	// idempotent
	ops2 := PlanLinks(d, observe(t, f))
	if len(ops2) != 0 {
		var descs []string
		for _, o := range ops2 {
			descs = append(descs, o.Desc)
		}
		t.Fatalf("expected idempotency, got: %v", descs)
	}
	a := observe(t, f)
	if a.Links.By("br-lan") == nil || !a.Links.By("br-lan").Up {
		t.Fatal("br-lan not created/up")
	}
	if a.Links.By("eth2.20") == nil || a.Links.By("eth2.20").VLANID != 20 {
		t.Fatal("vlan not created")
	}
	if a.Links.By("eth2.20").Master != "br-iot" {
		t.Fatal("vlan not attached")
	}
	if a.Links.By("eth2").Master != "br-lan" {
		t.Fatal("eth2 not enslaved")
	}
	if a.Links.By("wg-vpn") == nil {
		t.Fatal("wg link missing")
	}
}

func TestAddressReconciler(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	pre := observe(t, f)
	// links first
	ApplyOps(context.Background(), f, PlanLinks(d, pre))
	ops := PlanAddrs(d, observe(t, f))
	if len(ops) == 0 {
		t.Fatal("expected add ops")
	}
	if err := ApplyOps(context.Background(), f, ops); err != nil {
		t.Fatal(err)
	}
	if ops2 := PlanAddrs(d, observe(t, f)); len(ops2) != 0 {
		t.Fatalf("not idempotent: %+v", ops2)
	}
	// drift: remove an address, reconciler should restore
	f.Run(context.Background(), nil, "ip", "addr", "flush", "dev", "br-lan")
	ops3 := PlanAddrs(d, observe(t, f))
	if len(ops3) == 0 {
		t.Fatal("drift not detected")
	}
	ApplyOps(context.Background(), f, ops3)
	if ops4 := PlanAddrs(d, observe(t, f)); len(ops4) != 0 {
		t.Fatal("drift not repaired")
	}
}

func TestRouteReconciler(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	ApplyOps(context.Background(), f, PlanLinks(d, observe(t, f)))
	ApplyOps(context.Background(), f, PlanAddrs(d, observe(t, f)))
	ops := PlanRoutes(d, observe(t, f), nil)
	if err := ApplyOps(context.Background(), f, ops); err != nil {
		t.Fatal(err)
	}
	a := observe(t, f)
	var haveStatic bool
	for _, r := range a.Routes {
		if r.Dst == "10.50.0.0/24" && r.Via == "192.168.1.254" {
			haveStatic = true
		}
	}
	if !haveStatic {
		t.Fatalf("static route not installed: %+v", a.Routes)
	}
	if ops2 := PlanRoutes(d, observe(t, f), nil); len(ops2) != 0 {
		var d2 []string
		for _, o := range ops2 {
			d2 = append(d2, o.Desc)
		}
		t.Fatalf("not idempotent: %v", d2)
	}
}

func TestFirewallReconciler(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	ops := PlanFirewall(d, f.NftScript())
	if len(ops) != 1 {
		t.Fatalf("expected one apply op, got %d", len(ops))
	}
	if err := ApplyOps(context.Background(), f, ops); err != nil {
		t.Fatal(err)
	}
	if f.NftScript() != d.NftScript {
		t.Fatal("nft script not applied")
	}
	if ops2 := PlanFirewall(d, f.NftScript()); len(ops2) != 0 {
		t.Fatal("not idempotent")
	}
}

func TestServiceReconciler(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	ApplyOps(context.Background(), f, PlanLinks(d, observe(t, f)))
	ops := PlanServices(d, f)
	if err := ApplyOps(context.Background(), f, ops); err != nil {
		t.Fatal(err)
	}
	if b, ok := f.File(dhcpConfPath()); !ok || !strings.Contains(string(b), "interface=br-lan") {
		t.Fatal("dnsmasq conf not written")
	}
	if f.WGConfig("wg-vpn") == "" {
		t.Fatal("wg not synced")
	}
	ops2 := PlanServices(d, f)
	if len(ops2) != 0 {
		t.Fatalf("not idempotent: %+v", ops2)
	}
	// change wg conf on disk -> should resync
	d.WGConf["wg-vpn"] += "# changed\n"
	if len(PlanServices(d, f)) == 0 {
		t.Fatal("change not detected")
	}
	// service restarted on dnsmasq conf change
	restarts := f.ServiceOps()
	var sawDnsmasq bool
	for _, so := range restarts {
		if strings.Contains(so, "dnsmasq") {
			sawDnsmasq = true
		}
	}
	if !sawDnsmasq {
		t.Fatalf("dnsmasq never (re)started: %v", restarts)
	}
}

func TestQoSReconciler(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	ApplyOps(context.Background(), f, PlanLinks(d, observe(t, f)))
	a := observe(t, f)
	ops := PlanQoS(d, a)
	if err := ApplyOps(context.Background(), f, ops); err != nil {
		t.Fatal(err)
	}
	q, _ := state.ParseTC(tcShow(t, f, "eth0"))
	var haveCake bool
	for _, x := range q {
		if x.Kind == "cake" {
			haveCake = true
		}
	}
	if !haveCake {
		t.Fatal("cake qdisc not applied")
	}
	if ops2 := PlanQoS(d, observe(t, f)); len(ops2) != 0 {
		var desc []string
		for _, o := range ops2 {
			desc = append(desc, o.Desc)
		}
		t.Fatalf("not idempotent: %v", desc)
	}
}

func TestFullApplyAndVerify(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	e := NewEngine(f, NewMemoryProvenance())
	d, _ := Build(richConfig())
	rep, err := e.Apply(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Operations) == 0 {
		t.Fatal("expected operations")
	}
	// second apply must be a verified no-op
	rep2, err := e.Apply(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Operations) != 0 {
		var descs []string
		for _, o := range rep2.Operations {
			descs = append(descs, o.Desc)
		}
		sort.Strings(descs)
		t.Fatalf("expected convergence, got %v", descs)
	}
	// verify passes means observe->plan empty
	if err := e.Verify(context.Background(), d); err != nil {
		t.Fatal(err)
	}
}

func TestApplyFailurePropagates(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	f.FailNext("systemctl", "Unit dnsmasq.service is not loaded")
	e := NewEngine(f, NewMemoryProvenance())
	d, _ := Build(richConfig())
	if _, err := e.Apply(context.Background(), d); err == nil {
		t.Fatal("expected apply error")
	}
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func TestRouteProvenanceDeletes(t *testing.T) {
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	d, _ := Build(richConfig())
	ApplyOps(context.Background(), f, PlanLinks(d, observe(t, f)))
	e := NewEngine(f, NewMemoryProvenance())
	if _, err := e.Apply(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	// managed route present?
	var found bool
	for _, m := range e.prov.Load() {
		if m.Dst == "10.50.0.0/24" {
			found = true
		}
	}
	if !found {
		t.Fatal("provenance not recorded")
	}
	// remove the static route from config -> route must disappear
	c := richConfig()
	c.StaticRoutes = nil
	d2, _ := Build(c)
	if _, err := e.Apply(context.Background(), d2); err != nil {
		t.Fatal(err)
	}
	a := observe(t, f)
	for _, r := range a.Routes {
		if r.Dst == "10.50.0.0/24" {
			t.Fatal("stale route not deleted")
		}
	}
}
