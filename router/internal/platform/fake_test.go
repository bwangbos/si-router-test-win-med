package platform

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"router/internal/state"
)

func run(t *testing.T, f *Fake, stdin string, argv ...string) string {
	t.Helper()
	out, err := f.Run(context.Background(), []byte(stdin), argv...)
	if err != nil {
		t.Fatalf("%v: %v", argv, err)
	}
	return string(out)
}

func TestFakeLinkLifecycle(t *testing.T) {
	f := NewFake([]string{"lo", "eth0", "eth1"})
	run(t, f, "", "ip", "link", "add", "name", "br-lan", "type", "bridge")
	run(t, f, "", "ip", "link", "set", "dev", "br-lan", "up")
	run(t, f, "", "ip", "link", "set", "dev", "eth1", "master", "br-lan")

	out := run(t, f, "", "ip", "-json", "link", "show")
	links, err := state.ParseLinks(out)
	if err != nil {
		t.Fatal(err)
	}
	br := links.By("br-lan")
	if br == nil || !br.Up || br.Type != "bridge" {
		t.Fatalf("bridge missing: %+v", br)
	}
	e1 := links.By("eth1")
	if e1 == nil || e1.Master != "br-lan" {
		t.Fatalf("member not enslaved: %+v", e1)
	}
	run(t, f, "", "ip", "link", "set", "dev", "eth1", "nomaster")
	links, _ = state.ParseLinks(run(t, f, "", "ip", "-json", "link", "show"))
	if links.By("eth1").Master != "" {
		t.Fatal("nomaster failed")
	}
	run(t, f, "", "ip", "link", "set", "dev", "eth0", "mtu", "1492")
	links, _ = state.ParseLinks(run(t, f, "", "ip", "-json", "link", "show"))
	if links.By("eth0").MTU != 1492 {
		t.Fatal("mtu failed")
	}
	run(t, f, "", "ip", "link", "del", "dev", "br-lan")
	links, _ = state.ParseLinks(run(t, f, "", "ip", "-json", "link", "show"))
	if links.By("br-lan") != nil {
		t.Fatal("delete failed")
	}
	if links.By("eth1") == nil {
		t.Fatal("deleting bridge should not delete members")
	}
}

func TestFakeVLAN(t *testing.T) {
	f := NewFake([]string{"eth0"})
	run(t, f, "", "ip", "link", "add", "dev", "eth0.20", "link", "eth0", "type", "vlan", "id", "20")
	run(t, f, "", "ip", "link", "add", "name", "br-iot", "type", "bridge")
	run(t, f, "", "ip", "link", "set", "dev", "eth0.20", "master", "br-iot")
	links, _ := state.ParseLinks(run(t, f, "", "ip", "-json", "link", "show"))
	v := links.By("eth0.20")
	if v == nil || v.Type != "vlan" || v.VLANID != 20 || v.Link != "eth0" || v.Master != "br-iot" {
		t.Fatalf("vlan wrong: %+v", v)
	}
}

func TestFakeAddresses(t *testing.T) {
	f := NewFake([]string{"eth0"})
	run(t, f, "", "ip", "addr", "add", "192.168.1.1/24", "dev", "eth0")
	run(t, f, "", "ip", "addr", "add", "fd00::1/64", "dev", "eth0")
	addrs, err := state.ParseAddrs(run(t, f, "", "ip", "-json", "addr", "show"))
	if err != nil {
		t.Fatal(err)
	}
	a := addrs.By("eth0")
	if a == nil || !contains(a.Addrs, "192.168.1.1/24") || !contains(a.Addrs, "fd00::1/64") {
		t.Fatalf("addrs missing: %+v", a)
	}
	// idempotent re-add
	run(t, f, "", "ip", "addr", "add", "192.168.1.1/24", "dev", "eth0")
	addrs, _ = state.ParseAddrs(run(t, f, "", "ip", "-json", "addr", "show"))
	if n := countEq(addrs.By("eth0").Addrs, "192.168.1.1/24"); n != 1 {
		t.Fatalf("re-add should be idempotent, got %d", n)
	}
	run(t, f, "", "ip", "addr", "flush", "dev", "eth0")
	addrs, _ = state.ParseAddrs(run(t, f, "", "ip", "-json", "addr", "show"))
	if len(addrs.By("eth0").Addrs) != 0 {
		t.Fatal("flush failed")
	}
}

func TestFakeRoutes(t *testing.T) {
	f := NewFake([]string{"eth0"})
	run(t, f, "", "ip", "route", "add", "default", "via", "10.0.0.1", "dev", "eth0", "metric", "100")
	run(t, f, "", "ip", "route", "add", "10.10.0.0/24", "via", "192.168.1.254", "metric", "5")
	rt, err := state.ParseRoutes(run(t, f, "", "ip", "-json", "route", "show"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rt) != 2 {
		t.Fatalf("want 2 routes got %d", len(rt))
	}
	var def *state.Route
	for i := range rt {
		if rt[i].Dst == "0.0.0.0/0" {
			def = &rt[i]
		}
	}
	if def == nil || def.Via != "10.0.0.1" || def.Dev != "eth0" || def.Metric != 100 {
		t.Fatalf("bad default route: %+v", def)
	}
	run(t, f, "", "ip", "route", "del", "default", "via", "10.0.0.1", "dev", "eth0")
	rt, _ = state.ParseRoutes(run(t, f, "", "ip", "-json", "route", "show"))
	for _, r := range rt {
		if r.Dst == "0.0.0.0/0" {
			t.Fatal("route delete failed")
		}
	}
}

func TestFakeNeigh(t *testing.T) {
	f := NewFake([]string{"br-lan"})
	f.AddNeigh("br-lan", "192.168.1.55", "aa:bb:cc:dd:ee:ff")
	n, err := state.ParseNeigh(run(t, f, "", "ip", "-json", "neigh", "show"))
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 1 || n[0].LLAddr != "aa:bb:cc:dd:ee:ff" || n[0].Dev != "br-lan" {
		t.Fatalf("bad neigh: %+v", n)
	}
}

func TestFakeNft(t *testing.T) {
	f := NewFake([]string{"eth0"})
	script := "table inet router {\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n  }\n}\n"
	run(t, f, script, "nft", "-f", "-")
	if f.NftScript() != script {
		t.Fatalf("script not stored: %q", f.NftScript())
	}
	list := run(t, f, "", "nft", "list", "ruleset")
	if !strings.Contains(list, "table inet router") {
		t.Fatal("list ruleset missing table")
	}
	// invalid script rejected
	if _, err := f.Run(context.Background(), []byte("garbage script"), "nft", "-f", "-"); err == nil {
		t.Fatal("expected syntax error")
	}
}

func TestFakeTC(t *testing.T) {
	f := NewFake([]string{"eth0"})
	run(t, f, "", "tc", "qdisc", "replace", "dev", "eth0", "root", "handle", "1:", "cake", "bandwidth", "40mbit")
	run(t, f, "", "tc", "qdisc", "replace", "dev", "eth0", "ingress")
	q, err := state.ParseTC(run(t, f, "", "tc", "-s", "qdisc", "show", "dev", "eth0"))
	if err != nil {
		t.Fatal(err)
	}
	if len(q) != 2 {
		t.Fatalf("want 2 qdiscs got %v", q)
	}
	if q[0].Parent != "root" || !strings.Contains(q[0].Kind, "cake") {
		t.Fatalf("bad root qdisc: %+v", q[0])
	}
	run(t, f, "", "tc", "qdisc", "del", "dev", "eth0", "root")
	q, _ = state.ParseTC(run(t, f, "", "tc", "-s", "qdisc", "show", "dev", "eth0"))
	for _, x := range q {
		if x.Parent == "root" {
			t.Fatal("qdisc delete failed")
		}
	}
}

func TestFakeWG(t *testing.T) {
	f := NewFake([]string{"eth0"})
	run(t, f, "", "ip", "link", "add", "name", "wg-vpn", "type", "wireguard")
	conf := "[Interface]\nPrivateKey = abc\nListenPort = 51820\n\n[Peer]\nPublicKey = key1\nAllowedIPs = 10.8.0.2/32\n"
	run(t, f, conf, "wg", "syncconf", "wg-vpn", "-")
	if f.WGConfig("wg-vpn") != conf {
		t.Fatal("wg config not stored")
	}
}

func TestFakeRejectsUnknown(t *testing.T) {
	f := NewFake([]string{"eth0"})
	if _, err := f.Run(context.Background(), nil, "ip", "polite", "please"); err == nil {
		t.Fatal("expected error for nonsense")
	}
	if _, err := f.Run(context.Background(), nil, "iptables", "-L"); err == nil {
		t.Fatal("expected error for unsupported tool")
	}
	if _, err := f.Run(context.Background(), nil, "sh", "-c", "rm -rf /"); err == nil {
		t.Fatal("expected error for shell")
	}
}

func TestFakeWANStatus(t *testing.T) {
	f := NewFake([]string{"eth0"})
	// down by default
	if ws := f.WANStatus("eth0"); ws.Up {
		t.Fatal("wan should start down")
	}
	f.SimulateWANUp("eth0", "198.51.100.66/24", "198.51.100.1", []string{"8.8.8.8"})
	ws := f.WANStatus("eth0")
	if !ws.Up || ws.Address != "198.51.100.66/24" || ws.Gateway != "198.51.100.1" || ws.DNS[0] != "8.8.8.8" {
		t.Fatalf("wan up simulation failed: %+v", ws)
	}
	// DHCP client applied it as a real address + default route
	addrs, _ := state.ParseAddrs(run(t, f, "", "ip", "-json", "addr", "show", "dev", "eth0"))
	if !contains(addrs.By("eth0").Addrs, "198.51.100.66/24") {
		t.Fatal("simulated DHCP should install address")
	}
	f.SimulateWANDown("eth0")
	if ws := f.WANStatus("eth0"); ws.Up {
		t.Fatal("wan should be down")
	}
}

func TestFakeLeases(t *testing.T) {
	f := NewFake([]string{"br-lan"})
	f.SimulateLease("br-lan", "192.168.1.123", "aa:bb:cc:11:22:33", "laptop", 3600)
	leases := f.Leases()
	if len(leases) != 1 || leases[0].IP != "192.168.1.123" || leases[0].Hostname != "laptop" {
		t.Fatalf("lease not stored: %+v", leases)
	}
}

func TestFakeFiles(t *testing.T) {
	f := NewFake(nil)
	if err := f.WriteFile("/etc/dnsmasq.d/router.conf", []byte("conf")); err != nil {
		t.Fatal(err)
	}
	b, ok := f.File("/etc/dnsmasq.d/router.conf")
	if !ok || string(b) != "conf" {
		t.Fatal("file not stored")
	}
}

func TestFakeStatsRoundTrip(t *testing.T) {
	f := NewFake([]string{"eth0"})
	f.AddStats("eth0", state.Stats{RxBytes: 1000, TxBytes: 500, RxPackets: 10, TxPackets: 5})
	links, _ := state.ParseLinks(run(t, f, "", "ip", "-json", "link", "show"))
	st := links.By("eth0").Stats
	if st.RxBytes != 1000 || st.TxPackets != 5 {
		t.Fatalf("stats missing: %+v", st)
	}
}

func TestJSONOutputShapes(t *testing.T) {
	// fake output must be valid JSON arrays (same shape as iproute2)
	f := NewFake([]string{"eth0"})
	for _, argv := range [][]string{
		{"ip", "-json", "link", "show"},
		{"ip", "-json", "addr", "show"},
		{"ip", "-json", "route", "show"},
		{"ip", "-json", "neigh", "show"},
	} {
		out := run(t, f, "", argv...)
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("%v: %v", argv, err)
		}
	}
}

func contains(s []string, v string) bool {
	return countEq(s, v) > 0
}

func countEq(s []string, v string) int {
	n := 0
	for _, x := range s {
		if x == v {
			n++
		}
	}
	return n
}

func TestFakeTCClsactAndFilters(t *testing.T) {
	f := NewFake([]string{"eth0"})
	run(t, f, "", "tc", "qdisc", "replace", "dev", "eth0", "clsact")
	run(t, f, "", "tc", "filter", "replace", "dev", "eth0", "ingress", "protocol", "all", "prio", "1",
		"u32", "match", "u32", "0", "0", "action", "police", "rate", "940mbit", "burst", "10mbit", "drop")
	q, err := state.ParseTC(run(t, f, "", "tc", "-s", "qdisc", "show", "dev", "eth0"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range q {
		if x.Kind == "clsact" {
			found = true
		}
	}
	if !found {
		t.Fatalf("clsact qdisc missing: %+v", q)
	}
}
