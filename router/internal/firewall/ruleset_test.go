package firewall

import (
	"strings"
	"testing"

	"router/pkg/models"
)

func baseConfig() models.Config {
	return models.Config{
		Version: 1,
		WANs: []models.WAN{
			{ID: "wan", Name: "wan", Interface: "eth0", Mode: models.WANModeDHCP, Enabled: models.Bool(true)},
		},
		Networks: []models.Network{
			{ID: "lan", Name: "lan", Interface: "br-lan", Subnet: "192.168.1.1/24", Zone: "LAN",
				InternetAccess: models.Bool(true), AccessToLAN: models.Bool(true)},
			{ID: "iot", Name: "iot", Interface: "br-iot", Subnet: "192.168.20.1/24", Zone: "IOT"},
			{ID: "guest", Name: "guest", Interface: "br-guest", Subnet: "192.168.30.1/24", Zone: "GUEST"},
		},
	}
}

func mustGen(t *testing.T, c models.Config) string {
	t.Helper()
	s, err := Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGenerateStructure(t *testing.T) {
	s := mustGen(t, baseConfig())
	for _, want := range []string{
		"table inet router",
		"chain forward", "type filter hook forward priority 0; policy drop;",
		"chain input", "type filter hook input priority 0; policy drop;",
		"ct state established,related accept",
		"ct state invalid drop",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("ruleset missing %q:\n%s", want, s)
		}
	}
}

func TestGenerateZoneSets(t *testing.T) {
	s := mustGen(t, baseConfig())
	for _, want := range []string{
		`set wan_ifaces {`,
		`"eth0"`,
		`set lan_ifaces {`,
		`"br-lan"`,
		`set iot_ifaces {`,
		`set guest_ifaces {`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing zone set entry %q in:\n%s", want, s)
		}
	}
}

func TestGenerateWANBlocked(t *testing.T) {
	s := mustGen(t, baseConfig())
	// WAN -> forwarded traffic must be dropped before any accept
	i := strings.Index(s, `iifname @wan_ifaces counter drop`)
	if i < 0 {
		t.Fatal("missing wan forward drop")
	}
	j := strings.Index(s, "iifname @lan_ifaces")
	if i > j {
		t.Fatal("wan drop must precede zone accepts")
	}
}

func TestGenerateInternetPolicy(t *testing.T) {
	c := baseConfig()
	s := mustGen(t, c)
	if !strings.Contains(s, "iifname @lan_ifaces oifname @wan_ifaces counter accept") {
		t.Fatal("LAN->WAN should be accepted")
	}
	// IOT/GUEST default internet access is true
	if !strings.Contains(s, "iifname @iot_ifaces oifname @wan_ifaces counter accept") {
		t.Fatal("IOT->WAN default accept")
	}
	// no zone-to-zone accepts except from LAN
	if strings.Contains(s, "iifname @guest_ifaces oifname @lan_ifaces") {
		t.Fatal("GUEST->LAN must not be accepted")
	}
	if strings.Contains(s, "iifname @iot_ifaces oifname @lan_ifaces") {
		t.Fatal("IOT->LAN must not be accepted")
	}
	// LAN can reach all zones (admin)
	if !strings.Contains(s, "iifname @lan_ifaces oifname @iot_ifaces counter accept") {
		t.Fatal("LAN->IOT should be accepted")
	}
}

func TestGenerateInternetDisabled(t *testing.T) {
	c := baseConfig()
	f := false
	c.Networks[1].InternetAccess = &f
	s := mustGen(t, c)
	if strings.Contains(s, "iifname @iot_ifaces oifname @wan_ifaces") {
		t.Fatal("IOT internet disabled must remove accept")
	}
}

func TestGenerateLANAccessEnabled(t *testing.T) {
	c := baseConfig()
	c.Networks[1].AccessToLAN = models.Bool(true)
	s := mustGen(t, c)
	if !strings.Contains(s, "iifname @iot_ifaces oifname @lan_ifaces counter accept") {
		t.Fatal("explicit access_to_lan should generate accept")
	}
}

func TestGenerateUserRules(t *testing.T) {
	c := baseConfig()
	c.FirewallRules = []models.FirewallRule{{
		ID: "r1", SourceZone: "GUEST", DestZone: "IOT", Protocol: "tcp",
		Ports: []models.PortRange{{Start: 8000, End: 8010}}, Action: models.ActionAccept, Enabled: true,
	}, {
		ID: "r2", SourceZone: "IOT", DestZone: "LAN", Protocol: "any", Action: models.ActionReject, Enabled: true,
	}, {
		ID: "r3", SourceZone: "WAN", DestZone: "LAN", Protocol: "any", Action: models.ActionAccept, Enabled: false,
	}}
	s := mustGen(t, c)
	if !strings.Contains(s, "iifname @guest_ifaces oifname @iot_ifaces tcp dport 8000-8010 counter accept") {
		t.Fatalf("user rule missing:\n%s", s)
	}
	if !strings.Contains(s, "iifname @iot_ifaces oifname @lan_ifaces counter reject") {
		t.Fatal("reject rule missing")
	}
	if strings.Contains(s, "@wan_ifaces") && strings.Contains(s, "rule r3") {
		t.Fatal("disabled rule should not be present")
	}
	// user rules must be evaluated before generic zone policy accepts
	u := strings.Index(s, "tcp dport 8000-8010")
	z := strings.Index(s, "iifname @lan_ifaces oifname @wan_ifaces")
	if u < 0 || z < 0 || u > z {
		t.Fatal("user rules must precede zone defaults")
	}
}

func TestGenerateMasquerade(t *testing.T) {
	c := baseConfig()
	c.StaticRoutes = nil
	s := mustGen(t, c)
	if !strings.Contains(s, `ip saddr 192.168.1.0/24 oifname "eth0" counter masquerade`) {
		t.Fatalf("masquerade missing:\n%s", s)
	}
	if !strings.Contains(s, `ip saddr 192.168.20.0/24 oifname "eth0" counter masquerade`) {
		t.Fatal("masquerade for iot missing")
	}
}

func TestGeneratePortForwards(t *testing.T) {
	c := baseConfig()
	c.PortForwards = []models.PortForward{
		{ID: "pf1", Name: "https", WAN: "wan", Protocol: "tcp", ExternalPort: 8443, InternalIP: "192.168.1.50", InternalPort: 443, Enabled: true},
		{ID: "pf2", Protocol: "udp", ExternalPort: 5353, InternalIP: "192.168.30.9", InternalPort: 5353, Enabled: true},
		{ID: "pf3", Protocol: "tcp", ExternalPort: 22, InternalIP: "192.168.1.5", Enabled: false},
	}
	s := mustGen(t, c)
	if !strings.Contains(s, `tcp dport 8443 dnat to 192.168.1.50:443`) {
		t.Fatalf("dnat missing:\n%s", s)
	}
	if !strings.Contains(s, `udp dport 5353 dnat to 192.168.30.9:5353`) {
		t.Fatal("udp dnat missing")
	}
	if strings.Contains(s, "dport 22") {
		t.Fatal("disabled port forward present")
	}
	// hairpin support: dnat also applies to LAN traffic destined to WAN address set
	if !strings.Contains(s, "ip daddr @wan_public") {
		t.Fatal("hairpin rule missing")
	}
}

func TestGenerateInputServices(t *testing.T) {
	c := baseConfig()
	s := mustGen(t, c)
	for _, want := range []string{
		"iifname \"lo\" accept",
		"udp dport { 53, 67, 547 } accept", // dns/dhcp from lan-side
		"icmp type echo-request accept",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("input missing %q:\n%s", want, s)
		}
	}
	// WAN may not reach the router except wireguard/esp handled below
	if !strings.Contains(s, "iifname @wan_ifaces counter drop") {
		t.Fatal("wan input drop missing")
	}
}

func TestGenerateDeterministic(t *testing.T) {
	a := mustGen(t, baseConfig())
	b := mustGen(t, baseConfig())
	if a != b {
		t.Fatal("ruleset generation must be deterministic")
	}
}

func TestGenerateDisabledWANExcluded(t *testing.T) {
	c := baseConfig()
	c.WANs[0].Enabled = models.Bool(false)
	s := mustGen(t, c)
	if strings.Contains(s, `"eth0"`) {
		t.Fatal("disabled WAN must be excluded")
	}
}

func TestFirewallChainCommentMarker(t *testing.T) {
	s := mustGen(t, baseConfig())
	if !strings.Contains(s, `comment "routerd-sha:`) {
		t.Fatalf("chain comment marker missing:\n%s", s)
	}
}

func TestFirewallRuleZoneWithoutNetwork(t *testing.T) {
	c := baseConfig()
	c.FirewallRules = []models.FirewallRule{
		{ID: "r1", Name: "orphan", SourceZone: "DMZ", DestZone: "WAN",
			Protocol: "udp", Ports: []models.PortRange{{Start: 53, End: 53}},
			Action: models.ActionReject, Enabled: true},
	}
	s := mustGen(t, c)
	if !strings.Contains(s, "set dmz_ifaces") {
		t.Fatalf("referenced zone set missing:\n%s", s)
	}
}
