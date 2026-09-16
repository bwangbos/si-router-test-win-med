package models

import "testing"

func minimalConfig() Config {
	return Config{
		Version: 1,
		WANs: []WAN{{
			ID: "wan1", Name: "wan", Interface: "eth0", Mode: WANModeDHCP, Enabled: Bool(true), Metric: 50,
		}},
		Networks: []Network{{
			ID: "lan", Name: "lan", Interface: "br-lan", Subnet: "192.168.1.1/24", Zone: "LAN",
			DHCP: DHCPServer{Enabled: true, Start: "192.168.1.100", End: "192.168.1.220", LeaseSeconds: 86400},
		}},
	}
}

func TestValidMinimalConfig(t *testing.T) {
	errs := Validate(minimalConfig())
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %v", errs)
	}
}

func TestValidateRequiresWAN(t *testing.T) {
	c := minimalConfig()
	c.WANs = nil
	errs := Validate(c)
	if len(errs) == 0 {
		t.Fatal("expected error for missing WAN")
	}
}

func TestValidateWANModes(t *testing.T) {
	c := minimalConfig()
	c.WANs[0].Mode = "token-ring"
	errs := Validate(c)
	if countFor(errs, "wans[0].mode") == 0 {
		t.Fatalf("expected mode error, got %v", errs)
	}
}

func TestValidateWANStaticRequiresIP(t *testing.T) {
	c := minimalConfig()
	c.WANs[0].Mode = WANModeStatic
	errs := Validate(c)
	if countFor(errs, "wans[0].static") == 0 {
		t.Fatalf("expected static error, got %v", errs)
	}
	c.WANs[0].Static = &StaticWAN{Address: "198.51.100.5/24", Gateway: "198.51.100.1"}
	if errs := Validate(c); len(errs) != 0 {
		t.Fatalf("expected valid static WAN, got %v", errs)
	}
	c.WANs[0].Static.Address = "198.51.100.5" // missing prefix len
	errs2 := Validate(c)
	if countFor(errs2, "wans[0].static.address") == 0 {
		t.Fatalf("expected address CIDR error, got %v", errs2)
	}
}

func TestValidateDHCPRangeInSubnet(t *testing.T) {
	c := minimalConfig()
	c.Networks[0].DHCP.Start = "10.0.0.1"
	errs := Validate(c)
	if countFor(errs, "networks[0].dhcp.start") == 0 {
		t.Fatalf("expected dhcp range error, got %v", errs)
	}
}

func TestValidateDHCPRangeOrder(t *testing.T) {
	c := minimalConfig()
	c.Networks[0].DHCP.Start = "192.168.1.200"
	c.Networks[0].DHCP.End = "192.168.1.100"
	if countFor(Validate(c), "networks[0].dhcp.end") == 0 {
		t.Fatal("expected end<start error")
	}
}

func TestValidateDHCPReservations(t *testing.T) {
	c := minimalConfig()
	c.Networks[0].DHCP.Reservations = []DHCPReservation{{Name: "tv", MAC: "00:11:22:33:44:55", IP: "192.168.9.9"}}
	if countFor(Validate(c), "reservations[0].ip") == 0 {
		t.Fatal("expected reservation out-of-subnet error")
	}
	c.Networks[0].DHCP.Reservations[0].IP = "192.168.1.50"
	c.Networks[0].DHCP.Reservations[0].MAC = "not-a-mac"
	if countFor(Validate(c), "reservations[0].mac") == 0 {
		t.Fatal("expected mac format error")
	}
}

func TestValidateNetworkSubnet(t *testing.T) {
	c := minimalConfig()
	c.Networks[0].Subnet = "192.168.1.1"
	if countFor(Validate(c), "networks[0].subnet") == 0 {
		t.Fatal("expected subnet CIDR error")
	}
	c.Networks[0].Subnet = "192.168.1.1/24/24"
	if len(Validate(c)) == 0 {
		t.Fatal("expected invalid CIDR error")
	}
}

func TestValidateDuplicateNetworkNames(t *testing.T) {
	c := minimalConfig()
	n := c.Networks[0]
	n.ID = "lan2"
	c.Networks = append(c.Networks, n)
	if countFor(Validate(c), "duplicate") == 0 {
		t.Fatal("expected duplicate name error")
	}
}

func TestValidateOverlappingSubnets(t *testing.T) {
	c := minimalConfig()
	c.Networks = append(c.Networks, Network{
		ID: "iot", Name: "iot", Interface: "br-iot", Subnet: "192.168.1.1/25", Zone: "IOT",
	})
	errs := Validate(c)
	found := false
	for _, e := range errs {
		if contains(e.Message, "overlap") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected overlap error, got %v", errs)
	}
}

func TestValidateVLANRange(t *testing.T) {
	c := minimalConfig()
	c.Networks[0].VLAN = &VLANConfig{Parent: "eth1", ID: 4095}
	if countFor(Validate(c), "vlan.id") == 0 {
		t.Fatal("expected vlan id range error")
	}
	c.Networks[0].VLAN.ID = 0
	if countFor(Validate(c), "vlan.id") == 0 {
		t.Fatal("expected vlan id range error for 0")
	}
}

func TestValidateDuplicateVLAN(t *testing.T) {
	c := minimalConfig()
	c.Networks[0].VLAN = &VLANConfig{Parent: "eth1", ID: 20}
	c.Networks = append(c.Networks, Network{
		ID: "iot", Name: "iot", Interface: "eth1.20", Subnet: "192.168.20.1/24", Zone: "IOT",
		VLAN: &VLANConfig{Parent: "eth1", ID: 20},
	})
	if countFor(Validate(c), "vlan") == 0 {
		t.Fatal("expected duplicate vlan error")
	}
}

func TestValidateFirewallRules(t *testing.T) {
	c := minimalConfig()
	c.FirewallRules = []FirewallRule{
		{ID: "r1", Name: "allow-dns", SourceZone: "WAN", DestZone: "LAN", Protocol: "grpc", Action: ActionAccept},
		{ID: "r1", Name: "dup", SourceZone: "LAN", DestZone: "WAN", Protocol: "tcp", Action: "frolic"},
	}
	errs := Validate(c)
	if countFor(errs, "protocol") == 0 {
		t.Fatal("expected protocol error")
	}
	if countFor(errs, "action") == 0 {
		t.Fatal("expected action error")
	}
	if countFor(errs, "duplicate") == 0 {
		t.Fatal("expected duplicate rule id error")
	}
}

func TestValidateFirewallRuleAddressesAndPorts(t *testing.T) {
	c := minimalConfig()
	c.FirewallRules = []FirewallRule{{
		ID: "r1", SourceZone: "LAN", DestZone: "WAN", Protocol: "tcp", Action: ActionAccept,
		Source: []string{"999.1.1.1/24"},
		Ports:  []PortRange{{Start: 4000, End: 1000}},
	}}
	errs := Validate(c)
	if countFor(errs, "source[0]") == 0 {
		t.Fatal("expected bad source prefix error")
	}
	if countFor(errs, "ports[0]") == 0 {
		t.Fatal("expected bad port error")
	}
}

func TestValidatePortForwards(t *testing.T) {
	c := minimalConfig()
	c.PortForwards = []PortForward{
		{ID: "pf1", Name: "https", WAN: "nope", Protocol: "tcp", ExternalPort: 443, InternalIP: "192.168.40.10", InternalPort: 443},
		{ID: "pf2", Protocol: "udp", ExternalPort: 0, InternalIP: "bad", InternalPort: 80},
	}
	errs := Validate(c)
	if countFor(errs, "wans") == 0 && countFor(errs, "wan") == 0 {
		t.Fatalf("expected unknown wan error, got %v", errs)
	}
	if countFor(errs, "external_port") == 0 {
		t.Fatal("expected external port error")
	}
	if countFor(errs, "internal_ip") == 0 {
		t.Fatal("expected internal ip error")
	}
}

func TestValidateWireGuard(t *testing.T) {
	c := minimalConfig()
	c.WireGuard = []WireGuardTunnel{{
		Name: "wg-vpn", ListenPort: 70000, Address: "10.8.0.1/24",
		Peers: []WireGuardPeer{{Name: "laptop", PublicKey: "not-a-key", AllowedIPs: []string{"bogus"}}},
	}}
	errs := Validate(c)
	if countFor(errs, "listen_port") == 0 {
		t.Fatal("expected listen port error")
	}
	if countFor(errs, "peers[0].public_key") == 0 {
		t.Fatal("expected public key error")
	}
	if countFor(errs, "peers[0].allowed_ips[0]") == 0 {
		t.Fatal("expected allowed ips error")
	}
}

func TestValidateDuplicateInterfaceUse(t *testing.T) {
	c := minimalConfig()
	c.WANs = append(c.WANs, WAN{ID: "wan2", Name: "wan2", Interface: "eth0", Mode: WANModeDHCP, Enabled: Bool(true)})
	if countFor(Validate(c), "interface") == 0 {
		t.Fatal("expected duplicate interface usage error")
	}
}

func TestValidateSystem(t *testing.T) {
	c := minimalConfig()
	c.System = SystemConfig{Hostname: "bad host!", NTPServers: []string{"not a server"}}
	errs := Validate(c)
	if countFor(errs, "system.hostname") == 0 {
		t.Fatal("expected hostname error")
	}
	if countFor(errs, "system.ntp") == 0 {
		t.Fatal("expected ntp error")
	}
}

func TestValidateDNSConfig(t *testing.T) {
	c := minimalConfig()
	c.DNS = DNSConfig{Upstreams: []string{"999.999.999.999"}, LocalRecords: []DNSRecord{{Name: "router.local", IP: "nonsense"}}}
	errs := Validate(c)
	if countFor(errs, "dns.upstreams[0]") == 0 {
		t.Fatal("expected upstream error")
	}
	if countFor(errs, "dns.local_records[0]") == 0 {
		t.Fatal("expected local record error")
	}
}

func TestValidateTrafficPolicy(t *testing.T) {
	c := minimalConfig()
	c.TrafficPolicies = []TrafficPolicy{{Name: "wan1", Interface: "eth0", UpMbps: -5, DownMbps: 100, SQM: true, Qdisc: "bogus"}}
	errs := Validate(c)
	if countFor(errs, "up_mbps") == 0 {
		t.Fatal("expected up_mbps error")
	}
	if countFor(errs, "qdisc") == 0 {
		t.Fatal("expected qdisc error")
	}
}

func TestValidateStaticRoutes(t *testing.T) {
	c := minimalConfig()
	c.StaticRoutes = []StaticRoute{
		{ID: "r1", Destination: "10.0.0.0/8", Via: "192.168.1.254"},
		{ID: "r2", Destination: "invalid", Via: "1.1.1.1"},
	}
	errs := Validate(c)
	if countFor(errs, "static_routes[1]") == 0 {
		t.Fatal("expected route destination error")
	}
	c2 := minimalConfig()
	c2.StaticRoutes = []StaticRoute{{ID: "r1", Destination: "10.0.0.0/8"}}
	if countFor(Validate(c2), "via") == 0 && countFor(Validate(c2), "device") == 0 {
		t.Fatal("expected route needs via or device")
	}
}

func TestValidationErrorString(t *testing.T) {
	e := ValidationError{Field: "networks[0].subnet", Message: "bad"}
	if got := e.Error(); got != "networks[0].subnet: bad" {
		t.Fatalf("got %q", got)
	}
}

func countFor(errs []ValidationError, substr string) int {
	n := 0
	for _, e := range errs {
		if contains(e.Field, substr) || contains(e.Message, substr) {
			n++
		}
	}
	return n
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
