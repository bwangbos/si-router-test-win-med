package dhcp

import (
	"strings"
	"testing"

	"router/pkg/models"
)

func conf(t *testing.T, c models.Config) string {
	t.Helper()
	s, err := GenerateDnsmasqConf(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func base() models.Config {
	return models.Config{
		WANs: []models.WAN{{Name: "wan", Interface: "eth0", Mode: models.WANModeDHCP, Enabled: models.Bool(true)}},
		Networks: []models.Network{
			{ID: "lan", Name: "lan", Interface: "br-lan", Subnet: "192.168.1.1/24", Zone: "LAN",
				DHCP: models.DHCPServer{Enabled: true, Start: "192.168.1.100", End: "192.168.1.220", LeaseSeconds: 7200,
					DNS:          []string{"192.168.1.1"},
					Reservations: []models.DHCPReservation{{Name: "tv", MAC: "00:11:22:33:44:55", IP: "192.168.1.50"}}}},
			{ID: "mgmt", Name: "mgmt", Interface: "br-mgmt", Subnet: "10.9.9.1/24", Zone: "MGMT",
				DHCP: models.DHCPServer{Enabled: false}},
		},
		DNS: models.DNSConfig{Upstreams: []string{"1.1.1.1", "8.8.8.8:5353"}, ListenPort: 53,
			LocalRecords: []models.DNSRecord{{Name: "gw.home.arpa", IP: "192.168.1.1"}}},
	}
}

func TestDnsmasqBasic(t *testing.T) {
	s := conf(t, base())
	for _, want := range []string{
		"interface=br-lan",
		"interface=br-mgmt",
		"no-dhcp-interface=br-mgmt",
		"dhcp-range=lan,192.168.1.100,192.168.1.220,7200",
		"dhcp-host=00:11:22:33:44:55,tv,192.168.1.50",
		"dhcp-option=3,192.168.1.1",
		"dhcp-option=6,192.168.1.1",
		"server=1.1.1.1",
		"server=8.8.8.8#5353",
		"address=/gw.home.arpa/192.168.1.1",
		"no-resolv",
		"domain-needed",
		"bogus-priv",
		"dhcp-authoritative",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "dhcp-range=mgmt") {
		t.Fatal("dhcp disabled network must have no range")
	}
}

func TestDnsmasqDefaultUpstreams(t *testing.T) {
	c := base()
	c.DNS.Upstreams = nil
	s := conf(t, c)
	if !strings.Contains(s, "server=1.1.1.1") || !strings.Contains(s, "server=8.8.8.8") {
		t.Fatalf("expected default upstreams:\n%s", s)
	}
	if strings.Contains(s, "no-resolv") == false {
		t.Fatal("no-resolv still required")
	}
}

func TestDnsmasqListenPort(t *testing.T) {
	c := base()
	c.DNS.ListenPort = 5353
	s := conf(t, c)
	if !strings.Contains(s, "port=5353") {
		t.Fatal("custom port missing")
	}
}

func TestDnsmasqIPv6RA(t *testing.T) {
	c := base()
	c.Networks[0].IPv6Subnet = "fd12:3456::1/64"
	c.Networks[0].IPv6RA = true
	s := conf(t, c)
	if !strings.Contains(s, "dhcp-range=fd12:3456::,slaac") {
		t.Fatalf("slaac line missing:\n%s", s)
	}
}

func TestLeaseFilePath(t *testing.T) {
	if LeaseFilePath() == "" {
		t.Fatal("lease file path required")
	}
}

func TestDnsmasqAddnMasqPrecedence(t *testing.T) {
	s := conf(t, base())
	if !strings.HasPrefix(s, "addn-hosts=") && !strings.Contains(s, "\naddn-hosts=/etc/hosts\n") {
		t.Fatal("addn-hosts missing (required for /etc/hosts precedence when auth-file replaces main config)")
	}
}

func TestDnsmasqExceptLo(t *testing.T) {
	s := conf(t, base())
	if !strings.Contains(s, "except-interface=lo") {
		t.Fatal("loopback must be excluded so stub resolvers on lo cannot collide")
	}
}

func TestUnitFile(t *testing.T) {
	u := UnitFile("/etc/dnsmasq.d/router.conf")
	for _, want := range []string{"routerd managed", "--conf-file=", "--conf-file=/etc/dnsmasq.d/router.conf", "ExecStart=/usr/sbin/dnsmasq"} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q:\n%s", want, u)
		}
	}
}
