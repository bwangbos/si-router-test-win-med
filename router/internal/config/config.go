// Package config loads, validates, and stores routerd configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"router/pkg/models"
)

// Default returns a valid out-of-the-box router configuration (design §54).
func Default() models.Config {
	enabled := true
	return models.Config{
		Version: 1,
		System:  models.SystemConfig{Hostname: "routerd"},
		WANs: []models.WAN{{
			ID: "wan", Name: "wan", Interface: "eth0", Mode: models.WANModeDHCP,
			Enabled: models.Bool(true), Metric: 50,
		}},
		Networks: []models.Network{{
			ID: "lan", Name: "lan", Interface: "br-lan", Subnet: "192.168.1.1/24", Zone: "LAN",
			InternetAccess: &enabled, AccessToLAN: &enabled,
			DHCP: models.DHCPServer{
				Enabled: true, Start: "192.168.1.100", End: "192.168.1.220", LeaseSeconds: 86400,
			},
		}},
		DNS: models.DNSConfig{ListenPort: 53},
	}
}

// Parse decodes JSON or YAML configuration bytes and applies defaults.
// name is used only to pick the format (".yaml"/".yml" => YAML).
func Parse(data []byte, name string) (models.Config, error) {
	var c models.Config
	if strings.HasSuffix(strings.ToLower(name), ".yaml") || strings.HasSuffix(strings.ToLower(name), ".yml") {
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("parse yaml: %w", err)
		}
	} else {
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return c, fmt.Errorf("parse json: %w", err)
		}
	}
	ApplyDefaults(&c)
	if errs := models.Validate(c); len(errs) > 0 {
		return c, fmt.Errorf("invalid configuration: %s", models.ErrorList(errs))
	}
	return c, nil
}

// LoadFile loads a configuration file (JSON or YAML by extension).
func LoadFile(path string) (models.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return models.Config{}, err
	}
	c, err := Parse(data, path)
	if err != nil {
		return c, err
	}
	if c.System.Hostname == "" {
		c.System.Hostname = "routerd"
	}
	return c, nil
}

// SaveFile writes canonical JSON configuration atomically.
func SaveFile(path string, c models.Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ApplyDefaults fills in optional fields with sane values.
func ApplyDefaults(c *models.Config) {
	if c.Version == 0 {
		c.Version = 1
	}
	if c.System.Hostname == "" {
		c.System.Hostname = "routerd"
	}
	for i := range c.WANs {
		w := &c.WANs[i]
		if w.ID == "" {
			w.ID = w.Name
		}
		if w.Enabled == nil {
			w.Enabled = models.Bool(true)
		}
		if w.Mode == "" {
			w.Mode = models.WANModeDHCP
		}
		if w.Metric == 0 {
			w.Metric = 50 + i*10
		}
		if w.IPv6Mode == "" {
			w.IPv6Mode = "auto"
		}
	}
	for i := range c.Networks {
		n := &c.Networks[i]
		if n.ID == "" {
			n.ID = n.Name
		}
		if n.Zone == "" {
			n.Zone = strings.ToUpper(n.Name)
		}
		if n.DHCP.Enabled {
			if n.DHCP.LeaseSeconds == 0 {
				n.DHCP.LeaseSeconds = 86400
			}
			if n.DHCP.Start == "" || n.DHCP.End == "" {
				if s, e, err := defaultPool(n.Subnet); err == nil {
					if n.DHCP.Start == "" {
						n.DHCP.Start = s
					}
					if n.DHCP.End == "" {
						n.DHCP.End = e
					}
				}
			}
			if len(n.DHCP.DNS) == 0 {
				n.DHCP.DNS = []string{gatewayOf(n.Subnet)}
			}
		}
		if n.Interface == "" && n.VLAN != nil {
			n.Interface = fmt.Sprintf("%s.v%d", n.VLAN.Parent, n.VLAN.ID)
		}
	}
	if c.DNS.ListenPort == 0 {
		c.DNS.ListenPort = 53
	}
	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = []string{} // empty means use WAN-provided DNS
	}
}

// defaultPool proposes .100-.220 within the given subnet CIDR (clamped).
func defaultPool(subnet string) (string, string, error) {
	c, err := netip.ParsePrefix(subnet)
	if err != nil || !c.Addr().Is4() {
		return "", "", fmt.Errorf("invalid IPv4 subnet")
	}
	net0 := c.Masked().Addr()
	base := u32(net0)
	size := uint32(1) << (32 - c.Bits())
	last := base + size - 2 // exclude broadcast
	start := minU(base+100, last-1)
	end := minU(base+220, last)
	if end <= start {
		return "", "", fmt.Errorf("subnet too small")
	}
	return ipU32(start).String(), ipU32(end).String(), nil
}

// gatewayOf returns the network address + 1 (the router address convention).
func gatewayOf(subnet string) string {
	c, err := netip.ParsePrefix(subnet)
	if err != nil {
		return ""
	}
	return ipU32(u32(c.Masked().Addr()) + 1).String()
}

func u32(a netip.Addr) uint32 {
	b := a.AsSlice()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func ipU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func minU(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
