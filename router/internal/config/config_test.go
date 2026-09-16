package config

import (
	"os"
	"path/filepath"
	"testing"

	"router/pkg/models"
)

func TestDefaultConfigIsValid(t *testing.T) {
	c := Default()
	if errs := models.Validate(c); len(errs) != 0 {
		t.Fatalf("default config invalid: %v", errs)
	}
	if len(c.WANs) != 1 || c.WANs[0].Mode != models.WANModeDHCP {
		t.Fatal("default config should have one DHCP WAN")
	}
	if len(c.Networks) != 1 || c.Networks[0].Subnet != "192.168.1.1/24" {
		t.Fatal("default config should have LAN 192.168.1.1/24")
	}
	if !c.Networks[0].DHCP.Enabled {
		t.Fatal("default LAN should have DHCP enabled")
	}
}

func TestLoadJSONAndApplyDefaults(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	raw := `{"wans":[{"name":"wan","interface":"eth0","mode":"dhcp"}],
	"networks":[{"name":"lan","interface":"br-lan","subnet":"10.1.1.1/24","dhcp":{"enabled":true}}]}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WANs[0].ID != "wan" || !c.WANs[0].IsEnabled() {
		t.Fatalf("defaults not applied to wan: %+v", c.WANs[0])
	}
	if c.Networks[0].Zone != "LAN" {
		t.Fatalf("zone default missing: %+v", c.Networks[0])
	}
	if c.Networks[0].DHCP.Start != "10.1.1.100" || c.Networks[0].DHCP.End != "10.1.1.220" {
		t.Fatalf("dhcp pool default missing: %+v", c.Networks[0].DHCP)
	}
	if errs := models.Validate(c); len(errs) != 0 {
		t.Fatalf("after defaults config invalid: %v", errs)
	}
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	raw := `
wans:
  - name: wan
    interface: eth0
    mode: static
    static:
      address: 203.0.113.10/24
      gateway: 203.0.113.1
networks:
  - name: lan
    interface: br-lan
    subnet: 192.168.1.1/24
`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.WANs[0].Mode != models.WANModeStatic || c.WANs[0].Static.Gateway != "203.0.113.1" {
		t.Fatalf("yaml parse failed: %+v", c.WANs[0])
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(`{"wans":[{"name":"wan","interface":"eth0","mode":"carrier-pigeon"}]}`), 0o600)
	if _, err := LoadFile(p); err == nil {
		t.Fatal("expected validation error on load")
	}
}

func TestParseUnknownFieldsRejected(t *testing.T) {
	if _, err := Parse([]byte(`{"bogus":1}`), "x.json"); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	c := Default()
	c.Networks[0].Name = "office"
	dir := t.TempDir()
	p := filepath.Join(dir, "out.json")
	if err := SaveFile(p, c); err != nil {
		t.Fatal(err)
	}
	back, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.Networks[0].Name != "office" {
		t.Fatal("round trip failed")
	}
}
