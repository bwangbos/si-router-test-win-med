package main

import (
	"encoding/json"
	"strings"
	"testing"

	"router/pkg/models"
)

func TestParseArgs(t *testing.T) {
	got, flags := parseArgs([]string{"networks", "add", "--name", "iot", "--subnet", "10.0.0.1/24", "--vlan", "20"})
	if strings.Join(got, ",") != "networks,add" {
		t.Fatalf("positionals: %v", got)
	}
	if flags["name"] != "iot" || flags["subnet"] != "10.0.0.1/24" || flags["vlan"] != "20" {
		t.Fatalf("flags: %v", flags)
	}
}

func TestGlobalFlags(t *testing.T) {
	rest, flags := parseArgs([]string{"--server", "http://x:1", "--token", "abc", "status"})
	if flags["server"] != "http://x:1" || flags["token"] != "abc" {
		t.Fatalf("global flags lost: %v", flags)
	}
	if strings.Join(rest, ",") != "status" {
		t.Fatalf("rest: %v", rest)
	}
}

func TestBuildNetworkFromFlags(t *testing.T) {
	n, err := networkFromFlags(map[string]string{
		"name": "iot", "subnet": "192.168.20.1/24", "parent": "eth1", "vlan": "20",
		"dhcp": "true", "bridge": "br-iot", "internet": "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n.Name != "iot" || n.Subnet != "192.168.20.1/24" || n.Interface != "br-iot" {
		t.Fatalf("network: %+v", n)
	}
	if n.VLAN == nil || n.VLAN.Parent != "eth1" || n.VLAN.ID != 20 {
		t.Fatalf("vlan: %+v", n.VLAN)
	}
	if !n.DHCP.Enabled {
		t.Fatal("dhcp should be enabled")
	}
	if n.InternetAccess == nil || *n.InternetAccess {
		t.Fatal("internet should be disabled")
	}
	errs := models.Validate(attachNetwork(models.Config{
		WANs: []models.WAN{{Name: "wan", Interface: "eth0", Mode: models.WANModeDHCP}},
	}, n))
	if len(errs) != 0 {
		t.Fatalf("network should validate: %v", errs)
	}
}

func TestFormatTable(t *testing.T) {
	rows := [][]string{
		{"NAME", "SUBNET"},
		{"lan", "192.168.1.1/24"},
		{"iot-long-name", "10.0.0.1/8"},
	}
	out := formatTable(rows)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %d", len(lines))
	}
	if !strings.Contains(lines[1], "lan") || !strings.Contains(lines[2], "iot-long-name") {
		t.Fatalf("content: %s", out)
	}
	// columns aligned: same prefix width for header col2 and row col2
	col2 := func(l string) int { return strings.Index(l, "SUBNET") }
	if col2(lines[0]) != strings.Index(lines[1], "192") || col2(lines[0]) != strings.Index(lines[2], "10.") {
		t.Fatalf("not aligned:\n%s", out)
	}
}

func TestFormatJSONPassthrough(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(`{"a":1}`), &v); err != nil {
		t.Fatal(err)
	}
	s := formatJSON(v)
	if !strings.Contains(s, `"a"`) {
		t.Fatal("json format")
	}
}

func TestParseArgsBoolFlags(t *testing.T) {
	pos, flags := parseArgs([]string{"--insecure", "networks", "list"})
	if len(pos) != 2 || pos[0] != "networks" || pos[1] != "list" {
		t.Fatalf("pos=%v", pos)
	}
	if flags["insecure"] != "true" {
		t.Fatalf("flags=%v", flags)
	}
	pos, _ = parseArgs([]string{"networks", "add", "--name", "guest", "--dhcp", "--start", "1.2.3.4"})
	if flags["dhcp"] != "true" && true {
		_, f2 := parseArgs([]string{"networks", "add", "--name", "g", "--dhcp", "--start", "x"})
		if f2["dhcp"] != "true" || f2["start"] != "x" {
			t.Fatalf("f2=%v", f2)
		}
	}
	_ = pos
}

func TestNetworkFlagsMemberAndAliases(t *testing.T) {
	pos, f := parseArgs([]string{"networks", "add", "--name", "g", "--subnet", "10.0.0.1/24",
		"--member", "lan1,lan2", "--dhcp", "--start", "10.0.0.10", "--end", "10.0.0.20"})
	_ = pos
	n, err := networkFromFlags(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Members) != 2 || n.Members[0] != "lan1" {
		t.Fatalf("members=%v", n.Members)
	}
	if n.DHCP.Start != "10.0.0.10" || n.DHCP.End != "10.0.0.20" {
		t.Fatalf("pool=%v-%v (aliases --start/--end not honored)", n.DHCP.Start, n.DHCP.End)
	}
	_, f = parseArgs([]string{"firewall", "add", "--name", "x", "--src-zone", "GUEST", "--dst-zone", "WAN", "--dport", "53"})
	if f["src"] != "GUEST" || f["ports"] != "53" {
		t.Fatalf("firewall aliases not applied: %v", f)
	}
}
