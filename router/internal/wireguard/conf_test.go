package wireguard

import (
	"strings"
	"testing"

	"router/pkg/models"
)

func TestGenerateConf(t *testing.T) {
	tn := models.WireGuardTunnel{
		Name: "wg-vpn", PrivateKey: "aKey==", ListenPort: 51820, Address: "10.8.0.1/24",
		Peers: []models.WireGuardPeer{
			{Name: "laptop", PublicKey: "PubKey1==", AllowedIPs: []string{"10.8.0.2/32"}, PersistentKeepalive: 25},
			{Name: "siteB", PublicKey: "PubKey2==", AllowedIPs: []string{"10.20.0.0/24"}, Endpoint: "203.0.113.9:51820"},
		},
	}
	conf, err := GenerateConf(tn)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[Interface]", "PrivateKey = aKey==", "ListenPort = 51820",
		"[Peer]", "PublicKey = PubKey1==", "AllowedIPs = 10.8.0.2/32",
		"PersistentKeepalive = 25", "Endpoint = 203.0.113.9:51820",
		"PublicKey = PubKey2==", "AllowedIPs = 10.20.0.0/24",
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in:\n%s", want, conf)
		}
	}
	// peers must be separated
	if strings.Count(conf, "[Peer]") != 2 {
		t.Fatal("expected 2 peers")
	}
}

func TestGenerateConfDefaults(t *testing.T) {
	conf, err := GenerateConf(models.WireGuardTunnel{Name: "wg0", PrivateKey: "k=="})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, "ListenPort = 51820") {
		t.Fatal("default listen port")
	}
}

func TestMaskKeys(t *testing.T) {
	tn := models.WireGuardTunnel{Name: "wg0", PrivateKey: "supersecretkey=="}
	m := Mask(tn)
	if m.PrivateKey != "***" {
		t.Fatalf("private key leaked: %+v", m)
	}
	if m.Name != "wg0" {
		t.Fatal("other fields preserved")
	}
}

func TestIfaceName(t *testing.T) {
	if IfaceName("wg-vpn") != "wg-vpn" {
		t.Fatal("already wg-prefixed")
	}
	if IfaceName("vpn") != "wg-vpn" {
		t.Fatal("prefix added")
	}
}
