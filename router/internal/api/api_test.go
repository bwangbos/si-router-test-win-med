package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"router/internal/platform"
	"router/pkg/models"
)

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	token string
	f     *platform.Fake
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	f := platform.NewFake([]string{"eth0", "eth1", "eth2"})
	ln, err := NewTestEnv(t.TempDir(), f, "testpw")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(ln.Handler())
	t.Cleanup(ts.Close)
	h := &harness{t: t, srv: ts, f: f}
	code, body := h.do(http.MethodPost, "/api/v1/auth/login",
		map[string]string{"username": "admin", "password": "testpw"}, "")
	if code != 200 {
		t.Fatalf("login: %d %s", code, body)
	}
	var lr struct {
		Token string `json:"token"`
	}
	json.Unmarshal(body, &lr)
	if lr.Token == "" {
		t.Fatal("no token")
	}
	h.token = lr.Token
	return h
}

func (h *harness) do(method, path string, body any, token string) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("bad json: %v: %s", err, b)
	}
	return m
}

func TestAuthRequired(t *testing.T) {
	h := newHarness(t)
	if code, _ := h.do("GET", "/api/v1/system", nil, ""); code != 401 {
		t.Fatalf("want 401 got %d", code)
	}
	if code, _ := h.do("GET", "/api/v1/system", nil, "bogus"); code != 401 {
		t.Fatalf("want 401 for bogus token got %d", code)
	}
	if code, _ := h.do("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "nope"}, ""); code != 401 {
		t.Fatalf("bad login should be 401 got %d", code)
	}
}

func TestWhoamiAndSystem(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/auth/whoami", nil, h.token)
	if code != 200 {
		t.Fatalf("whoami %d", code)
	}
	m := decode(t, body)
	if m["user"] != "admin" || m["role"] != "admin" {
		t.Fatalf("whoami wrong: %v", m)
	}
	code, body = h.do("GET", "/api/v1/system", nil, h.token)
	m = decode(t, body)
	if code != 200 || m["hostname"] != "routerd" {
		t.Fatalf("system wrong: %d %v", code, m)
	}
	if _, ok := m["version"]; !ok {
		t.Fatal("version missing")
	}
	if m["revision"].(float64) < 1 {
		t.Fatal("revision missing")
	}
}

func TestInterfacesEndpoint(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/interfaces", nil, h.token)
	if code != 200 {
		t.Fatalf("interfaces: %d", code)
	}
	var ifaces []map[string]any
	json.Unmarshal(body, &ifaces)
	var haveEth0 bool
	for _, i := range ifaces {
		if i["name"] == "eth0" {
			haveEth0 = true
			if _, ok := i["stats"]; !ok {
				t.Fatal("stats missing")
			}
		}
	}
	if !haveEth0 {
		t.Fatalf("eth0 missing: %s", body)
	}
	code, body = h.do("GET", "/api/v1/interfaces/eth0", nil, h.token)
	if code != 200 {
		t.Fatalf("iface by name: %d %s", code, body)
	}
	code, _ = h.do("GET", "/api/v1/interfaces/ghost", nil, h.token)
	if code != 404 {
		t.Fatalf("ghost want 404 got %d", code)
	}
}

func TestNetworkCRUDApply(t *testing.T) {
	h := newHarness(t)
	// list initial
	code, body := h.do("GET", "/api/v1/networks", nil, h.token)
	if code != 200 {
		t.Fatalf("networks: %d", code)
	}
	var nets []models.Network
	json.Unmarshal(body, &nets)
	if len(nets) != 1 || nets[0].Name != "lan" {
		t.Fatalf("want 1 lan network, got %s", body)
	}
	// add iot network
	newNet := models.Network{
		Name: "iot", Interface: "br-iot", Subnet: "192.168.20.1/24", Zone: "IOT",
		VLAN: &models.VLANConfig{Parent: "eth2", ID: 20},
		DHCP: models.DHCPServer{Enabled: true},
	}
	code, body = h.do("POST", "/api/v1/networks", newNet, h.token)
	if code != 201 {
		t.Fatalf("add network: %d %s", code, body)
	}
	// the fake system must now have br-iot and the vlan
	names := h.f.LinkNames()
	if !strIn(names, "br-iot") || !strIn(names, "eth2.20") {
		t.Fatalf("links not created via API: %v", names)
	}
	// revision bumped
	_, body = h.do("GET", "/api/v1/system", nil, h.token)
	if decode(t, body)["revision"].(float64) < 2 {
		t.Fatalf("revision not bumped: %s", body)
	}
	// patch it
	_, body = h.do("GET", "/api/v1/networks/iot", nil, h.token)
	var got models.Network
	json.Unmarshal(body, &got)
	got.Subnet = "192.168.21.1/24"
	got.DHCP.Start = ""
	got.DHCP.End = "" // re-derived from the new subnet by defaults
	code, body = h.do("PATCH", "/api/v1/networks/iot", got, h.token)
	if code != 200 {
		t.Fatalf("patch: %d %s", code, body)
	}
	addrs, _ := h.f.File("/etc/dnsmasq.d/router.conf")
	if !strings.Contains(string(addrs), "192.168.21") {
		t.Fatalf("dnsmasq conf not regenerated: %s", addrs)
	}
	// delete
	code, _ = h.do("DELETE", "/api/v1/networks/iot", nil, h.token)
	if code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if strIn(h.f.LinkNames(), "br-iot") {
		t.Fatal("link still present after delete")
	}
}

func TestInvalidConfigRejected400(t *testing.T) {
	h := newHarness(t)
	bad := models.Network{Name: "bad", Interface: "br-bad", Subnet: "not-a-cidr", Zone: "BAD"}
	code, body := h.do("POST", "/api/v1/networks", bad, h.token)
	if code != 400 {
		t.Fatalf("want 400 got %d: %s", code, body)
	}
	if !strings.Contains(string(body), "subnet") {
		t.Fatalf("error should mention field: %s", body)
	}
}

func TestFirewallRuleCRUD(t *testing.T) {
	h := newHarness(t)
	rule := models.FirewallRule{ID: "allow-ssh", Name: "ssh from lan", SourceZone: "LAN", DestZone: "IOT",
		Protocol: "tcp", Ports: []models.PortRange{{Start: 22, End: 22}}, Action: models.ActionAccept, Enabled: true}
	code, body := h.do("POST", "/api/v1/firewall/rules", rule, h.token)
	if code != 201 {
		t.Fatalf("add rule: %d %s", code, body)
	}
	code, body = h.do("GET", "/api/v1/firewall/rules", nil, h.token)
	var rules []models.FirewallRule
	json.Unmarshal(body, &rules)
	if code != 200 || len(rules) != 1 {
		t.Fatalf("list: %d %s", code, body)
	}
	script := h.f.NftScript()
	if !strings.Contains(script, "tcp dport 22") {
		t.Fatalf("rule not in nft script: %s", script)
	}
	code, _ = h.do("DELETE", "/api/v1/firewall/rules/allow-ssh", nil, h.token)
	if code != 200 {
		t.Fatalf("delete rule: %d", code)
	}
	if strings.Contains(h.f.NftScript(), "tcp dport 22") {
		t.Fatal("rule still in script after delete")
	}
}

func TestPortForwardCRUD(t *testing.T) {
	h := newHarness(t)
	pf := models.PortForward{Name: "https", WAN: "wan", Protocol: "tcp", ExternalPort: 8443,
		InternalIP: "192.168.1.50", InternalPort: 443, Enabled: true}
	code, body := h.do("POST", "/api/v1/portforwards", pf, h.token)
	if code != 201 {
		t.Fatalf("add pf: %d %s", code, body)
	}
	if !strings.Contains(h.f.NftScript(), "dport 8443") {
		t.Fatal("dnat rule missing")
	}
	code, body = h.do("GET", "/api/v1/portforwards", nil, h.token)
	var pfs []models.PortForward
	json.Unmarshal(body, &pfs)
	if code != 200 || len(pfs) != 1 || pfs[0].ID == "" {
		t.Fatalf("list pfs: %d %s", code, body)
	}
	code, _ = h.do("DELETE", "/api/v1/portforwards/"+pfs[0].ID, nil, h.token)
	if code != 200 {
		t.Fatalf("delete pf: %d", code)
	}
}

func TestWireGuardEndpointMasksKeys(t *testing.T) {
	h := newHarness(t)
	tun := models.WireGuardTunnel{
		Name: "wg-vpn", PrivateKey: "supersecretprivkey=", ListenPort: 51820, Address: "10.8.0.1/24",
		Peers: []models.WireGuardPeer{{Name: "laptop", PublicKey: strings.Repeat("B", 43) + "=",
			AllowedIPs: []string{"10.8.0.2/32"}}},
	}
	code, body := h.do("POST", "/api/v1/wireguard/tunnels", tun, h.token)
	if code != 201 {
		t.Fatalf("add tunnel: %d %s", code, body)
	}
	code, body = h.do("GET", "/api/v1/wireguard/tunnels", nil, h.token)
	if strings.Contains(string(body), "supersecretprivkey") {
		t.Fatal("private key leaked via API")
	}
	if !strings.Contains(string(body), "laptop") {
		t.Fatalf("peer missing: %s", body)
	}
	if !strIn(h.f.LinkNames(), "wg-vpn") {
		t.Fatalf("wg link not created: %v", h.f.LinkNames())
	}
	if !strings.Contains(h.f.WGConfig("wg-vpn"), "supersecretprivkey") {
		t.Fatal("wg conf not synced")
	}
}

func TestWANAndDevicesAndEvents(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/wan/status", nil, h.token)
	if code != 200 {
		t.Fatalf("wan: %d", code)
	}
	var st []map[string]any
	json.Unmarshal(body, &st)
	if len(st) != 1 || st[0]["up"].(bool) {
		t.Fatalf("wan status wrong: %s", body)
	}
	h.f.SimulateWANUp("eth0", "198.51.100.9/24", "198.51.100.1", []string{"9.9.9.9"})
	code, body = h.do("GET", "/api/v1/wan/status", nil, h.token)
	json.Unmarshal(body, &st)
	if !st[0]["up"].(bool) {
		t.Fatalf("wan up not reflected: %s", body)
	}
	h.f.SimulateLease("br-lan", "192.168.1.77", "11:22:33:44:55:66", "phone", 600)
	code, body = h.do("GET", "/api/v1/devices", nil, h.token)
	var devs []map[string]any
	json.Unmarshal(body, &devs)
	if code != 200 || len(devs) != 1 || devs[0]["ipv4"] != "192.168.1.77" {
		t.Fatalf("devices: %d %s", code, body)
	}
	// name it
	code, body = h.do("PUT", "/api/v1/devices/11:22:33:44:55:66", map[string]string{"name": "My Phone"}, h.token)
	if code != 200 {
		t.Fatalf("name device: %d %s", code, body)
	}
	_, body = h.do("GET", "/api/v1/devices", nil, h.token)
	json.Unmarshal(body, &devs)
	if devs[0]["name"] != "My Phone" {
		t.Fatalf("alias not stored: %s", body)
	}
	code, body = h.do("GET", "/api/v1/events", nil, h.token)
	var evs []map[string]any
	json.Unmarshal(body, &evs)
	if code != 200 || len(evs) == 0 {
		t.Fatalf("events empty: %d %s", code, body)
	}
}

func TestConfigEndpointsAndValidate(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/config", nil, h.token)
	if code != 200 {
		t.Fatal(code)
	}
	var cfg models.Config
	json.Unmarshal(body, &cfg)
	cfg.System.Hostname = "gateway01"
	code, body = h.do("PUT", "/api/v1/config", cfg, h.token)
	if code != 200 {
		t.Fatalf("put config: %d %s", code, body)
	}
	_, body = h.do("GET", "/api/v1/system", nil, h.token)
	if decode(t, body)["hostname"] != "gateway01" {
		t.Fatal("hostname not applied")
	}
	code, body = h.do("POST", "/api/v1/config/validate", cfg, h.token)
	if code != 200 {
		t.Fatalf("validate ok: %d %s", code, body)
	}
	code, _ = h.do("POST", "/api/v1/config/validate", nil, h.token)
	if code == 200 {
		t.Fatal("nil config should fail validate")
	}
	// revisions visible
	code, body = h.do("GET", "/api/v1/config/revisions", nil, h.token)
	var revs []map[string]any
	json.Unmarshal(body, &revs)
	if code != 200 || len(revs) < 2 {
		t.Fatalf("revisions: %d %s", code, body)
	}
	// restore revision 1
	code, body = h.do("POST", "/api/v1/config/revisions/1/restore", nil, h.token)
	if code != 200 {
		t.Fatalf("restore: %d %s", code, body)
	}
	_, body = h.do("GET", "/api/v1/system", nil, h.token)
	if decode(t, body)["hostname"] != "routerd" {
		t.Fatal("restore did not apply")
	}
}

func TestConfirmedCommit(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/config", nil, h.token)
	var cfg models.Config
	json.Unmarshal(body, &cfg)
	cfg.System.Hostname = "confirmed-gw"
	// apply with confirmation window
	code, body = h.do("PUT", "/api/v1/config?confirm_seconds=60", cfg, h.token)
	if code != 202 {
		t.Fatalf("want 202 pending, got %d: %s", code, body)
	}
	m := decode(t, body)
	pending, ok := m["pending"].(map[string]any)
	if !ok || pending["commit_token"] == "" {
		t.Fatalf("no pending state: %s", body)
	}
	// commit
	code, body = h.do("POST", "/api/v1/config/commit", map[string]string{"commit_token": pending["commit_token"].(string)}, h.token)
	if code != 200 {
		t.Fatalf("commit: %d %s", code, body)
	}
	_, body = h.do("GET", "/api/v1/config", nil, h.token)
	json.Unmarshal(body, &cfg)
	if cfg.System.Hostname != "confirmed-gw" {
		t.Fatal("commit did not persist")
	}

	// now apply with short window and let it roll back
	code, body = h.do("GET", "/api/v1/config", nil, h.token)
	json.Unmarshal(body, &cfg)
	cfg.System.Hostname = "should-not-stick"
	code, _ = h.do("PUT", "/api/v1/config?confirm_seconds=1", cfg, h.token)
	if code != 202 {
		t.Fatalf("want 202 got %d", code)
	}
	time.Sleep(1600 * time.Millisecond)
	_, body = h.do("GET", "/api/v1/config", nil, h.token)
	json.Unmarshal(body, &cfg)
	if cfg.System.Hostname != "confirmed-gw" {
		t.Fatalf("unconfirmed change was committed: %s", cfg.System.Hostname)
	}
	// system state (Linux side) also rolled back
	_, body = h.do("GET", "/api/v1/system", nil, h.token)
	if decode(t, body)["hostname"] != "confirmed-gw" {
		t.Fatalf("live state not rolled back: %s", body)
	}
}

func TestTransactionLifecycle(t *testing.T) {
	h := newHarness(t)
	// BEGIN
	code, body := h.do("POST", "/api/v1/transactions", nil, h.token)
	if code != 201 {
		t.Fatalf("begin: %d %s", code, body)
	}
	m := decode(t, body)
	id, _ := m["id"].(string)
	if id == "" {
		t.Fatal("no txn id")
	}
	// edit draft
	var cfg models.Config
	b, _ := json.Marshal(m["config"])
	json.Unmarshal(b, &cfg)
	cfg.Networks[0].Name = "office"
	code, body = h.do("PUT", "/api/v1/transactions/"+id+"/config", cfg, h.token)
	if code != 200 {
		t.Fatalf("draft edit: %d %s", code, body)
	}
	// VALIDATE
	code, _ = h.do("POST", "/api/v1/transactions/"+id+"/validate", nil, h.token)
	if code != 200 {
		t.Fatalf("validate: %d", code)
	}
	// draft is NOT live yet
	_, body = h.do("GET", "/api/v1/networks", nil, h.token)
	if strings.Contains(string(body), "office") {
		t.Fatal("unapplied draft leaked into live config")
	}
	// APPLY (with confirm)
	code, body = h.do("POST", "/api/v1/transactions/"+id+"/apply?confirm_seconds=120", nil, h.token)
	if code != 202 {
		t.Fatalf("apply: %d %s", code, body)
	}
	_, body = h.do("GET", "/api/v1/networks", nil, h.token)
	if !strings.Contains(string(body), "office") {
		t.Fatalf("applied draft not live: %s", body)
	}
	// COMMIT
	code, body = h.do("POST", "/api/v1/transactions/"+id+"/commit", nil, h.token)
	if code != 200 {
		t.Fatalf("commit: %d %s", code, body)
	}
	// ROLLBACK lifecycle on a second transaction
	code, body = h.do("POST", "/api/v1/transactions", nil, h.token)
	id2 := decode(t, body)["id"].(string)
	b2, _ := json.Marshal(decode(t, mustBody(t, h, "/api/v1/transactions/"+id2))["config"])
	json.Unmarshal(b2, &cfg)
	cfg.System.Hostname = "txn-rollback-me"
	h.do("PUT", "/api/v1/transactions/"+id2+"/config", cfg, h.token)
	code, _ = h.do("POST", "/api/v1/transactions/"+id2+"/apply", nil, h.token)
	if code != 200 { // immediate apply without confirm window
		t.Fatalf("instant apply: %d", code)
	}
	code, body = h.do("POST", "/api/v1/transactions/"+id2+"/rollback", nil, h.token)
	if code != 200 {
		t.Fatalf("rollback: %d %s", code, body)
	}
	_, body = h.do("GET", "/api/v1/system", nil, h.token)
	if decode(t, body)["hostname"] == "txn-rollback-me" {
		t.Fatal("rollback failed")
	}
}

func mustBody(t *testing.T, h *harness, path string) []byte {
	t.Helper()
	_, b := h.do("GET", path, nil, h.token)
	return b
}

func TestReadonlyRoleBlocked(t *testing.T) {
	h := newHarness(t)
	// create readonly token as admin
	code, body := h.do("POST", "/api/v1/auth/tokens", map[string]string{"name": "ro", "role": "readonly"}, h.token)
	if code != 201 {
		t.Fatalf("create token: %d %s", code, body)
	}
	tok := decode(t, body)["token"].(string)
	if code2, _ := h.do("GET", "/api/v1/networks", nil, tok); code2 != 200 {
		t.Fatalf("readonly GET blocked: %d", code2)
	}
	code, _ = h.do("POST", "/api/v1/networks", models.Network{Name: "x", Interface: "br-x", Subnet: "10.0.0.1/24", Zone: "X"}, tok)
	if code != 403 {
		t.Fatalf("readonly POST should 403, got %d", code)
	}
}

func TestRoutesEndpoint(t *testing.T) {
	h := newHarness(t)
	sr := models.StaticRoute{ID: "srv", Destination: "10.50.0.0/24", Via: "192.168.1.254", Metric: 100}
	code, body := h.do("POST", "/api/v1/routes", sr, h.token)
	if code != 201 {
		t.Fatalf("add route: %d %s", code, body)
	}
	code, body = h.do("GET", "/api/v1/routes", nil, h.token)
	var rt []map[string]any
	json.Unmarshal(body, &rt)
	found := false
	for _, r := range rt {
		if r["dst"] == "10.50.0.0/24" {
			found = true
		}
	}
	if code != 200 || !found {
		t.Fatalf("routes list missing static route: %d %s", code, body)
	}
	code, _ = h.do("DELETE", "/api/v1/routes/srv", nil, h.token)
	if code != 200 {
		t.Fatalf("delete route: %d", code)
	}
}

func TestAuditEndpoint(t *testing.T) {
	h := newHarness(t)
	h.do("POST", "/api/v1/networks", models.Network{Name: "audited", Interface: "br-audited",
		Subnet: "10.7.0.1/24", Zone: "AUDITED"}, h.token)
	code, body := h.do("GET", "/api/v1/audit", nil, h.token)
	if code != 200 {
		t.Fatalf("audit: %d", code)
	}
	if !strings.Contains(string(body), "network") || !strings.Contains(string(body), "admin") {
		t.Fatalf("audit content wrong: %s", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET", h.srv.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	s := string(data)
	if resp.StatusCode != 200 || !strings.Contains(s, "router_interface_rx_bytes") {
		t.Fatalf("metrics: %d %s", resp.StatusCode, s[:min(200, len(s))])
	}
}

func strIn(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func TestServicesEndpoints(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/services", nil, h.token)
	if code != 200 || !strings.Contains(string(body), "routerd-dnsmasq") {
		t.Fatalf("services: %d %s", code, body)
	}
	code, body = h.do("GET", "/api/v1/config/dhcp", nil, h.token)
	if code != 200 {
		t.Fatalf("dhcp status: %d %s", code, body)
	}
	for _, want := range []string{"conf_path", "in_sync", "active_leases"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("missing %s: %s", want, body)
		}
	}
}

func TestPlainApplyCancelsStalePending(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/api/v1/config", nil, h.token)
	if code != 200 {
		t.Fatal(code)
	}
	var cfg map[string]any
	json.Unmarshal(body, &cfg)
	set := func(host string, confirm string) int {
		cfg["system"] = map[string]any{"hostname": host}
		c, _ := h.do("PUT", "/api/v1/config"+confirm, cfg, h.token)
		return c
	}
	if c := set("pend-me", "?confirm_seconds=2"); c != 202 {
		t.Fatalf("pending apply: %d", c)
	}
	if c := set("committed-final", ""); c != 200 {
		t.Fatalf("plain apply: %d", c)
	}
	time.Sleep(3200 * time.Millisecond)
	_, body = h.do("GET", "/api/v1/system", nil, h.token)
	if !strings.Contains(string(body), "committed-final") {
		t.Fatalf("stale pending rolled back committed state: %s", body)
	}
}

func TestWebUIServed(t *testing.T) {
	h := newHarness(t)
	code, body := h.do("GET", "/", nil, "")
	if code != 200 || !strings.Contains(string(body), "routerd") {
		t.Fatalf("GET / = %d, %d bytes", code, len(body))
	}
	if code, _ = h.do("GET", "/app.js", nil, ""); code != 200 {
		t.Fatalf("GET /app.js = %d", code)
	}
	// API routes must not be shadowed by the SPA catch-all
	if code, _ = h.do("GET", "/api/v1/system", nil, ""); code != 401 {
		t.Fatalf("GET /system unauth = %d, want 401", code)
	}
}
