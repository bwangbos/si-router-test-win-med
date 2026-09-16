// cmd/routerctl is the routerd command-line client (design §32).
// It talks to routerd over the same REST API as the web UI; it never
// modifies Linux networking directly.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"router/internal/config"
	"router/pkg/models"
)

const version = "0.1.0-dev"

func main() {
	args := os.Args[1:]
	rest, flags := parseArgs(args)
	if err := run(rest, flags); err != nil {
		fmt.Fprintln(os.Stderr, "routerctl:", err)
		os.Exit(1)
	}
}

func run(pos []string, flags map[string]string) error {
	if len(pos) == 0 || pos[0] == "help" || has(flags, "help") {
		usage()
		return nil
	}
	if pos[0] == "version" {
		fmt.Println("routerctl", version)
		return nil
	}
	c := &client{
		server:   first(flags["server"], envOr("ROUTERD_URL", "https://127.0.0.1:8443")),
		token:    first(flags["token"], envOr("ROUTERD_TOKEN", loadStoredToken())),
		insecure: has(flags, "insecure"),
	}

	switch pos[0] {
	case "login":
		return c.login(flags)
	case "status":
		return c.getJSON("/api/v1/system", nil, flags)
	case "health":
		return c.getJSON("/api/v1/health", nil, flags)
	case "interfaces":
		return c.getJSON("/api/v1/interfaces", renderInterfaces, flags)
	case "networks":
		return c.networks(pos[1:], flags)
	case "routes":
		return c.routes(pos[1:], flags)
	case "firewall":
		return c.firewall(pos[1:], flags)
	case "portfwd", "portforwards":
		return c.portforwards(pos[1:], flags)
	case "wireguard", "wg":
		return c.wireguard(pos[1:], flags)
	case "services":
		return c.getJSON("/api/v1/services", nil, flags)
	case "dhcp":
		return c.getJSON("/api/v1/config/dhcp", nil, flags)
	case "devices":
		return c.devices(pos[1:], flags)
	case "wan":
		return c.getJSON("/api/v1/wan/status", nil, flags)
	case "leases":
		return c.getJSON("/api/v1/leases", nil, flags)
	case "events":
		return c.getJSON("/api/v1/events", nil, flags)
	case "audit":
		return c.getJSON("/api/v1/audit", nil, flags)
	case "config":
		return c.config(pos[1:], flags)
	case "transactions", "txn":
		return c.transactions(pos[1:], flags)
	case "tokens":
		return c.tokens(pos[1:], flags)
	}
	return fmt.Errorf("unknown command %q (see: routerctl help)", pos[0])
}

func usage() {
	fmt.Print(`routerctl — routerd management CLI

Usage: routerctl [global flags] <command> [subcommand] [flags]

Global flags:
  --server URL     routerd API URL        (env ROUTERD_URL, default https://127.0.0.1:8443)
  --token TOKEN    API/bearer token       (env ROUTERD_TOKEN)
  --insecure       skip TLS verification
  --json           raw JSON output

Commands:
  login                          authenticate and store the session token
  status | health                system status / health
  interfaces                     interfaces with addresses and counters
  networks list|add|rm           manage routed networks (VLANs, DHCP zones)
  routes list|add|rm             static routes
  firewall rules|add|rm          zone firewall rules
  portfwd list|add|rm            port forwards (DNAT)
  wireguard tunnels|add-peers|rm WireGuard tunnels
  devices [name MAC NAME]        device inventory / friendly names
  wan | leases | events | audit  runtime state
  services | dhcp              managed service state
  config get|validate|apply|commit|rollback|revisions|restore
  transactions begin|set|validate|apply|commit|rollback|discard
  tokens list|add|rm             API tokens
  version | help
`)
}

// --- tiny arg parser ---

// boolFlags never consume a following token as a value.
var boolFlags = map[string]bool{
	"insecure": true, "json": true, "help": true,
	"dhcp": true, "ra": true, "enabled": true, "internet": true,
	"lan-access": true, "all": true, "yes": true, "force": true,
}

func parseArgs(args []string) ([]string, map[string]string) {
	var pos []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "--") {
			key := strings.TrimPrefix(a, "--")
			if boolFlags[key] {
				flags[key] = "true"
				continue
			}
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
			continue
		}
		pos = append(pos, a)
	}
	for _, al := range [][2]string{{"src-zone", "src"}, {"dst-zone", "dst"}, {"dport", "ports"}} {
		if v, ok := flags[al[0]]; ok && flags[al[1]] == "" {
			flags[al[1]] = v
		}
	}
	return pos, flags
}

func has(f map[string]string, k string) bool { return f[k] != "" && f[k] != "false" }
func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func tokenPath() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "routerctl", "token")
	}
	return ".routerctl-token"
}

func loadStoredToken() string {
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// --- HTTP client ---

type client struct {
	server   string
	token    string
	insecure bool
}

func (c *client) httpClient() *http.Client {
	tr := &http.Transport{}
	if c.insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func (c *client) request(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.server+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach routerd at %s: %w", c.server, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct {
			Error  string                   `json:"error"`
			Fields []models.ValidationError `json:"fields"`
		}
		json.Unmarshal(data, &e)
		msg := e.Error
		if msg == "" {
			msg = resp.Status
		}
		if len(e.Fields) > 0 {
			msg += "\n  - " + models.ErrorList(e.Fields)
		}
		return nil, errors.New(msg)
	}
	return data, nil
}

func (c *client) getJSON(path string, render func([]byte) string, flags map[string]string) error {
	data, err := c.request("GET", path, nil)
	if err != nil {
		return err
	}
	if has(flags, "json") || render == nil {
		fmt.Println(formatJSON(raw(data)))
		return nil
	}
	fmt.Print(render(data))
	return nil
}

func raw(data []byte) any {
	var v any
	json.Unmarshal(data, &v)
	return v
}

func (c *client) login(flags map[string]string) error {
	user := first(flags["user"], "admin")
	pw := flags["password"]
	if pw == "" {
		fmt.Print("password: ")
		var line string
		fmt.Scanln(&line)
		pw = line
	}
	data, err := c.request("POST", "/api/v1/auth/login",
		map[string]string{"username": user, "password": pw})
	if err != nil {
		return err
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(tokenPath()), 0o700)
	if err := os.WriteFile(tokenPath(), []byte(res.Token), 0o600); err != nil {
		return err
	}
	fmt.Println("login ok; token stored in", tokenPath())
	return nil
}

// --- commands ---

func (c *client) networks(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "list") {
	case "list":
		return c.getJSON("/api/v1/networks", renderNetworks, flags)
	case "add":
		n, err := networkFromFlags(flags)
		if err != nil {
			return err
		}
		data, err := c.request("POST", "/api/v1/networks", n)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	case "rm", "del":
		if len(pos) < 2 {
			return errors.New("usage: routerctl networks rm <id>")
		}
		_, err := c.request("DELETE", "/api/v1/networks/"+pos[1], nil)
		fmt.Println("deleted")
		return err
	}
	return errors.New("networks: list|add|rm")
}

func networkFromFlags(f map[string]string) (models.Network, error) {
	if v, ok := f["member"]; ok && f["members"] == "" {
		f["members"] = v
	}
	if v, ok := f["start"]; ok && f["dhcp-start"] == "" {
		f["dhcp-start"] = v
	}
	if v, ok := f["end"]; ok && f["dhcp-end"] == "" {
		f["dhcp-end"] = v
	}
	var n models.Network
	n.Name = f["name"]
	if n.Name == "" {
		return n, errors.New("--name required")
	}
	n.Subnet = f["subnet"]
	if n.Subnet == "" {
		return n, errors.New("--subnet required (router address, e.g. 192.168.20.1/24)")
	}
	n.Interface = f["bridge"]
	if f["vlan"] != "" {
		id, err := strconv.Atoi(f["vlan"])
		if err != nil {
			return n, fmt.Errorf("--vlan: %w", err)
		}
		parent := first(f["parent"], "eth1")
		n.VLAN = &models.VLANConfig{Parent: parent, ID: id}
		if n.Interface == "" {
			n.Interface = fmt.Sprintf("%s.%d", parent, id)
		}
	}
	if n.Interface == "" {
		n.Interface = "br-" + n.Name
	}
	n.DHCP.Enabled = f["dhcp"] == "true" || f["dhcp"] == "" && f["dhcp"] != "false"
	if n.DHCP.Enabled {
		n.DHCP.Start = f["dhcp-start"]
		n.DHCP.End = f["dhcp-end"]
	}
	if _, ok := f["internet"]; ok {
		b := f["internet"] != "false"
		n.InternetAccess = models.Bool(b)
	}
	if _, ok := f["lan-access"]; ok {
		b := f["lan-access"] != "false"
		n.AccessToLAN = models.Bool(b)
	}
	if f["members"] != "" {
		for _, m := range strings.Split(f["members"], ",") {
			if m = strings.TrimSpace(m); m != "" {
				n.Members = append(n.Members, m)
			}
		}
	}
	n.Zone = strings.ToUpper(first(f["zone"], n.Name))
	// mirror routerd defaults (DHCP pool etc.) so local validation matches
	tmp := models.Config{Networks: []models.Network{n}}
	config.ApplyDefaults(&tmp)
	return tmp.Networks[0], nil
}

func attachNetwork(c models.Config, n models.Network) models.Config {
	c.Networks = append(c.Networks, n)
	return c
}

func (c *client) routes(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "list") {
	case "list":
		return c.getJSON("/api/v1/routes", renderRoutes, flags)
	case "add":
		rt := models.StaticRoute{
			ID:          first(flags["id"], fmt.Sprintf("r%d", time.Now().UnixNano()%1000000)),
			Destination: flags["dst"], Via: flags["via"], Device: flags["dev"],
		}
		rt.Metric, _ = strconv.Atoi(flags["metric"])
		_, err := c.request("POST", "/api/v1/routes", rt)
		fmt.Println("route added")
		return err
	case "rm", "del":
		if len(pos) < 2 {
			return errors.New("usage: routerctl routes rm <id>")
		}
		_, err := c.request("DELETE", "/api/v1/routes/"+pos[1], nil)
		fmt.Println("deleted")
		return err
	}
	return errors.New("routes: list|add|rm")
}

func (c *client) firewall(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "rules") {
	case "rules", "list":
		return c.getJSON("/api/v1/firewall/rules", renderRules, flags)
	case "add":
		r := models.FirewallRule{
			ID:   first(flags["id"], fmt.Sprintf("rule%d", time.Now().UnixNano()%1000000)),
			Name: flags["name"], SourceZone: strings.ToUpper(first(flags["src"], flags["src-zone"])),
			DestZone: strings.ToUpper(first(flags["dst"], flags["dst-zone"], "WAN")),
			Protocol: first(flags["proto"], "any"),
			Action:   models.Action(first(flags["action"], "accept")), Enabled: true,
		}
		p := first(flags["ports"], flags["dport"])
		if p != "" {
			pr, err := parsePorts(p)
			if err != nil {
				return err
			}
			r.Ports = []models.PortRange{pr}
		}
		if v, ok := flags["disabled"]; ok && v == "true" {
			r.Enabled = false
		}
		_, err := c.request("POST", "/api/v1/firewall/rules", r)
		fmt.Println("rule added")
		return err
	case "rm", "del":
		if len(pos) < 2 {
			return errors.New("usage: routerctl firewall rm <id>")
		}
		_, err := c.request("DELETE", "/api/v1/firewall/rules/"+pos[1], nil)
		fmt.Println("deleted")
		return err
	}
	return errors.New("firewall: rules|add|rm")
}

func parsePorts(s string) (models.PortRange, error) {
	a, b, _ := strings.Cut(s, "-")
	start, err := strconv.Atoi(a)
	if err != nil {
		return models.PortRange{}, fmt.Errorf("ports: %w", err)
	}
	end := start
	if b != "" {
		end, err = strconv.Atoi(b)
		if err != nil {
			return models.PortRange{}, fmt.Errorf("ports: %w", err)
		}
	}
	return models.PortRange{Start: uint16(start), End: uint16(end)}, nil
}

func (c *client) portforwards(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "list") {
	case "list":
		return c.getJSON("/api/v1/portforwards", renderPFs, flags)
	case "add":
		ext, err := strconv.Atoi(flags["ext"])
		if err != nil {
			return fmt.Errorf("--ext required: %w", err)
		}
		inp := ext
		if flags["int"] != "" {
			inp, _ = strconv.Atoi(flags["int"])
		}
		pf := models.PortForward{
			Name: flags["name"], WAN: first(flags["wan"], "wan"),
			Protocol:     first(flags["proto"], "tcp"),
			ExternalPort: uint16(ext), InternalIP: flags["ip"],
			InternalPort: uint16(inp), Enabled: true,
		}
		_, err = c.request("POST", "/api/v1/portforwards", pf)
		fmt.Println("port forward added")
		return err
	case "rm", "del":
		if len(pos) < 2 {
			return errors.New("usage: routerctl portfwd rm <id>")
		}
		_, err := c.request("DELETE", "/api/v1/portforwards/"+pos[1], nil)
		fmt.Println("deleted")
		return err
	}
	return errors.New("portfwd: list|add|rm")
}

func (c *client) wireguard(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "tunnels") {
	case "tunnels", "list":
		return c.getJSON("/api/v1/wireguard/tunnels", renderWG, flags)
	case "add":
		t := models.WireGuardTunnel{
			Name: flags["name"], PrivateKey: flags["private-key"],
			Address: flags["address"],
		}
		t.ListenPort, _ = strconv.Atoi(flags["port"])
		for _, p := range strings.Split(flags["peers"], ";") {
			if strings.TrimSpace(p) == "" {
				continue
			}
			// NAME:PUBLICKEY:ALLOWED[/endpoint]
			f := strings.Split(p, ":")
			if len(f) < 3 {
				return fmt.Errorf("peer format NAME:PUBLICKEY:ALLOWEDIPS got %q", p)
			}
			pe := models.WireGuardPeer{Name: f[0], PublicKey: f[1],
				AllowedIPs: strings.Split(f[2], ",")}
			if len(f) > 3 {
				pe.Endpoint = f[3]
			}
			t.Peers = append(t.Peers, pe)
		}
		_, err := c.request("POST", "/api/v1/wireguard/tunnels", t)
		fmt.Println("tunnel added")
		return err
	case "rm", "del":
		if len(pos) < 2 {
			return errors.New("usage: routerctl wireguard rm <name>")
		}
		_, err := c.request("DELETE", "/api/v1/wireguard/tunnels/"+pos[1], nil)
		fmt.Println("deleted")
		return err
	}
	return errors.New("wireguard: tunnels|add|rm")
}

func (c *client) devices(pos []string, flags map[string]string) error {
	if len(pos) >= 3 && pos[0] == "name" {
		_, err := c.request("PUT", "/api/v1/devices/"+pos[1],
			map[string]string{"name": strings.Join(pos[2:], " ")})
		fmt.Println("renamed")
		return err
	}
	return c.getJSON("/api/v1/devices", renderDevices, flags)
}

func (c *client) config(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "get") {
	case "get":
		return c.getJSON("/api/v1/config", nil, flags)
	case "validate":
		path := arg(pos, 1, "")
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		parsed, err := parseConfigBytes(data, path)
		if err != nil {
			return err
		}
		res, err := c.request("POST", "/api/v1/config/validate", parsed)
		if err != nil {
			return err
		}
		fmt.Println(string(res))
		return nil
	case "apply":
		path := arg(pos, 1, "")
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		parsed, err := parseConfigBytes(data, path)
		if err != nil {
			return err
		}
		q := ""
		if flags["confirm"] != "" {
			q = "?confirm_seconds=" + flags["confirm"]
		}
		res, err := c.request("PUT", "/api/v1/config"+q, parsed)
		if err != nil {
			return err
		}
		fmt.Println(formatJSON(raw(res)))
		return nil
	case "commit":
		res, err := c.request("POST", "/api/v1/config/commit",
			map[string]string{"commit_token": flags["token"]})
		fmt.Print(formatJSON(raw(res)))
		return err
	case "rollback":
		res, err := c.request("POST", "/api/v1/config/rollback", nil)
		fmt.Print(formatJSON(raw(res)))
		return err
	case "revisions":
		return c.getJSON("/api/v1/config/revisions", nil, flags)
	case "restore":
		if len(pos) < 2 {
			return errors.New("usage: routerctl config restore <rev>")
		}
		res, err := c.request("POST", "/api/v1/config/revisions/"+pos[1]+"/restore", nil)
		fmt.Print(formatJSON(raw(res)))
		return err
	}
	return errors.New("config: get|validate|apply|commit|rollback|revisions|restore")
}

func (c *client) transactions(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "begin") {
	case "begin":
		res, err := c.request("POST", "/api/v1/transactions", map[string]any{})
		if err != nil {
			return err
		}
		if has(flags, "json") {
			fmt.Println(formatJSON(raw(res)))
			return nil
		}
		var v map[string]any
		json.Unmarshal(res, &v)
		fmt.Println("transaction", v["id"], "begun (draft = current config)")
		return nil
	case "set":
		id := arg(pos, 1, "")
		path := arg(pos, 2, "")
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parseConfigBytes(data, path)
		if err != nil {
			return err
		}
		res, err := c.request("PUT", "/api/v1/transactions/"+id+"/config", parsed)
		fmt.Println("draft updated:", respStatus(res))
		return err
	case "validate":
		_, err := c.request("POST", "/api/v1/transactions/"+arg(pos, 1, "")+"/validate", nil)
		fmt.Println("valid")
		return err
	case "apply":
		q := ""
		if flags["confirm"] != "" {
			q = "?confirm_seconds=" + flags["confirm"]
		}
		res, err := c.request("POST", "/api/v1/transactions/"+arg(pos, 1, "")+"/apply"+q, nil)
		fmt.Print(formatJSON(raw(res)))
		return err
	case "commit":
		res, err := c.request("POST", "/api/v1/transactions/"+arg(pos, 1, "")+"/commit", nil)
		fmt.Print(formatJSON(raw(res)))
		return err
	case "rollback", "discard":
		res, err := c.request("POST", "/api/v1/transactions/"+arg(pos, 1, "")+"/rollback", nil)
		fmt.Print(formatJSON(raw(res)))
		return err
	}
	return errors.New("transactions: begin|set|validate|apply|commit|rollback")
}

func respStatus(data []byte) string {
	var v map[string]any
	json.Unmarshal(data, &v)
	if s, ok := v["id"]; ok {
		return fmt.Sprint(s)
	}
	return "ok"
}

func (c *client) tokens(pos []string, flags map[string]string) error {
	switch arg(pos, 0, "list") {
	case "list":
		return c.getJSON("/api/v1/auth/tokens", nil, flags)
	case "add":
		res, err := c.request("POST", "/api/v1/auth/tokens",
			map[string]string{"name": first(flags["name"], "token"), "role": first(flags["role"], "readonly")})
		if err != nil {
			return err
		}
		fmt.Println(formatJSON(raw(res)))
		return err
	case "rm", "del":
		_, err := c.request("DELETE", "/api/v1/auth/tokens/"+arg(pos, 1, ""), nil)
		fmt.Println("revoked")
		return err
	}
	return errors.New("tokens: list|add|rm")
}

func parseConfigBytes(data []byte, path string) (models.Config, error) {
	// reuse config.Parse semantics without importing internal (CLI stays a
	// pure API client): decode JSON/YAML minimally.
	var c models.Config
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("parse %s: %w", path, err)
		}
		return c, nil
	}
	return c, errors.New("CLI config files must be JSON (use the API or routerd --config for YAML)")
}

// --- rendering helpers ---

func arg(pos []string, i int, d string) string {
	if i < len(pos) {
		return pos[i]
	}
	return d
}

func formatTable(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	widths := make([]int, len(rows[0]))
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	var b strings.Builder
	for _, r := range rows {
		for i, c := range r {
			if i == len(r)-1 {
				fmt.Fprintf(&b, "%s", c)
			} else {
				fmt.Fprintf(&b, "%-*s  ", widths[i], c)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func formatJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func renderInterfaces(data []byte) string {
	var list []map[string]any
	json.Unmarshal(data, &list)
	rows := [][]string{{"NAME", "TYPE", "UP", "MTU", "MASTER", "ADDRS"}}
	for _, l := range list {
		addrs, _ := json.Marshal(l["addrs"])
		rows = append(rows, []string{fmt.Sprint(l["name"]), fmt.Sprint(l["type"]),
			fmt.Sprint(l["up"]), fmt.Sprint(l["mtu"]), fmt.Sprint(l["master"]),
			strings.Trim(strings.Trim(string(addrs), "[]"), "\"")})
	}
	return formatTable(rows)
}

func renderNetworks(data []byte) string {
	var nets []models.Network
	json.Unmarshal(data, &nets)
	rows := [][]string{{"NAME", "INTERFACE", "SUBNET", "VLAN", "DHCP", "ZONE", "INTERNET", "LAN-ACCESS"}}
	for _, n := range nets {
		vl := ""
		if n.VLAN != nil {
			vl = fmt.Sprintf("%s.%d", n.VLAN.Parent, n.VLAN.ID)
		}
		dhcp := "no"
		if n.DHCP.Enabled {
			dhcp = fmt.Sprintf("%s-%s", n.DHCP.Start, n.DHCP.End)
		}
		rows = append(rows, []string{n.Name, n.Interface, n.Subnet, vl, dhcp, n.Zone,
			flag(n.HasInternet()), flag(n.CanAccessLAN())})
	}
	return formatTable(rows)
}

func renderRoutes(data []byte) string {
	var rt []map[string]any
	json.Unmarshal(data, &rt)
	rows := [][]string{{"DST", "VIA", "DEV", "METRIC", "TABLE", "SOURCE"}}
	for _, r := range rt {
		rows = append(rows, []string{s(r["dst"]), s(r["via"]), s(r["dev"]), s(r["metric"]), s(r["table"]), s(r["source"])})
	}
	return formatTable(rows)
}

func renderRules(data []byte) string {
	var rs []models.FirewallRule
	json.Unmarshal(data, &rs)
	rows := [][]string{{"ID", "SRC", "DST", "PROTO", "PORTS", "ACTION", "ON"}}
	for _, r := range rs {
		var ps []string
		for _, p := range r.Ports {
			if p.End == p.Start || p.End == 0 {
				ps = append(ps, fmt.Sprint(p.Start))
			} else {
				ps = append(ps, fmt.Sprintf("%d-%d", p.Start, p.End))
			}
		}
		rows = append(rows, []string{r.ID, r.SourceZone, r.DestZone, r.Protocol,
			strings.Join(ps, ","), string(r.Action), flag(r.Enabled)})
	}
	return formatTable(rows)
}

func renderPFs(data []byte) string {
	var ps []models.PortForward
	json.Unmarshal(data, &ps)
	rows := [][]string{{"ID", "WAN", "PROTO", "EXT", "INTERNAL", "ON"}}
	for _, p := range ps {
		rows = append(rows, []string{p.ID, p.WAN, p.Protocol, fmt.Sprint(p.ExternalPort),
			fmt.Sprintf("%s:%d", p.InternalIP, p.InternalPort), flag(p.Enabled)})
	}
	return formatTable(rows)
}

func renderWG(data []byte) string {
	var ts []models.WireGuardTunnel
	json.Unmarshal(data, &ts)
	rows := [][]string{{"NAME", "ADDRESS", "PORT", "PEERS"}}
	for _, t := range ts {
		rows = append(rows, []string{t.Name, t.Address, fmt.Sprint(t.ListenPort), fmt.Sprint(len(t.Peers))})
	}
	return formatTable(rows)
}

func renderDevices(data []byte) string {
	var ds []map[string]any
	json.Unmarshal(data, &ds)
	rows := [][]string{{"MAC", "IPv4", "HOSTNAME", "NAME", "NETWORK", "SRC"}}
	for _, d := range ds {
		rows = append(rows, []string{s(d["mac"]), s(d["ipv4"]), s(d["hostname"]),
			s(d["name"]), s(d["network"]), s(d["source"])})
	}
	return formatTable(rows)
}

func s(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func flag(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
