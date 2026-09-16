package models

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// ValidationError is a single field-level configuration error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string { return e.Field + ": " + e.Message }

var (
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	macRe      = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	wgKeyRe    = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	nameRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
)

type validator struct{ errs []ValidationError }

func (v *validator) add(field, msg string) {
	v.errs = append(v.errs, ValidationError{Field: field, Message: msg})
}

// Validate checks a configuration for correctness and consistency.
func Validate(c Config) []ValidationError {
	v := &validator{}
	v.validateSystem(c.System)
	v.validateDNS(c.DNS)
	if len(c.WANs) == 0 {
		v.add("wans", "at least one WAN is required")
	}

	wanNames := map[string]bool{}
	wanIfaces := map[string]int{}
	for i, w := range c.WANs {
		f := fmt.Sprintf("wans[%d]", i)
		if w.Name == "" {
			v.add(f+".name", "required")
		} else if !nameRe.MatchString(w.Name) {
			v.add(f+".name", "invalid name")
		} else if wanNames[w.Name] {
			v.add(f+".name", "duplicate wan name")
		}
		wanNames[w.Name] = true
		if w.ID != "" && wanNames[w.ID] && w.ID != w.Name {
			v.add(f+".id", "duplicate wan id")
		} else if w.ID != "" {
			wanNames[w.ID] = true
		}
		if w.Interface == "" {
			v.add(f+".interface", "required")
		} else if prev, dup := wanIfaces[w.Interface]; dup {
			v.add(f+".interface", fmt.Sprintf("interface %s already used by wans[%d]", w.Interface, prev))
		}
		wanIfaces[w.Interface] = i
		switch WANMode(w.Mode) {
		case WANModeDHCP:
		case WANModeStatic:
			if w.Static == nil {
				v.add(f+".static", "required for static mode")
			} else {
				if _, err := netip.ParsePrefix(w.Static.Address); err != nil {
					v.add(f+".static.address", "must be a valid CIDR prefix")
				}
				if w.Static.Gateway == "" || !validAddr(w.Static.Gateway) {
					v.add(f+".static.gateway", "must be a valid address")
				}
				v.addrs(f+".static.dns", w.Static.DNS)
			}
		case WANModePPPoE:
			if w.PPPoE == nil || w.PPPoE.Username == "" {
				v.add(f+".pppoe", "username required for pppoe mode")
			}
		default:
			v.add(f+".mode", fmt.Sprintf("unsupported mode %q (dhcp|static|pppoe)", w.Mode))
		}
		v.addrs(f+".dns", w.DNS)
		if w.Metric < 0 {
			v.add(f+".metric", "must be >= 0")
		}
	}

	netNames := map[string]bool{}
	netIfaces := map[string]int{}
	vlanSeen := map[string]int{}
	var prefixes []netip.Prefix
	for i, n := range c.Networks {
		f := fmt.Sprintf("networks[%d]", i)
		if n.Name == "" {
			v.add(f+".name", "required")
		} else if !nameRe.MatchString(n.Name) {
			v.add(f+".name", "invalid name")
		} else if netNames[n.Name] {
			v.add(f+".name", "duplicate network name")
		}
		netNames[n.Name] = true
		if n.Interface == "" {
			v.add(f+".interface", "required")
		} else if prev, dup := netIfaces[n.Interface]; dup {
			v.add(f+".interface", fmt.Sprintf("interface %s already used by networks[%d]", n.Interface, prev))
		}
		netIfaces[n.Interface] = i
		if n.VLAN != nil {
			vf := f + ".vlan"
			if n.VLAN.ID < 1 || n.VLAN.ID > 4094 {
				v.add(vf+".id", "vlan id must be 1-4094")
			}
			if n.VLAN.Parent == "" {
				v.add(vf+".parent", "required")
			} else {
				key := fmt.Sprintf("%s.%d", n.VLAN.Parent, n.VLAN.ID)
				if prev, dup := vlanSeen[key]; dup {
					v.add(vf, fmt.Sprintf("vlan %s already assigned by networks[%d]", key, prev))
				}
				vlanSeen[key] = i
			}
		}
		pfx, err := parseSubnet(n.Subnet)
		if n.Subnet == "" {
			v.add(f+".subnet", "required")
		} else if err != nil {
			v.add(f+".subnet", "must be a valid CIDR (router address/prefix)")
		} else {
			for j, p := range prefixes {
				if p.Overlaps(pfx) {
					v.add(f+".subnet", fmt.Sprintf("overlaps with networks[%d] subnet %s", j, p.String()))
				}
			}
			prefixes = append(prefixes, pfx)
			v.validateDHCP(f+".dhcp", n.DHCP, pfx, err == nil)
		}
		if n.Zone == "" {
			v.add(f+".zone", "required")
		}
	}

	ruleIDs := map[string]bool{}
	for i, r := range c.FirewallRules {
		f := fmt.Sprintf("firewall_rules[%d]", i)
		if r.ID == "" {
			v.add(f+".id", "required")
		} else if ruleIDs[r.ID] {
			v.add(f+".id", "duplicate rule id")
		}
		ruleIDs[r.ID] = true
		switch r.Protocol {
		case "any", "tcp", "udp", "icmp":
		default:
			v.add(f+".protocol", fmt.Sprintf("unsupported protocol %q (any|tcp|udp|icmp)", r.Protocol))
		}
		switch r.Action {
		case ActionAccept, ActionDrop, ActionReject, ActionLog:
		default:
			v.add(f+".action", fmt.Sprintf("unsupported action %q (accept|drop|reject|log)", r.Action))
		}
		if r.SourceZone == "" || r.DestZone == "" {
			v.add(f+".zones", "source_zone and dest_zone are required")
		}
		v.prefixes(f+".source", r.Source)
		v.prefixes(f+".destination", r.Destination)
		for j, p := range r.Ports {
			if p.End < p.Start {
				v.add(fmt.Sprintf("%s.ports[%d]", f, j), "end must be >= start")
			}
		}
	}

	for i, pf := range c.PortForwards {
		f := fmt.Sprintf("port_forwards[%d]", i)
		if pf.WAN == "" || !wanNames[pf.WAN] {
			v.add(f+".wan", fmt.Sprintf("unknown wan %q", pf.WAN))
		}
		if pf.Protocol != "tcp" && pf.Protocol != "udp" {
			v.add(f+".protocol", "must be tcp or udp")
		}
		if pf.ExternalPort == 0 {
			v.add(f+".external_port", "required (1-65535)")
		}
		if pf.InternalPort == 0 {
			pf.InternalPort = pf.ExternalPort
			_ = pf
		}
		if pf.InternalPort == 0 {
			v.add(f+".internal_port", "required (1-65535)")
		}
		if !validAddr(pf.InternalIP) {
			v.add(f+".internal_ip", "must be a valid IPv4/IPv6 address")
		}
	}

	wgNames := map[string]bool{}
	for i, t := range c.WireGuard {
		f := fmt.Sprintf("wireguard[%d]", i)
		if t.Name == "" {
			v.add(f+".name", "required")
		} else if !nameRe.MatchString(t.Name) {
			v.add(f+".name", "invalid name")
		} else if wgNames[t.Name] {
			v.add(f+".name", "duplicate tunnel name")
		}
		wgNames[t.Name] = true
		if t.ListenPort < 0 || t.ListenPort > 65535 {
			v.add(f+".listen_port", "must be 0-65535")
		}
		if _, err := netip.ParsePrefix(t.Address); err != nil {
			v.add(f+".address", "must be a valid CIDR prefix")
		}
		for j, p := range t.Peers {
			pf := fmt.Sprintf("%s.peers[%d]", f, j)
			if !wgKeyRe.MatchString(p.PublicKey) {
				v.add(pf+".public_key", "must be a valid base64 wireguard public key")
			}
			if len(p.AllowedIPs) == 0 {
				v.add(pf+".allowed_ips", "at least one prefix required")
			}
			v.prefixes(pf+".allowed_ips", p.AllowedIPs)
			if p.PersistentKeepalive < 0 || p.PersistentKeepalive > 120 {
				v.add(pf+".persistent_keepalive", "must be 0-120")
			}
		}
	}

	tpNames := map[string]bool{}
	for i, tp := range c.TrafficPolicies {
		f := fmt.Sprintf("traffic_policies[%d]", i)
		if tp.Name == "" || tpNames[tp.Name] {
			v.add(f+".name", "required and unique")
		}
		tpNames[tp.Name] = true
		if tp.Interface == "" {
			v.add(f+".interface", "required")
		}
		if tp.UpMbps < 0 || tp.DownMbps < 0 {
			v.add(f+".up_mbps", "bandwidth limits must be >= 0")
		}
		switch tp.Qdisc {
		case "", "cake", "fq_codel", "tbf":
		default:
			v.add(f+".qdisc", fmt.Sprintf("unsupported qdisc %q (cake|fq_codel|tbf)", tp.Qdisc))
		}
	}

	routeIDs := map[string]bool{}
	for i, r := range c.StaticRoutes {
		f := fmt.Sprintf("static_routes[%d]", i)
		if r.ID == "" {
			v.add(f+".id", "required")
		} else if routeIDs[r.ID] {
			v.add(f+".id", "duplicate route id")
		}
		routeIDs[r.ID] = true
		if _, err := netip.ParsePrefix(r.Destination); err != nil {
			v.add(f+".destination", "must be a valid CIDR prefix")
		}
		if r.Via == "" && r.Device == "" {
			v.add(f, "route requires via or device")
		}
		if r.Via != "" && !validAddr(r.Via) {
			v.add(f+".via", "must be a valid address")
		}
		if r.Table < 0 || r.Table > 254 {
			v.add(f+".table", "must be 0-254")
		}
	}
	return v.errs
}

func (v *validator) validateSystem(s SystemConfig) {
	if s.Hostname != "" && !hostnameRe.MatchString(s.Hostname) {
		v.add("system.hostname", "invalid hostname")
	}
	for i, n := range s.NTPServers {
		if !validHost(n) {
			v.add(fmt.Sprintf("system.ntp_servers[%d]", i), "invalid server")
		}
	}
}

func (v *validator) validateDNS(d DNSConfig) {
	for i, u := range d.Upstreams {
		if !validAddrOrIPPort(u) {
			v.add(fmt.Sprintf("dns.upstreams[%d]", i), "must be an IP address or IP:port")
		}
	}
	if d.ListenPort < 0 || d.ListenPort > 65535 {
		v.add("dns.listen_port", "must be 0-65535")
	}
	for i, r := range d.LocalRecords {
		f := fmt.Sprintf("dns.local_records[%d]", i)
		if r.Name == "" || !hostnameRe.MatchString(r.Name) {
			v.add(f, "invalid record name")
		} else if !validAddr(r.IP) {
			v.add(f, "record IP must be a valid address")
		}
	}
}

func (v *validator) validateDHCP(f string, d DHCPServer, pfx netip.Prefix, subnetOK bool) {
	if !d.Enabled {
		return
	}
	start, sErr := netip.ParseAddr(d.Start)
	end, eErr := netip.ParseAddr(d.End)
	if sErr != nil || !start.Is4() {
		v.add(f+".start", "must be a valid IPv4 address")
		return
	}
	if eErr != nil || !end.Is4() {
		v.add(f+".end", "must be a valid IPv4 address")
		return
	}
	if subnetOK {
		if !pfx.Contains(start) {
			v.add(f+".start", "not within network subnet")
		}
		if !pfx.Contains(end) {
			v.add(f+".end", "not within network subnet")
		}
	}
	if cmpAddr(start, end) > 0 {
		v.add(f+".end", "end must be >= start")
	}
	if d.LeaseSeconds < 0 {
		v.add(f+".lease_seconds", "must be >= 0")
	}
	v.addrs(f+".dns", d.DNS)
	for i, r := range d.Reservations {
		rf := fmt.Sprintf("%s.reservations[%d]", f, i)
		if !macRe.MatchString(r.MAC) {
			v.add(rf+".mac", "must be a valid MAC address (aa:bb:cc:dd:ee:ff)")
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !ip.Is4() {
			v.add(rf+".ip", "must be a valid IPv4 address")
		} else if subnetOK && !pfx.Contains(ip) {
			v.add(rf+".ip", "not within network subnet")
		}
	}
}

func (v *validator) addrs(f string, addrs []string) {
	for i, a := range addrs {
		if !validAddr(a) {
			v.add(fmt.Sprintf("%s[%d]", f, i), "must be a valid IP address")
		}
	}
}

func (v *validator) prefixes(f string, list []string) {
	for i, p := range list {
		if _, err := netip.ParsePrefix(p); err != nil {
			v.add(fmt.Sprintf("%s[%d]", f, i), "must be a valid CIDR prefix")
		}
	}
}

// parseSubnet parses "addr/prefix" (a router interface address) and returns
// the network prefix.
func parseSubnet(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func validAddr(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.IsValid()
}

func validHost(s string) bool {
	return validAddr(s) || hostnameRe.MatchString(s)
}

func validAddrOrIPPort(s string) bool {
	if validAddr(s) {
		return true
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	return validAddr(host) && validPort(port)
}

func validPort(s string) bool {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return false
	}
	return n >= 1 && n <= 65535
}

func cmpAddr(a, b netip.Addr) int {
	switch {
	case a.Less(b):
		return -1
	case b.Less(a):
		return 1
	}
	return 0
}

// ErrorList helper for joining errors into a message.
func ErrorList(errs []ValidationError) string {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}
