// Package monitor derives runtime state (devices, WAN status, health) from
// the executor and managed services (design §23, §10, §43).
package monitor

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"router/internal/platform"
	"router/internal/state"
	"router/pkg/models"
)

// Health statuses.
const (
	StatusHealthy   = "healthy"
	StatusDegraded  = "degraded"
	StatusUnhealthy = "unhealthy"
)

// Device is an inventory entry (design §23).
type Device struct {
	MAC       string    `json:"mac"`
	IPv4      string    `json:"ipv4,omitempty"`
	IPv6      []string  `json:"ipv6,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Name      string    `json:"name,omitempty"`
	Interface string    `json:"interface,omitempty"`
	Network   string    `json:"network,omitempty"`
	Source    string    `json:"source"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// HealthCheck is one health probe result.
type HealthCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Health is the aggregate system health.
type Health struct {
	Status string        `json:"status"`
	Checks []HealthCheck `json:"checks"`
	Time   time.Time     `json:"time"`
}

// LeaseSource supplies DHCP leases.
type LeaseSource interface {
	Leases() []state.Lease
}

// WANStatusProvider optionally supplies service-level WAN status
// (implemented by the simulated backend; the real platform derives it from
// observed addresses/routes).
type WANStatusProvider interface {
	WANStatus(iface string) state.WANStatus
}

// Monitor aggregates runtime state.
type Monitor struct {
	ex      platform.Executor
	src     any
	aliases map[string]string
	mu      sync.Mutex
	upSince map[string]time.Time
	svcDown map[string]bool
}

// New creates a monitor. src may implement LeaseSource and/or
// WANStatusProvider (e.g. platform.Fake); real deployments pass the
// executor-derived sources.
func New(ex platform.Executor, src any) *Monitor {
	return &Monitor{ex: ex, src: src, aliases: map[string]string{},
		upSince: map[string]time.Time{}, svcDown: map[string]bool{}}
}

// SetAliases installs MAC→name aliases.
func (m *Monitor) SetAliases(a map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aliases = a
}

// SetServiceDown records a managed service failure.
func (m *Monitor) SetServiceDown(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.svcDown[name] = true
}

// SetServiceUp clears a managed service failure.
func (m *Monitor) SetServiceUp(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.svcDown, name)
}

func (m *Monitor) leases() []state.Lease {
	if ls, ok := m.src.(LeaseSource); ok {
		return ls.Leases()
	}
	if ls, ok := m.ex.(LeaseSource); ok {
		return ls.Leases()
	}
	return nil
}

// Devices builds the device inventory from leases, neighbors and aliases.
func (m *Monitor) Devices(cfg models.Config) []Device {
	now := time.Now().UTC()
	netByIface := map[string]string{}
	for _, n := range cfg.Networks {
		netByIface[n.Interface] = n.Name
	}
	m.mu.Lock()
	aliases := m.aliases
	m.mu.Unlock()

	byMAC := map[string]*Device{}
	get := func(mac string) *Device {
		if d, ok := byMAC[mac]; ok {
			return d
		}
		d := &Device{MAC: mac, FirstSeen: now, LastSeen: now}
		byMAC[mac] = d
		return d
	}

	for _, l := range m.leases() {
		d := get(strings.ToLower(l.MAC))
		d.IPv4 = l.IP
		d.Hostname = l.Hostname
		d.Source = "dhcp"
		d.FirstSeen = l.Expiry
		d.LastSeen = now
	}
	if out, err := m.ex.Run(context.Background(), nil, "ip", "-json", "neigh", "show"); err == nil {
		if ns, err := state.ParseNeigh(string(out)); err == nil {
			for _, n := range ns {
				if n.LLAddr == "" || strings.Contains(n.LLAddr, ":") && strings.Count(n.LLAddr, ":") != 5 {
					continue
				}
				if !strings.Contains(n.Addr, ":") {
					d := get(strings.ToLower(n.LLAddr))
					if d.IPv4 == "" {
						d.IPv4 = n.Addr
						d.Interface = n.Dev
						d.Source = "neighbor"
					}
				}
			}
		}
	}

	var out []Device
	for _, d := range byMAC {
		if a, ok := aliases[d.MAC]; ok {
			d.Name = a
		}
		if d.Interface != "" {
			d.Network = netByIface[d.Interface]
		}
		if d.Network == "" && d.IPv4 != "" {
			d.Network = matchNet(cfg, d.IPv4)
			if d.Network != "" {
				d.Interface = ifaceForNet(cfg, d.Network)
			}
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IPv4 < out[j].IPv4 })
	return out
}

func matchNet(cfg models.Config, ip string) string {
	for _, n := range cfg.Networks {
		if n.Subnet == "" {
			continue
		}
		if netContains(n.Subnet, ip) {
			return n.Name
		}
	}
	return ""
}

func ifaceForNet(cfg models.Config, name string) string {
	for _, n := range cfg.Networks {
		if n.Name == name {
			return n.Interface
		}
	}
	return ""
}

func netContains(cidr, ip string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return p.Contains(a)
}

// WANStatus returns per-WAN runtime status.
func (m *Monitor) WANStatus(cfg models.Config) []state.WANStatus {
	var out []state.WANStatus
	for _, w := range cfg.WANs {
		st := state.WANStatus{Interface: w.Interface}
		if p, ok := m.src.(WANStatusProvider); ok {
			st = p.WANStatus(w.Interface)
		} else if p, ok := m.ex.(WANStatusProvider); ok {
			st = p.WANStatus(w.Interface)
		}
		st.Interface = w.Interface
		// derive from observation
		if links := m.linksFor(w.Interface); links != nil {
			st.Up = links.Up && w.IsEnabled()
			st.Stats = links.Stats
		}
		if st.Address == "" {
			st.Address = m.addrFor(w.Interface)
		}
		if st.Gateway == "" {
			st.Gateway = m.defaultVia(w.Interface)
		}
		if w.Static != nil && st.Gateway == "" {
			st.Gateway = w.Static.Gateway
		}
		if len(st.DNS) == 0 {
			st.DNS = w.DNS
			if len(st.DNS) == 0 && w.Static != nil {
				st.DNS = w.Static.DNS
			}
		}
		m.mu.Lock()
		if st.Up {
			if since, seen := m.upSince[w.Interface]; !seen || time.Now().Sub(since) < 0 {
				m.upSince[w.Interface] = time.Now()
			}
			st.Uptime = time.Since(m.upSince[w.Interface]).Round(time.Second).String()
		} else {
			delete(m.upSince, w.Interface)
		}
		m.mu.Unlock()
		st.Lease = m.leaseFor(w)
		out = append(out, st)
	}
	return out
}

func (m *Monitor) leaseFor(w models.WAN) *state.Lease {
	if w.Mode != models.WANModeDHCP {
		return nil
	}
	if w.Static == nil {
		// lease belongs to the WAN subnet? best-effort: return any lease matching WAN dns timing
		return nil
	}
	return nil
}

func (m *Monitor) linksFor(iface string) *state.Link {
	out, err := m.ex.Run(context.Background(), nil, "ip", "-json", "-s", "link", "show", "dev", iface)
	if err != nil {
		return nil
	}
	links, err := state.ParseLinks(string(out))
	if err != nil {
		return nil
	}
	return links.By(iface)
}

func (m *Monitor) addrFor(iface string) string {
	out, err := m.ex.Run(context.Background(), nil, "ip", "-json", "addr", "show", "dev", iface)
	if err != nil {
		return ""
	}
	al, err := state.ParseAddrs(string(out))
	if err != nil {
		return ""
	}
	for _, a := range al.By(iface).Addrs {
		if !strings.HasPrefix(a, "fe80:") {
			return a
		}
	}
	return ""
}

func (m *Monitor) defaultVia(iface string) string {
	out, err := m.ex.Run(context.Background(), nil, "ip", "-json", "route", "show", "default")
	if err != nil {
		return ""
	}
	rs, err := state.ParseRoutes(string(out))
	if err != nil {
		return ""
	}
	best := -1
	gw := ""
	for _, r := range rs {
		if (r.Dst == "default" || r.Dst == "0.0.0.0/0") && r.Dev == iface && (best < 0 || r.Metric < best) {
			best, gw = r.Metric, r.Via
		}
	}
	return gw
}

// Health aggregates WAN and service state.
func (m *Monitor) Health(cfg models.Config) Health {
	status := StatusHealthy
	var checks []HealthCheck
	wans := m.WANStatus(cfg)
	anyUp := false
	for _, w := range wans {
		st := StatusDegraded
		if w.Up {
			st = StatusHealthy
			anyUp = true
		}
		checks = append(checks, HealthCheck{Name: "wan:" + w.Interface, Status: st, Detail: w.Address})
	}
	if !anyUp {
		status = StatusDegraded
	}
	m.mu.Lock()
	for svc := range m.svcDown {
		status = StatusDegraded
		checks = append(checks, HealthCheck{Name: "service:" + svc, Status: StatusDegraded})
	}
	m.mu.Unlock()
	checks = append(checks, HealthCheck{Name: "leases", Status: StatusHealthy, Detail: itoa(len(m.leases()))})
	return Health{Status: status, Checks: checks, Time: time.Now().UTC()}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
