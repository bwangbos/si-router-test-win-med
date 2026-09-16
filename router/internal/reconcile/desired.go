// Package reconcile implements the desired-state reconciliation engine
// (design §5, §28): Observe -> Plan -> Apply -> Verify -> Commit/Rollback.
package reconcile

import (
	"fmt"
	"strings"

	"router/internal/dhcp"
	"router/internal/firewall"
	"router/internal/qos"
	"router/internal/wireguard"
	"router/pkg/models"
)

// DesiredLink is an intended interface configuration.
type DesiredLink struct {
	Name   string
	Type   string // bridge|vlan|wireguard|ether
	Parent string // VLAN parent
	Master string // bridge membership
	VLANID int
	MTU    int
	Up     bool
}

// DesiredLinks is an ordered list of intended interfaces.
type DesiredLinks []DesiredLink

// DesiredRoute is an intended kernel route (routerd-managed).
type DesiredRoute struct {
	Dst    string
	Via    string
	Dev    string
	Metric int
	Table  int
}

// Desired is the fully computed target state for the system.
type Desired struct {
	Config      models.Config
	Links       DesiredLinks
	Addrs       map[string][]string // dev -> CIDRs to be present
	DropAddrs   map[string]bool     // devs whose extra addresses are removed
	Routes      []DesiredRoute      // routerd-managed routes
	NftScript   string
	DnsmasqConf string
	DHCPActive  bool              // at least one LAN network serves DHCP
	WGConf      map[string]string // iface -> syncconf document
	TC          map[string][]string
}

// Build computes desired state from configuration.
func Build(c models.Config) (*Desired, error) {
	errs := models.Validate(c)
	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %s", models.ErrorList(errs))
	}
	d := &Desired{Config: c, Addrs: map[string][]string{}, DropAddrs: map[string]bool{},
		WGConf: map[string]string{}, TC: map[string][]string{}}

	seen := map[string]bool{}
	add := func(l DesiredLink) {
		if seen[l.Name] {
			return
		}
		seen[l.Name] = true
		d.Links = append(d.Links, l)
	}

	// WAN links (physical, managed externally at L2; bring up + static addr)
	for _, w := range c.WANs {
		add(DesiredLink{Name: w.Interface, Type: "ether", Up: w.IsEnabled()})
		if w.Mode == models.WANModeStatic && w.Static != nil {
			d.Addrs[w.Interface] = append(d.Addrs[w.Interface], w.Static.Address)
			d.DropAddrs[w.Interface] = true
			metric := w.Metric
			if metric == 0 {
				metric = 100
			}
			d.Routes = append(d.Routes, DesiredRoute{Dst: "0.0.0.0/0", Via: w.Static.Gateway,
				Dev: w.Interface, Metric: metric})
			if len(w.Static.DNS) == 0 && len(w.DNS) == 0 {
				// no DNS: keep empty, dnsmasq uses fallbacks
			}
		}
	}

	// Networks: bridges, VLANs, members, addresses
	for _, n := range c.Networks {
		if n.VLAN != nil {
			vname := fmt.Sprintf("%s.%d", n.VLAN.Parent, n.VLAN.ID)
			if n.Interface == vname || strings.Contains(n.Interface, ".") {
				// routed VLAN interface without bridge
				add(DesiredLink{Name: n.Interface, Type: "vlan", Parent: n.VLAN.Parent,
					VLANID: n.VLAN.ID, Up: true})
			} else {
				add(DesiredLink{Name: n.Interface, Type: "bridge", Up: true})
				d.DropAddrs[n.Interface] = true
				add(DesiredLink{Name: vname, Type: "vlan", Parent: n.VLAN.Parent, VLANID: n.VLAN.ID,
					Master: n.Interface, Up: true})
			}
		} else if !physical(c, n.Interface) {
			add(DesiredLink{Name: n.Interface, Type: "bridge", Up: true})
			d.DropAddrs[n.Interface] = true
		}
		d.Addrs[n.Interface] = append(d.Addrs[n.Interface], n.Subnet)
		if n.IPv6Subnet != "" {
			d.Addrs[n.Interface] = append(d.Addrs[n.Interface], n.IPv6Subnet)
		}
		for _, m := range n.Members {
			add(DesiredLink{Name: m, Type: "ether", Master: n.Interface, Up: true})
		}
	}

	// WireGuard tunnels
	for _, t := range c.WireGuard {
		iface := wireguard.IfaceName(t.Name)
		add(DesiredLink{Name: iface, Type: "wireguard", Up: true})
		d.Addrs[iface] = append(d.Addrs[iface], t.Address)
		d.DropAddrs[iface] = true
		conf, err := wireguard.GenerateConf(t)
		if err != nil {
			return nil, fmt.Errorf("wireguard %s: %w", t.Name, err)
		}
		d.WGConf[iface] = conf
		for _, p := range t.Peers {
			for _, aip := range p.AllowedIPs {
				if strings.HasSuffix(aip, "/0") || aip == "0.0.0.0/0" || aip == "::/0" {
					continue // remote default routes are a footgun; opt-in via static routes
				}
				d.Routes = append(d.Routes, DesiredRoute{Dst: aip, Dev: iface, Metric: t.Table})
			}
		}
	}

	// Static routes
	for _, r := range c.StaticRoutes {
		dst := r.Destination
		d.Routes = append(d.Routes, DesiredRoute{Dst: dst, Via: r.Via, Dev: r.Device,
			Metric: routeMetric(r), Table: r.Table})
	}

	// Artifacts
	nft, err := firewall.Generate(c)
	if err != nil {
		return nil, err
	}
	d.NftScript = nft
	dnsmasq, err := dhcp.GenerateDnsmasqConf(c)
	if err != nil {
		return nil, err
	}
	d.DnsmasqConf = dnsmasq
	for _, n := range c.Networks {
		if n.DHCP.Enabled {
			d.DHCPActive = true
		}
	}

	// QoS
	wanIfaceOf := map[string]models.WAN{}
	for _, w := range c.WANs {
		wanIfaceOf[w.Name] = w
		wanIfaceOf[w.ID] = w
	}
	for _, tp := range c.TrafficPolicies {
		ops, err := qos.Plan(tp)
		if err != nil {
			return nil, err
		}
		d.TC[tp.Interface] = append(d.TC[tp.Interface], ops...)
	}
	return d, nil
}

func routeMetric(r models.StaticRoute) int {
	if r.Metric > 0 {
		return r.Metric
	}
	return 100
}

func physical(c models.Config, name string) bool {
	for _, w := range c.WANs {
		if w.Interface == name {
			return true
		}
	}
	for _, n := range c.Networks {
		if n.Interface == name && n.VLAN == nil {
			for _, m := range n.Members {
				_ = m
			}
			return false
		}
	}
	return false
}
