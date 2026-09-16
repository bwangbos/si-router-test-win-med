// Package state models the actual Linux networking state observed by
// routerd, plus parsers for iproute2/nft/tc output.
package state

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Stats holds interface counters.
type Stats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
}

// Link is a network interface as seen via `ip -json -s link show`.
type Link struct {
	Name   string `json:"ifname"`
	Type   string `json:"link_type"`
	Master string `json:"master"`
	Link   string `json:"link"` // parent for VLAN devices
	VLANID int    `json:"-"`
	MTU    int    `json:"mtu"`
	Up     bool   `json:"-"`
	Stats  Stats  `json:"-"`
}

// Links is an indexed list of links.
type Links []Link

// By returns the link with the given name or nil.
func (ls Links) By(name string) *Link {
	for i := range ls {
		if ls[i].Name == name {
			return &ls[i]
		}
	}
	return nil
}

// LinkAddrs is the address set of one interface.
type LinkAddrs struct {
	IfName string   `json:"ifname"`
	Addrs  []string `json:"-"` // CIDR form
}

// AddrList is an indexed list of per-link addresses.
type AddrList []LinkAddrs

// By returns addresses for the named interface (possibly empty, nil list).
func (al AddrList) By(name string) *LinkAddrs {
	for i := range al {
		if al[i].IfName == name {
			return &al[i]
		}
	}
	return &LinkAddrs{IfName: name}
}

// Route is a kernel route.
type Route struct {
	Dst      string `json:"dst"`
	Via      string `json:"gateway"`
	Dev      string `json:"dev"`
	Metric   int    `json:"metric"`
	Table    string `json:"-"`
	Protocol string `json:"protocol"`
	Comment  string `json:"-"`
}

// Neigh is an ARP/NDP neighbor entry.
type Neigh struct {
	Addr   string `json:"-"`
	LLAddr string `json:"-"`
	Dev    string `json:"-"`
	State  string `json:"-"`
}

// Qdisc is a traffic-control queueing discipline summary.
type Qdisc struct {
	Dev    string
	Parent string // root|ingress|clsact|...
	Handle string
	Kind   string
	Raw    string // full output line for suffix comparison
}

// Lease is a DHCP lease.
type Lease struct {
	Expiry   time.Time `json:"expiry"`
	MAC      string    `json:"mac"`
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname"`
}

// WANStatus is the runtime status of a WAN interface.
type WANStatus struct {
	Interface string   `json:"interface"`
	Up        bool     `json:"up"`
	Address   string   `json:"address,omitempty"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Lease     *Lease   `json:"lease,omitempty"`
	Uptime    string   `json:"uptime,omitempty"`
	Stats     Stats    `json:"stats"`
}

// Actual is a full snapshot of the observed Linux networking state.
type Actual struct {
	Links     Links
	Addrs     AddrList
	Routes    []Route
	Neigh     []Neigh
	NftScript string
	Qdiscs    []Qdisc
	Time      time.Time
}

// --- parsers ---

type rawLink struct {
	Ifname   string   `json:"ifname"`
	LinkType string   `json:"link_type"`
	Master   string   `json:"master"`
	Link     string   `json:"link"`
	MTU      int      `json:"mtu"`
	Flags    []string `json:"flags"`
	VLAN     *struct {
		ID int `json:"id"`
	} `json:"vlan"`
	Stats64 *struct {
		Rx struct {
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
			Errors  uint64 `json:"errors"`
		} `json:"rx"`
		Tx struct {
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
			Errors  uint64 `json:"errors"`
		} `json:"tx"`
	} `json:"stats64"`
	StatsRaw *struct {
		Rx struct {
			Bytes   jsonNumber `json:"bytes"`
			Packets jsonNumber `json:"packets"`
		} `json:"rx"`
		Tx struct {
			Bytes   jsonNumber `json:"bytes"`
			Packets jsonNumber `json:"packets"`
		} `json:"tx"`
	} `json:"stats"`
}

type jsonNumber uint64

func (j *jsonNumber) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	*j = jsonNumber(v)
	return nil
}

// ParseLinks parses `ip -json [-s] link show` output.
func ParseLinks(out string) (Links, error) {
	var raw []rawLink
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse link json: %w", err)
	}
	out2 := make(Links, 0, len(raw))
	for _, r := range raw {
		l := Link{Name: r.Ifname, Type: r.LinkType, Master: r.Master, Link: r.Link, MTU: r.MTU}
		if r.VLAN != nil {
			l.VLANID = r.VLAN.ID
		}
		for _, f := range r.Flags {
			if f == "UP" {
				l.Up = true
			}
		}
		if r.Stats64 != nil {
			l.Stats = Stats{RxBytes: r.Stats64.Rx.Bytes, TxBytes: r.Stats64.Tx.Bytes,
				RxPackets: r.Stats64.Rx.Packets, TxPackets: r.Stats64.Tx.Packets,
				RxErrors: r.Stats64.Rx.Errors, TxErrors: r.Stats64.Tx.Errors}
		} else if r.StatsRaw != nil {
			l.Stats = Stats{RxBytes: uint64(r.StatsRaw.Rx.Bytes), TxBytes: uint64(r.StatsRaw.Tx.Bytes),
				RxPackets: uint64(r.StatsRaw.Rx.Packets), TxPackets: uint64(r.StatsRaw.Tx.Packets)}
		}
		out2 = append(out2, l)
	}
	return out2, nil
}

type rawAddrInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Address   string `json:"address"`
	Prefixlen int    `json:"prefixlen"`
}

type rawAddrIface struct {
	Ifname   string        `json:"ifname"`
	AddrInfo []rawAddrInfo `json:"addr_info"`
}

// ParseAddrs parses `ip -json addr show` output.
func ParseAddrs(out string) (AddrList, error) {
	var raw []rawAddrIface
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse addr json: %w", err)
	}
	var al AddrList
	for _, r := range raw {
		la := LinkAddrs{IfName: r.Ifname}
		for _, a := range r.AddrInfo {
			addr := a.Local
			if addr == "" {
				addr = a.Address
			}
			if addr != "" {
				la.Addrs = append(la.Addrs, fmt.Sprintf("%s/%d", addr, a.Prefixlen))
			}
		}
		al = append(al, la)
	}
	return al, nil
}

type rawRoute struct {
	Dst      string          `json:"dst"`
	Gateway  string          `json:"gateway"`
	Dev      string          `json:"dev"`
	Metric   jsonNumber      `json:"metric"`
	Table    json.RawMessage `json:"table"`
	Protocol string          `json:"protocol"`
	Comment  string          `json:"comment"`
}

// ParseRoutes parses `ip -json route show` output.
func ParseRoutes(out string) ([]Route, error) {
	var raw []rawRoute
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse route json: %w", err)
	}
	var rs []Route
	for _, r := range raw {
		tbl := "main"
		if len(r.Table) > 0 {
			var s string
			if json.Unmarshal(r.Table, &s) == nil {
				tbl = s
			} else {
				var n int
				if json.Unmarshal(r.Table, &n) == nil {
					tbl = strconv.Itoa(n)
				}
			}
		}
		dst := r.Dst
		if dst == "default" {
			dst = "0.0.0.0/0"
		}
		rs = append(rs, Route{Dst: dst, Via: r.Gateway, Dev: r.Dev,
			Metric: int(r.Metric), Table: tbl, Protocol: r.Protocol, Comment: r.Comment})
	}
	return rs, nil
}

type rawNeigh struct {
	DstAddr string   `json:"dstaddr"`
	Dev     string   `json:"dev"`
	LLAddr  string   `json:"lladdr"`
	State   []string `json:"state"`
}

// ParseNeigh parses `ip -json neigh show` output.
func ParseNeigh(out string) ([]Neigh, error) {
	var raw []rawNeigh
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		return nil, fmt.Errorf("parse neigh json: %w", err)
	}
	var ns []Neigh
	for _, r := range raw {
		ns = append(ns, Neigh{Addr: r.DstAddr, Dev: r.Dev, LLAddr: r.LLAddr,
			State: strings.Join(r.State, ",")})
	}
	return ns, nil
}

// ParseTC parses `tc -s qdisc show dev X` (text) output.
func ParseTC(out string) ([]Qdisc, error) {
	var qs []Qdisc
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "qdisc" {
			continue
		}
		q := Qdisc{Kind: f[1], Handle: f[2], Raw: strings.TrimSpace(line)}
		for i := 3; i < len(f); i++ {
			switch f[i] {
			case "root", "ingress", "clsact":
				q.Parent = f[i]
				i++
			case "parent":
				if i+1 < len(f) {
					q.Parent = f[i+1]
				}
				i++
			}
		}
		if q.Parent == "" {
			q.Parent = "none"
		}
		qs = append(qs, q)
	}
	return qs, nil
}

// ParseLeases parses a dnsmasq-format lease file:
// <unix-expiry> <mac> <ip> <hostname> <client-id>
func ParseLeases(data []byte) []Lease {
	var out []Lease
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		exp, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		host := f[3]
		if host == "*" {
			host = ""
		}
		out = append(out, Lease{Expiry: time.Unix(exp, 0).UTC(), MAC: strings.ToLower(f[1]), IP: f[2], Hostname: host})
	}
	return out
}

// HasRoute reports whether an equivalent route is present.
func (a *Actual) HasRoute(r Route) bool {
	for _, x := range a.Routes {
		if x.Dst == r.Dst && x.Via == r.Via && x.Dev == r.Dev {
			return true
		}
	}
	return false
}

// QdiscsFor returns observed qdiscs attached to a device.
func (a *Actual) QdiscsFor(dev string) []Qdisc {
	var out []Qdisc
	for _, q := range a.Qdiscs {
		if q.Dev == dev {
			out = append(out, q)
		}
	}
	return out
}
