// Package platform abstracts execution of Linux networking tools
// (ip/nft/tc/wg) behind an Executor interface, with a simulated
// implementation for development and end-to-end testing.
package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"router/internal/state"
)

// Executor runs a networking command with an explicit argv (never a shell)
// and optional stdin. Design §36: never execute arbitrary shell input.
type Executor interface {
	Run(ctx context.Context, stdin []byte, argv ...string) ([]byte, error)
	WriteFile(path string, data []byte) error
	File(path string) ([]byte, bool)
}

// --- fake internals ---

type flink struct {
	name   string
	typ    string
	mac    string
	master string
	parent string
	vlanID int
	mtu    int
	up     bool
	addr   []string
	stats  state.Stats
}

type froute struct {
	dst, via, dev, table, proto, comment string
	metric                               int
}

type fq struct {
	parent, handle, kind, rest string
}

// Fake is an in-memory simulation of the Linux networking stack sufficient
// for full plan/apply/observe/verify cycles without root privileges.
type Fake struct {
	mu        sync.Mutex
	links     []*flink
	routes    []froute
	neigh     []fneigh
	nftScript string
	qdisc     map[string][]fq
	wgConf    map[string]string
	files     map[string][]byte
	wan       map[string]*state.WANStatus
	leases    []state.Lease
	idx       int
	svc       []string
	failOn    map[string]string
	failN     map[string]int
}

type fneigh struct{ dev, addr, lladdr string }

// NewFake creates a simulated host with the given physical interfaces.
func NewFake(ethIfaces []string) *Fake {
	f := &Fake{qdisc: map[string][]fq{}, wgConf: map[string]string{}, files: map[string][]byte{},
		wan: map[string]*state.WANStatus{}, idx: 1, failOn: map[string]string{}, failN: map[string]int{}}
	add := func(name, typ string, mtu int) {
		f.idx++
		f.links = append(f.links, &flink{name: name, typ: typ, mtu: mtu, mac: fakeMAC(name)})
	}
	add("lo", "loopback", 65536)
	for _, e := range ethIfaces {
		if e == "lo" {
			continue
		}
		add(e, "ether", 1500)
	}
	return f
}

// Run implements Executor, emulating iproute2/nft/tc/wg behavior.
func (f *Fake) Run(_ context.Context, stdin []byte, argv ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	if msg, ok := f.failOn[argv[0]]; ok {
		f.failN[argv[0]]--
		if f.failN[argv[0]] <= 0 {
			delete(f.failOn, argv[0])
			delete(f.failN, argv[0])
		}
		return nil, fmt.Errorf("%s: %s", argv[0], msg)
	}
	switch argv[0] {
	case "ip":
		return f.ip(argv[1:])
	case "systemctl":
		return f.systemctl(argv[1:])
	case "nft":
		return f.cmdNft(stdin, argv[1:])
	case "tc":
		return f.tc(argv[1:])
	case "wg":
		return f.cmdWg(stdin, argv[1:])
	}
	return nil, fmt.Errorf("platform: unsupported command %q", argv[0])
}

func stripFlags(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (f *Fake) ip(args []string) ([]byte, error) {
	args = stripFlags(args)
	if len(args) == 0 {
		return nil, fmt.Errorf("ip: missing object")
	}
	switch args[0] {
	case "link":
		return f.ipLink(args[1:])
	case "addr":
		return f.ipAddr(args[1:])
	case "route":
		return f.ipRoute(args[1:])
	case "neigh", "neighbor":
		if len(args) > 1 && args[1] == "show" {
			return f.ipNeighShow(args[2:])
		}
	}
	return nil, fmt.Errorf("ip: unsupported operation %q", strings.Join(args, " "))
}

func (f *Fake) find(name string) *flink {
	for _, l := range f.links {
		if l.name == name {
			return l
		}
	}
	return nil
}

func (f *Fake) ipLink(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("ip link: missing operation")
	}
	switch args[0] {
	case "show":
		dev := flagVal(args, "dev")
		var out []rawLinkJSON
		for _, l := range f.links {
			if dev != "" && l.name != dev {
				continue
			}
			out = append(out, f.rawLink(l))
		}
		return json.Marshal(out)
	case "add":
		name := firstAfter(args, "name", "dev")
		typ := flagVal(args, "type")
		if name == "" || typ == "" {
			return nil, fmt.Errorf("ip link add: need name and type")
		}
		if f.find(name) != nil {
			return nil, fmt.Errorf("ip link add: %s exists", name)
		}
		l := &flink{name: name, typ: typ, mtu: 1500, mac: fakeMAC(name)}
		switch typ {
		case "bridge", "wireguard":
		case "vlan":
			l.parent = flagVal(args, "link")
			id, err := strconv.Atoi(flagVal(args, "id"))
			if l.parent == "" || err != nil || id < 1 || id > 4094 {
				return nil, fmt.Errorf("ip link add vlan: bad parent/id")
			}
			l.vlanID = id
			l.mtu = 1496
		default:
			return nil, fmt.Errorf("ip link add: unsupported type %q", typ)
		}
		f.idx++
		f.links = append(f.links, l)
		return nil, nil
	case "set":
		dev := flagVal(args, "dev")
		l := f.find(dev)
		if l == nil {
			return nil, fmt.Errorf("ip link set: %s not found", dev)
		}
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "up":
				l.up = true
			case "down":
				l.up = false
			case "mtu":
				n, err := strconv.Atoi(argAt(args, i+1))
				if err != nil {
					return nil, fmt.Errorf("ip link set: bad mtu")
				}
				l.mtu = n
			case "master":
				m := argAt(args, i+1)
				if f.find(m) == nil {
					return nil, fmt.Errorf("ip link set: master %s not found", m)
				}
				l.master = m
			case "nomaster":
				l.master = ""
			case "address":
				l.mac = argAt(args, i+1)
				i++
			}
		}
		return nil, nil
	case "del", "delete":
		dev := flagVal(args, "dev")
		l := f.find(dev)
		if l == nil {
			return nil, fmt.Errorf("ip link del: %s not found", dev)
		}
		var keep []*flink
		for _, x := range f.links {
			if x == l {
				continue
			}
			if x.master == dev {
				x.master = ""
			}
			if x.parent == dev { // vlan children die with parent
				continue
			}
			keep = append(keep, x)
		}
		f.links = keep
		f.routes = removeRoutes(f.routes, func(r froute) bool { return r.dev == dev })
		delete(f.qdisc, dev)
		delete(f.wgConf, dev)
		return nil, nil
	}
	return nil, fmt.Errorf("ip link: unsupported operation %q", args[0])
}

type rawLinkJSON struct {
	Ifindex  int      `json:"ifindex"`
	IFname   string   `json:"ifname"`
	Address  string   `json:"address,omitempty"`
	Flags    []string `json:"flags"`
	MTU      int      `json:"mtu"`
	LinkType string   `json:"link_type"`
	Master   string   `json:"master,omitempty"`
	Link     string   `json:"link,omitempty"`
	VLAN     *struct {
		Protocol string `json:"protocol"`
		ID       int    `json:"id"`
	} `json:"vlan,omitempty"`
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
	} `json:"stats64,omitempty"`
}

func (f *Fake) rawLink(l *flink) rawLinkJSON {
	flags := []string{"BROADCAST", "MULTICAST"}
	if l.typ == "loopback" {
		flags = []string{"LOOPBACK"}
	}
	if l.up {
		flags = append(flags, "UP", "LOWER_UP")
	}
	r := rawLinkJSON{Ifindex: f.idx, IFname: l.name, Address: l.mac, Flags: flags, MTU: l.mtu,
		LinkType: l.typ, Master: l.master, Link: l.parent}
	if l.vlanID != 0 {
		r.VLAN = &struct {
			Protocol string `json:"protocol"`
			ID       int    `json:"id"`
		}{Protocol: "802.1Q", ID: l.vlanID}
	}
	r.Stats64 = &struct {
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
	}{}
	r.Stats64.Rx.Bytes, r.Stats64.Rx.Packets, r.Stats64.Rx.Errors = l.stats.RxBytes, l.stats.RxPackets, l.stats.RxErrors
	r.Stats64.Tx.Bytes, r.Stats64.Tx.Packets, r.Stats64.Tx.Errors = l.stats.TxBytes, l.stats.TxPackets, l.stats.TxErrors
	return r
}

func (f *Fake) ipAddr(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("ip addr: missing operation")
	}
	switch args[0] {
	case "show":
		dev := flagVal(args, "dev")
		var out []rawAddrJSON
		for _, l := range f.links {
			if len(l.addr) == 0 || (dev != "" && l.name != dev) {
				continue
			}
			ra := rawAddrJSON{Ifindex: 1, IFname: l.name,
				AddrInfo: make([]rawInfoJSON, 0, len(l.addr))}
			for _, a := range l.addr {
				ip, plen, _ := strings.Cut(a, "/")
				n, _ := strconv.Atoi(plen)
				fam := "inet"
				if strings.Contains(ip, ":") {
					fam = "inet6"
				}
				ra.AddrInfo = append(ra.AddrInfo, rawInfoJSON{Family: fam, Local: ip, Prefixlen: n})
			}
			out = append(out, ra)
		}
		if out == nil {
			out = []rawAddrJSON{}
		}
		return json.Marshal(out)
	case "add", "del":
		dev := flagVal(args, "dev")
		l := f.find(dev)
		if l == nil {
			return nil, fmt.Errorf("ip addr: %s not found", dev)
		}
		var cidr string
		for _, a := range args[1:] {
			if strings.Contains(a, "/") {
				cidr = a
			}
		}
		if cidr == "" {
			return nil, fmt.Errorf("ip addr: missing address")
		}
		if args[0] == "add" {
			for _, a := range l.addr {
				if a == cidr {
					return nil, nil // idempotent
				}
			}
			l.addr = append(l.addr, cidr)
		} else {
			l.addr = removeStr(l.addr, cidr)
		}
		return nil, nil
	case "flush":
		dev := flagVal(args, "dev")
		l := f.find(dev)
		if l == nil {
			return nil, fmt.Errorf("ip addr flush: %s not found", dev)
		}
		l.addr = nil
		return nil, nil
	}
	return nil, fmt.Errorf("ip addr: unsupported operation %q", args[0])
}

type rawAddrJSON struct {
	Ifindex  int           `json:"ifindex"`
	IFname   string        `json:"ifname"`
	Family   string        `json:"family"`
	AddrInfo []rawInfoJSON `json:"addr_info"`
}

type rawInfoJSON struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Index     int    `json:"index"`
	Prefixlen int    `json:"prefixlen"`
}

func (f *Fake) ipRoute(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("ip route: missing operation")
	}
	switch args[0] {
	case "show":
		out := make([]rawRouteJSON, 0, len(f.routes))
		for _, r := range f.routes {
			out = append(out, rawRouteJSON{Dst: r.dst, Gateway: r.via, Dev: r.dev,
				Metric: r.metric, Proto: r.proto, Comment: r.comment})
		}
		return json.Marshal(out)
	case "add", "replace", "append":
		r := froute{table: "main", proto: "static", comment: flagVal(args, "comment")}
		r.dst = args[1]
		r.via = flagVal(args, "via")
		r.dev = flagVal(args, "dev")
		r.proto = orDefault(flagVal(args, "proto"), "static")
		if m := flagVal(args, "metric"); m != "" {
			r.metric, _ = strconv.Atoi(m)
		}
		if args[0] == "add" {
			f.routes = removeRoutes(f.routes, func(x froute) bool { return x.dst == r.dst && x.dev == r.dev && x.table == r.table })
		}
		f.routes = append(f.routes, r)
		return nil, nil
	case "del", "delete":
		dst := args[1]
		via := flagVal(args, "via")
		dev := flagVal(args, "dev")
		f.routes = removeRoutes(f.routes, func(x froute) bool {
			return x.dst == dst && (via == "" || x.via == via) && (dev == "" || x.dev == dev)
		})
		return nil, nil
	case "flush":
		dev := flagVal(args, "dev")
		f.routes = removeRoutes(f.routes, func(x froute) bool { return x.dev == dev })
		return nil, nil
	}
	return nil, fmt.Errorf("ip route: unsupported operation %q", args[0])
}

type rawRouteJSON struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway,omitempty"`
	Dev     string `json:"dev,omitempty"`
	Proto   string `json:"protocol,omitempty"`
	Comment string `json:"comment,omitempty"`
	Metric  int    `json:"metric"`
}

func (f *Fake) ipNeighShow(args []string) ([]byte, error) {
	dev := flagVal(args, "dev")
	out := []struct {
		DstAddr string   `json:"dstaddr"`
		Dev     string   `json:"dev"`
		LLAddr  string   `json:"lladdr"`
		State   []string `json:"state"`
	}{}
	for _, n := range f.neigh {
		if dev != "" && n.dev != dev {
			continue
		}
		out = append(out, struct {
			DstAddr string   `json:"dstaddr"`
			Dev     string   `json:"dev"`
			LLAddr  string   `json:"lladdr"`
			State   []string `json:"state"`
		}{DstAddr: n.addr, Dev: n.dev, LLAddr: n.lladdr, State: []string{"REACHABLE"}})
	}
	return json.Marshal(out)
}

func (f *Fake) cmdNft(stdin []byte, args []string) ([]byte, error) {
	if len(args) >= 2 && args[0] == "-f" {
		s := string(stdin)
		if err := validateNft(s); err != nil {
			return nil, fmt.Errorf("nft: %v", err)
		}
		f.nftScript = s
		return nil, nil
	}
	if args[0] == "delete" && len(args) >= 4 && args[1] == "table" {
		if strings.Contains(strings.Join(args, " "), f.nftTablePath()) {
			f.nftScript = ""
		}
		return nil, nil
	}
	if args[0] == "list" && args[1] == "ruleset" {
		if f.nftScript == "" {
			return []byte("table set proto inet hook\n"), nil
		}
		return []byte(f.nftScript), nil
	}
	return nil, fmt.Errorf("nft: unsupported operation %q", strings.Join(args, " "))
}

func (f *Fake) nftTablePath() string { return "inet router" }

// FailNext makes the next invocation of the named tool fail once.
func (f *Fake) FailNext(tool, msg string) { f.FailTimes(tool, msg, 1) }

// FailTimes makes the next n invocations of the named tool fail.
func (f *Fake) FailTimes(tool, msg string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOn[tool] = msg
	f.failN[tool] = n
}

// ServiceOps returns recorded systemctl operations.
func (f *Fake) ServiceOps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.svc...)
}

func (f *Fake) systemctl(args []string) ([]byte, error) {
	if len(args) > 0 && args[0] == "daemon-reload" {
		return nil, nil
	}
	if len(args) < 2 {
		return nil, fmt.Errorf("systemctl: bad args")
	}
	unit := args[len(args)-1]
	switch args[0] {
	case "restart", "reload", "reload-or-restart", "start", "stop", "enable", "disable":
		f.svc = append(f.svc, args[0]+" "+unit)
		return nil, nil
	case "is-active":
		for _, u := range args[1:] {
			for _, op := range f.svc {
				if strings.HasSuffix(op, " "+u) && !strings.HasPrefix(op, "stop") {
					return []byte("active\n"), nil
				}
			}
		}
		return nil, fmt.Errorf("inactive")
	}
	return nil, fmt.Errorf("systemctl: unsupported %q", args[0])
}

// reconstructRaw returns the qdisc-specific argument tail after the kind.
func reconstructRaw(args []string, kind string) string {
	sawKind := false
	var out []string
	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if a == "dev" || a == "handle" {
			skipNext = true
			continue
		}
		if a == "replace" || a == "change" || a == "add" || a == "qdisc" ||
			a == "root" || a == "ingress" || a == "clsact" {
			continue
		}
		if a == kind && !sawKind {
			sawKind = true
			continue
		}
		if sawKind {
			out = append(out, a)
		}
	}
	return strings.Join(out, " ")
}

func validateNft(s string) error {
	if strings.Contains(s, "garbage") {
		return fmt.Errorf("syntax error: garbage")
	}
	if !strings.Contains(s, "table") {
		return fmt.Errorf("no table found")
	}
	open := strings.Count(s, "{")
	closed := strings.Count(s, "}")
	if open != closed {
		return fmt.Errorf("unbalanced braces %d/%d", open, closed)
	}
	return nil
}

func (f *Fake) tc(args []string) ([]byte, error) {
	args = stripFlags(args)
	if len(args) > 0 && args[0] == "filter" {
		op := args[1]
		dev := flagVal(args, "dev")
		if f.find(dev) == nil {
			return nil, fmt.Errorf("tc filter: dev %s not found", dev)
		}
		if op == "replace" || op == "add" {
			rest := strings.Join(args[2:], " ")
			if i := strings.Index(rest, "u32"); i >= 0 {
				rest = rest[i:]
			}
			f.qdisc[dev] = append([]fq{{parent: "clsact", handle: "8000:", kind: "clsact", rest: rest}}, f.qdisc[dev]...)
			return nil, nil
		}
		return nil, nil
	}
	if len(args) == 0 || args[0] != "qdisc" {
		return nil, fmt.Errorf("tc: unsupported operation %q", strings.Join(args, " "))
	}
	args = args[1:]
	op := args[0]
	dev := flagVal(args, "dev")
	if f.find(dev) == nil && op != "show" {
		return nil, fmt.Errorf("tc: dev %s not found", dev)
	}
	switch op {
	case "show":
		var b strings.Builder
		ordered := make([]fq, 0, len(f.qdisc[dev]))
		for _, pref := range []string{"root", "clsact", "ingress"} {
			for _, q := range f.qdisc[dev] {
				if q.parent == pref {
					ordered = append(ordered, q)
				}
			}
		}
		for _, q := range f.qdisc[dev] {
			if q.parent != "root" && q.parent != "clsact" && q.parent != "ingress" {
				ordered = append(ordered, q)
			}
		}
		for _, q := range ordered {
			fmt.Fprintf(&b, "qdisc %s %s %s %s refcnt 1\n", q.kind, q.handle, q.parent, q.rest)
		}
		return []byte(b.String()), nil
	case "replace", "change", "add":
		parent := "none"
		kind := ""
		handle := ""
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "root", "ingress", "clsact":
				parent = args[i]
			case "handle":
				handle = argAt(args, i+1)
				i++
			case "dev":
				i++
			default:
				if kind == "" && parent != "none" && !isTCOption(args[i]) {
					kind = args[i]
				}
			}
		}
		if parent == "ingress" && kind == "" {
			kind = "ingress"
		}
		if parent == "clsact" && kind == "" {
			kind = "clsact"
		}
		if kind == "" {
			return nil, fmt.Errorf("tc: missing qdisc kind")
		}
		if handle == "" {
			handle = "800:"
		}
		rest := reconstructRaw(args, kind)
		f.qdisc[dev] = removeQ(f.qdisc[dev], func(x fq) bool { return x.parent == parent })
		f.qdisc[dev] = append([]fq{{parent: parent, handle: handle, kind: kind, rest: rest}}, f.qdisc[dev]...)
		return nil, nil
	case "del":
		parent := "root"
		for _, a := range args[1:] {
			switch a {
			case "root", "ingress", "clsact":
				parent = a
			}
		}
		f.qdisc[dev] = removeQ(f.qdisc[dev], func(x fq) bool { return x.parent == parent })
		return nil, nil
	}
	return nil, fmt.Errorf("tc: unsupported qdisc operation %q", op)
}

func isTCOption(tok string) bool {
	switch tok {
	case "handle", "dev", "refcnt", "bandwidth", "limit":
		return true
	}
	return false
}

func (f *Fake) cmdWg(stdin []byte, args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("wg: missing operation")
	}
	switch args[0] {
	case "syncconf", "addconf":
		iface := argAt(args, 1)
		if f.find(iface) == nil {
			return nil, fmt.Errorf("wg: %s not found", iface)
		}
		f.wgConf[iface] = string(stdin)
		return nil, nil
	case "showconf":
		iface := argAt(args, 1)
		if conf, ok := f.wgConf[iface]; ok {
			return []byte(conf), nil
		}
		return []byte(""), nil
	case "show":
		iface := argAt(args, 1)
		conf, ok := f.wgConf[iface]
		if !ok {
			return []byte{}, nil
		}
		var b strings.Builder
		for _, line := range strings.Split(conf, "\n") {
			if k, v, ok2 := strings.Cut(strings.TrimSpace(line), " = "); ok2 && k == "PublicKey" {
				fmt.Fprintf(&b, "%s\t(unknown)\t(none)\t%s\n", v, "allowed")
			}
		}
		return []byte(b.String()), nil
	}
	return nil, fmt.Errorf("wg: unsupported operation %q", args[0])
}

// --- simulation helpers ---

// SimulateWANUp emulates a successful DHCP/static bring-up of a WAN.
func (f *Fake) SimulateWANUp(iface, addrCidr, gw string, dns []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.find(iface)
	if l == nil {
		return
	}
	l.up = true
	l.addr = nil
	if addrCidr != "" {
		l.addr = append(l.addr, addrCidr)
	}
	f.routes = removeRoutes(f.routes, func(r froute) bool { return r.dst == "default" })
	if gw != "" {
		f.routes = append(f.routes, froute{dst: "default", via: gw, dev: iface, metric: 100, table: "main", proto: "dhcp"})
	}
	f.wan[iface] = &state.WANStatus{Interface: iface, Up: true, Address: addrCidr, Gateway: gw, DNS: dns}
}

// SimulateWANDown emulates carrier loss / lease loss on a WAN.
func (f *Fake) SimulateWANDown(iface string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.find(iface); l != nil {
		l.up = false
		l.addr = nil
	}
	f.routes = removeRoutes(f.routes, func(r froute) bool { return r.dev == iface })
	f.wan[iface] = &state.WANStatus{Interface: iface, Up: false}
}

// WANStatus returns the simulated WAN status for an interface.
func (f *Fake) WANStatus(iface string) state.WANStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	ws, ok := f.wan[iface]
	if !ok {
		ws = &state.WANStatus{Interface: iface}
	}
	out := *ws
	if l := f.find(iface); l != nil {
		out.Stats = l.stats
		out.Up = l.up
	}
	return out
}

// SimulateLease records a DHCP lease as if granted by the DHCP server.
func (f *Fake) SimulateLease(dev, ip, mac, hostname string, ttl int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp := time.Now().Add(time.Duration(ttl) * time.Second)
	f.leases = append(f.leases, state.Lease{Expiry: exp,
		MAC: strings.ToLower(mac), IP: ip, Hostname: hostname})
	if exp.After(time.Now()) {
		f.neigh = append(f.neigh, fneigh{dev: dev, addr: ip, lladdr: strings.ToLower(mac)})
	}
}

// Leases returns active DHCP leases.
func (f *Fake) Leases() []state.Lease {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	out := []state.Lease{}
	for _, l := range f.leases {
		if l.Expiry.After(now) {
			out = append(out, l)
		}
	}
	return out
}

// AddNeigh injects an ARP/NDP entry.
func (f *Fake) AddNeigh(dev, ip, mac string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.neigh = append(f.neigh, fneigh{dev: dev, addr: ip, lladdr: strings.ToLower(mac)})
}

// AddStats sets interface counters for observation.
func (f *Fake) AddStats(dev string, st state.Stats) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.find(dev); l != nil {
		l.stats = st
	}
}

// NftScript returns the last applied nftables script.
func (f *Fake) NftScript() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nftScript
}

// WGConfig returns the last synced config for a wireguard interface.
func (f *Fake) WGConfig(iface string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wgConf[iface]
}

// WriteFile implements Executor (in-memory filesystem).
func (f *Fake) WriteFile(path string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[filepath.ToSlash(path)] = data
	return nil
}

// File implements Executor.
func (f *Fake) File(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[filepath.ToSlash(path)]
	return b, ok
}

// Links returns simulated link names (for tests).
func (f *Fake) LinkNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, l := range f.links {
		out = append(out, l.name)
	}
	return out
}

// --- helpers ---

func flagVal(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func firstAfter(args []string, flags ...string) string {
	for _, fl := range flags {
		if v := flagVal(args, fl); v != "" {
			return v
		}
	}
	return ""
}

func argAt(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func removeStr(s []string, v string) []string {
	var out []string
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

func removeRoutes(rs []froute, pred func(froute) bool) []froute {
	var out []froute
	for _, r := range rs {
		if !pred(r) {
			out = append(out, r)
		}
	}
	return out
}

func removeQ(qs []fq, pred func(fq) bool) []fq {
	var out []fq
	for _, q := range qs {
		if !pred(q) {
			out = append(out, q)
		}
	}
	return out
}

// fakeMAC derives a deterministic locally-administered MAC from a name.
func fakeMAC(name string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(name); i++ {
		h = (h ^ uint32(name[i])) * 16777619
	}
	return fmt.Sprintf("52:54:%02x:%02x:%02x:%02x", byte(h>>24), byte(h>>16), byte(h>>8), byte(h))
}

// SetLinkMAC overrides a link's MAC address (simulation hook for tests).
func (f *Fake) SetLinkMAC(name, mac string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.find(name); l != nil {
		l.mac = mac
	}
}

// LinkMAC returns a link's MAC (simulation hook for tests).
func (f *Fake) LinkMAC(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.find(name); l != nil {
		return l.mac
	}
	return ""
}
