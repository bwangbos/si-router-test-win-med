package reconcile

import (
	"context"
	"fmt"
	"strings"

	"router/internal/dhcp"
	"router/internal/platform"
	"router/internal/state"
)

// Actual is the observed system state snapshot.
type Actual = state.Actual

// Command is one executor invocation.
type Command struct {
	Argv         []string
	Stdin        []byte
	WritePath    string // when set, write file instead of running a command
	WriteData    []byte
	IgnoreErrors bool
}

// Operation is a single unit of change planned by a reconciler.
type Operation struct {
	Reconciler string
	Desc       string
	Commands   []Command
}

// Observe snapshots the actual Linux state via the executor.
func Observe(ctx context.Context, ex platform.Executor) (*Actual, error) {
	a := &Actual{}
	out, err := ex.Run(ctx, nil, "ip", "-json", "-s", "link", "show")
	if err != nil {
		return nil, err
	}
	if a.Links, err = state.ParseLinks(string(out)); err != nil {
		return nil, err
	}
	if out, err = ex.Run(ctx, nil, "ip", "-json", "addr", "show"); err != nil {
		return nil, err
	}
	if a.Addrs, err = state.ParseAddrs(string(out)); err != nil {
		return nil, err
	}
	if out, err = ex.Run(ctx, nil, "ip", "-json", "route", "show"); err != nil {
		return nil, err
	}
	if a.Routes, err = state.ParseRoutes(string(out)); err != nil {
		return nil, err
	}
	if out, err = ex.Run(ctx, nil, "nft", "list", "ruleset"); err == nil {
		a.NftScript = string(out)
	}
	for _, l := range a.Links {
		if out, err := ex.Run(ctx, nil, "tc", "-s", "qdisc", "show", "dev", l.Name); err == nil {
			qs, _ := state.ParseTC(string(out))
			a.Qdiscs = append(a.Qdiscs, prefixDev(qs, l.Name)...)
		}
	}
	return a, nil
}

// ApplyOps executes operations in order.
func ApplyOps(ctx context.Context, ex platform.Executor, ops []Operation) error {
	for _, op := range ops {
		for _, c := range op.Commands {
			var err error
			if c.WritePath != "" {
				err = ex.WriteFile(c.WritePath, c.WriteData)
			} else {
				_, err = ex.Run(ctx, c.Stdin, c.Argv...)
			}
			if err != nil && !c.IgnoreErrors {
				return fmt.Errorf("%s: %w", op.Desc, err)
			}
		}
	}
	return nil
}

// --- link reconciler ---

func linkCmdsCreate(l DesiredLink) []string {
	switch l.Type {
	case "bridge":
		return []string{"ip", "link", "add", "name", l.Name, "type", "bridge"}
	case "wireguard":
		return []string{"ip", "link", "add", "name", l.Name, "type", "wireguard"}
	case "vlan":
		return []string{"ip", "link", "add", "dev", l.Name, "link", l.Parent, "type", "vlan", "id", fmt.Sprint(l.VLANID)}
	}
	return nil
}

func cmd(ops []Operation, rec, desc string, argvs ...[]string) []Operation {
	var cs []Command
	for _, a := range argvs {
		cs = append(cs, Command{Argv: a})
	}
	return append(ops, Operation{Reconciler: rec, Desc: desc, Commands: cs})
}

// ByName finds a desired link by name.
func (ls DesiredLinks) ByName(name string) *DesiredLink {
	for i := range ls {
		if ls[i].Name == name {
			return &ls[i]
		}
	}
	return nil
}

// CheckInterfaces reports physical interfaces referenced by the desired
// state that do not exist on the system.
func CheckInterfaces(d *Desired, a *Actual) error {
	for _, l := range d.Links {
		if l.Type == "ether" && a.Links.By(l.Name) == nil {
			return fmt.Errorf("interface %s referenced by configuration does not exist", l.Name)
		}
	}
	return nil
}

// PlanLinks diffs desired links/interfaces against actual state.
func PlanLinks(d *Desired, a *Actual) []Operation {
	var ops []Operation
	// Deletions first: routerd-managed device kinds that are no longer
	// desired (design §5: config is authoritative).
	for _, cur := range a.Links {
		if d.Links.ByName(cur.Name) != nil {
			continue
		}
		switch cur.Type {
		case "bridge", "wireguard", "vlan":
			ops = cmd(ops, "link", "delete "+cur.Type+" "+cur.Name,
				[]string{"ip", "link", "del", "dev", cur.Name})
		}
	}
	for _, l := range d.Links {
		cur := a.Links.By(l.Name)
		if cur == nil {
			if c := linkCmdsCreate(l); c != nil {
				ops = cmd(ops, "link", "create "+l.Type+" "+l.Name, c)
				cur = &state.Link{Name: l.Name, Type: l.Type}
			} else if l.Type == "ether" {
				continue // physical: existence is validated by CheckInterfaces
			}
		} else if cur.Type != l.Type && l.Type != "ether" {
			// exists with different kind: leave alone if physical device in use as-is
			if cur.Type != "ether" {
				ops = cmd(ops, "link", "recreate "+l.Name,
					[]string{"ip", "link", "del", "dev", l.Name}, linkCmdsCreate(l))
				cur = &state.Link{Name: l.Name, Type: l.Type}
			}
		}
		if l.MTU > 0 && cur.MTU != l.MTU && l.Type == "vlan" {
			ops = cmd(ops, "link", "mtu "+l.Name,
				[]string{"ip", "link", "set", "dev", l.Name, "mtu", fmt.Sprint(l.MTU)})
		}
		if l.Master != "" && cur.Master != l.Master {
			ops = cmd(ops, "link", "enslave "+l.Name+" to "+l.Master,
				[]string{"ip", "link", "set", "dev", l.Name, "master", l.Master})
			cur.Master = l.Master
		} else if l.Master == "" && cur.Master != "" && !memberOfDesired(d, l.Name) {
			ops = cmd(ops, "link", "release "+l.Name,
				[]string{"ip", "link", "set", "dev", l.Name, "nomaster"})
		}
		wantUp := l.Up
		if l.Type == "ether" && d.Config.IsWANIface(l.Name) {
			wantUp = true
		}
		if cur.Up != wantUp {
			st := "up"
			if !wantUp {
				st = "down"
			}
			ops = cmd(ops, "link", "set "+st+" "+l.Name,
				[]string{"ip", "link", "set", "dev", l.Name, st})
		}
	}
	return ops
}

func memberOfDesired(d *Desired, name string) bool {
	for _, l := range d.Links {
		if l.Name == name && l.Master != "" {
			return true
		}
	}
	return false
}

// --- address reconciler ---

// PlanAddrs ensures router-managed interfaces carry exactly the desired
// addresses. Interfaces without desired addresses (e.g. DHCP WAN) are not
// touched.
func PlanAddrs(d *Desired, a *Actual) []Operation {
	var ops []Operation
	for dev, want := range d.Addrs {
		if d.Links.ByName(dev) == nil && a.Links.By(dev) == nil {
			continue // link will be created in a later pass
		}
		have := a.Addrs.By(dev).Addrs
		for _, w := range want {
			if !strHas(have, w) {
				ops = cmd(ops, "address", "add "+w+" dev "+dev,
					[]string{"ip", "addr", "add", w, "dev", dev})
			}
		}
		if d.DropAddrs[dev] {
			for _, h := range have {
				if !strHas(want, h) && !strings.HasPrefix(h, "fe80:") {
					ops = cmd(ops, "address", "del "+h+" dev "+dev,
						[]string{"ip", "addr", "del", h, "dev", dev})
				}
			}
		}
	}
	return ops
}

func strHas(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// --- route reconciler ---

// RouteComment marks routes managed by routerd (legacy; provenance file
// is authoritative now because iproute2 comment support varies).
const RouteComment = "routerd"

// PlanRoutes ensures desired routes exist and routes previously installed
// by routerd (per provenance) that are no longer desired are removed.
// managed==nil falls back to kernel route comments where present.
func PlanRoutes(d *Desired, a *Actual, managed []state.Route) []Operation {
	var ops []Operation
	for _, r := range d.Routes {
		if a.HasRoute(state.Route{Dst: r.Dst, Via: r.Via, Dev: r.Dev}) {
			continue
		}
		argv := []string{"ip", "route", "replace", r.Dst}
		if r.Via != "" {
			argv = append(argv, "via", r.Via)
		}
		if r.Dev != "" {
			argv = append(argv, "dev", r.Dev)
		}
		argv = append(argv, "metric", fmt.Sprint(r.Metric))
		if r.Table > 0 && r.Table != 254 {
			argv = append(argv, "table", fmt.Sprint(r.Table))
		}
		ops = cmd(ops, "route", "route "+r.Dst, argv)
	}
	for _, r := range managed {
		if desiredHasRoute(d, r) {
			continue
		}
		if !a.HasRoute(state.Route{Dst: r.Dst, Via: r.Via, Dev: r.Dev}) {
			continue // already removed (idempotent; keeps verify clean)
		}
		argv := []string{"ip", "route", "del", r.Dst}
		if r.Via != "" {
			argv = append(argv, "via", r.Via)
		}
		if r.Dev != "" {
			argv = append(argv, "dev", r.Dev)
		}
		ops = cmd(ops, "route", "del stale route "+r.Dst, argv)
	}
	return ops
}

func desiredHasRoute(d *Desired, r state.Route) bool {
	for _, w := range d.Routes {
		if w.Dst == r.Dst && w.Dev == r.Dev && (w.Via == r.Via || r.Via == "") {
			return true
		}
	}
	return false
}

// --- firewall reconciler ---

// NftHashMarker extracts the embedded hash marker from a generated script.
func NftHashMarker(script string) string {
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "# routerd-sha:") {
			return line
		}
	}
	return ""
}

// PlanFirewall applies the generated ruleset when the live ruleset does not
// carry the current hash marker.
func PlanFirewall(d *Desired, actualRuleset string) []Operation {
	want := NftHashMarker(d.NftScript)
	hexHash := strings.TrimPrefix(want, "# routerd-sha:")
	if hexHash != "" && strings.Contains(actualRuleset, "routerd-sha:"+hexHash) {
		return nil
	}
	return []Operation{{
		Reconciler: "firewall",
		Desc:       "apply nftables ruleset",
		Commands: []Command{
			{Argv: []string{"nft", "delete", "table", "inet", "router"}, IgnoreErrors: true},
			{Argv: []string{"nft", "-f", "-"}, Stdin: []byte(d.NftScript)},
		},
	}}
}

// --- service reconciler (dhcp/dns/wireguard) ---

// PlanServices writes service configuration, installs the dedicated
// dnsmasq unit, and syncs WireGuard peers.
func PlanServices(d *Desired, ex platform.Executor) []Operation {
	var ops []Operation
	confPath := dhcp.ConfPathFor()
	unitPath := "/etc/systemd/system/" + dhcp.ServiceName + ".service"
	wantUnit := dhcp.UnitFile(confPath)
	curConf, hasConf := ex.File(confPath)
	curUnit, hasUnit := ex.File(unitPath)
	confChanged := d.DnsmasqConf != "" && (!hasConf || string(curConf) != d.DnsmasqConf)
	if d.DnsmasqConf != "" && (!hasConf || string(curConf) != d.DnsmasqConf) {
		var cs []Command
		cs = append(cs, Command{WritePath: confPath, WriteData: []byte(d.DnsmasqConf)})
		if !hasUnit || string(curUnit) != wantUnit {
			cs = append(cs, Command{WritePath: unitPath, WriteData: []byte(wantUnit)},
				Command{Argv: []string{"systemctl", "daemon-reload"}})
		}
		if d.DnsmasqConf != "" {
			cs = append(cs, Command{Argv: []string{"systemctl", "reload-or-restart", dhcp.ServiceName}})
		}
		ops = append(ops, Operation{Reconciler: "dhcp", Desc: "update dnsmasq configuration", Commands: cs})
	} else if !hasUnit || string(curUnit) != wantUnit {
		ops = append(ops, Operation{Reconciler: "dhcp", Desc: "install routerd-dnsmasq unit",
			Commands: []Command{{WritePath: unitPath, WriteData: []byte(wantUnit)},
				{Argv: []string{"systemctl", "daemon-reload"}}}})
	}
	// ensure the service is enabled+active whenever DHCP is configured
	if d.DnsmasqConf != "" && (confChanged || !hasUnit || string(curUnit) != wantUnit) {
		ops = append(ops, Operation{Reconciler: "dhcp", Desc: "enable " + dhcp.ServiceName,
			Commands: []Command{{Argv: []string{"systemctl", "enable", "--now", dhcp.ServiceName},
				IgnoreErrors: true}}})
	}
	for _, kv := range sortedWG(d) {
		iface, conf := kv[0], kv[1]
		out, err := ex.Run(context.Background(), nil, "wg", "showconf", iface)
		if err == nil && strings.TrimSpace(string(out)) == strings.TrimSpace(conf) {
			continue
		}
		ops = append(ops, Operation{
			Reconciler: "wireguard",
			Desc:       "sync " + iface,
			Commands:   []Command{{Argv: []string{"wg", "syncconf", iface, "-"}, Stdin: []byte(conf)}},
		})
	}
	return ops
}

func sortedWG(d *Desired) [][2]string {
	var out [][2]string
	for _, l := range d.Links {
		if l.Type == "wireguard" {
			if conf, ok := d.WGConf[l.Name]; ok {
				out = append(out, [2]string{l.Name, conf})
			}
		}
	}
	return out
}

// --- qos reconciler ---

// PlanQoS applies bandwidth policies.
func PlanQoS(d *Desired, a *Actual) []Operation {
	var ops []Operation
	for _, l := range d.Links {
		want, ok := d.TC[l.Name]
		if !ok {
			continue
		}
		qs := a.QdiscsFor(l.Name)
		for _, wantCmd := range want {
			kind, suffix := splitTC(wantCmd)
			if tcHas(qs, kind, suffix) {
				continue
			}
			ops = append(ops, Operation{Reconciler: "qos", Desc: "apply qdisc on " + l.Name,
				Commands: []Command{{Argv: strings.Fields(wantCmd)}}})
		}
	}
	return ops
}

func splitTC(cmdLine string) (string, string) {
	f := strings.Fields(cmdLine)
	for i, x := range f {
		if x == "clsact" || x == "cake" || x == "fq_codel" || x == "tbf" || x == "u32" {
			if x == "u32" {
				return "clsact", strings.Join(f[i:], " ")
			}
			return x, strings.Join(f[i+1:], " ")
		}
	}
	return "", ""
}

func tcHas(qs []state.Qdisc, kind, suffix string) bool {
	for _, q := range qs {
		if strings.Contains(q.Raw, kind) {
			if suffix == "" || tcSuffixMatch(q.Raw, suffix) {
				return true
			}
		}
	}
	return false
}

func tcSuffixMatch(raw, suffix string) bool {
	toks := strings.Fields(suffix)
	low := strings.ToLower(raw)
	for i := 0; i+1 < len(toks); i += 2 {
		key, val := strings.ToLower(toks[i]), strings.ToLower(toks[i+1])
		if !strings.Contains(low, key) || !strings.Contains(low, val) {
			return false
		}
	}
	return true
}

// --- engine ---

// Report summarizes an Apply run.
type Report struct {
	Operations []Operation
}

// Engine orchestrates observe/plan/apply/verify across reconcilers.
type Engine struct {
	ex   platform.Executor
	prov RouteProvenance
}

// NewEngine creates a reconciliation engine over the given executor and
// route provenance store.
func NewEngine(ex platform.Executor, prov RouteProvenance) *Engine {
	if prov == nil {
		prov = NewMemoryProvenance()
	}
	return &Engine{ex: ex, prov: prov}
}

// PlanAll computes the full ordered operation set.
func (e *Engine) PlanAll(ctx context.Context, d *Desired) (*Actual, []Operation, error) {
	a, err := Observe(ctx, e.ex)
	if err != nil {
		return nil, nil, err
	}
	if err := CheckInterfaces(d, a); err != nil {
		return a, nil, err
	}
	// Interfaces are additive and safe to materialize immediately so that
	// dependent phases can plan against a refreshed observation.
	if linkOps := PlanLinks(d, a); len(linkOps) > 0 {
		if err := ApplyOps(ctx, e.ex, linkOps); err != nil {
			return a, linkOps, err
		}
		if a, err = Observe(ctx, e.ex); err != nil {
			return a, linkOps, err
		}
	}
	var ops []Operation
	ops = append(ops, PlanAddrs(d, a)...)
	ops = append(ops, PlanRoutes(d, a, e.prov.Load())...)
	ops = append(ops, PlanFirewall(d, a.NftScript)...)
	ops = append(ops, PlanServices(d, e.ex)...)
	ops = append(ops, PlanQoS(d, a)...)
	return a, ops, nil
}

func prefixDev(qs []state.Qdisc, dev string) []state.Qdisc {
	for i := range qs {
		qs[i].Dev = dev
	}
	return qs
}

// applyAndObserve applies link ops then re-observes so that later phases
// (addresses/routes/services) see the newly created devices in the same pass.

// Apply plans and executes all operations, then verifies convergence.
func (e *Engine) Apply(ctx context.Context, d *Desired) (*Report, error) {
	_, ops, err := e.PlanAll(ctx, d)
	if err != nil {
		return nil, err
	}
	if err := ApplyOps(ctx, e.ex, ops); err != nil {
		return &Report{Operations: ops}, err
	}
	if err := e.Verify(ctx, d); err != nil {
		return &Report{Operations: ops}, fmt.Errorf("verification failed: %w", err)
	}
	var managed []state.Route
	for _, r := range d.Routes {
		managed = append(managed, state.Route{Dst: r.Dst, Via: r.Via, Dev: r.Dev,
			Metric: r.Metric, Comment: RouteComment})
	}
	if err := e.prov.Save(managed); err != nil {
		return &Report{Operations: ops}, err
	}
	return &Report{Operations: ops}, nil
}

// Verify re-plans from a fresh observation; any leftover ops mean the
// system has not reached desired state.
func (e *Engine) Verify(ctx context.Context, d *Desired) error {
	a, err := Observe(ctx, e.ex)
	if err != nil {
		return err
	}
	ops := PlanLinks(d, a)
	ops = append(ops, PlanAddrs(d, a)...)
	ops = append(ops, PlanRoutes(d, a, e.prov.Load())...)
	ops = append(ops, PlanFirewall(d, a.NftScript)...)
	ops = append(ops, PlanServices(d, e.ex)...)
	ops = append(ops, PlanQoS(d, a)...)
	if len(ops) != 0 {
		var descs []string
		for _, o := range ops {
			descs = append(descs, o.Desc)
		}
		return fmt.Errorf("not converged: %d operations pending (%s)", len(ops), strings.Join(descs, "; "))
	}
	return nil
}
