package dhcp4

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"sync"
	"time"

	"router/internal/platform"
	"router/internal/reconcile"
	"router/internal/state"
	"router/pkg/models"
)

// Lease is a runtime DHCP lease for one WAN interface.
type Lease struct {
	Iface    string
	Addr     *net.IPNet // yiaddr + mask
	Gateway  net.IP
	DNS      []string
	ServerID string
	Acquired time.Time
	Expire   time.Time
	T1, T2   time.Duration
	State    string // "bound"|"renewing"|"rebinding"
}

// CIDR renders the lease address in CIDR notation.
func (l *Lease) CIDR() string { return l.Addr.String() }

// Registry holds current WAN leases. It is the bridge between the client
// (network I/O) and the reconciler (kernel state): the engine derives WAN
// addresses, default routes and DNS upstreams from it every pass.
type Registry struct {
	mu       sync.Mutex
	leases   map[string]*Lease
	onChange func() // called after every lease set/remove (reconcile nudge)
}

// NewRegistry creates an empty registry; onChange may be nil.
func NewRegistry(onChange func()) *Registry {
	return &Registry{leases: map[string]*Lease{}, onChange: onChange}
}

func (r *Registry) set(l *Lease) {
	r.mu.Lock()
	r.leases[l.Iface] = l
	r.mu.Unlock()
	if r.onChange != nil {
		r.onChange()
	}
}

// Remove forgets a lease (idempotent).
func (r *Registry) Remove(iface string) {
	r.mu.Lock()
	_, had := r.leases[iface]
	delete(r.leases, iface)
	r.mu.Unlock()
	if had && r.onChange != nil {
		r.onChange()
	}
}

// Get returns the lease for iface (nil when unbound).
func (r *Registry) Get(iface string) *Lease {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.leases[iface]
}

// Snapshot copies all leases keyed by interface.
func (r *Registry) Snapshot() map[string]*Lease {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]*Lease, len(r.leases))
	for k, v := range r.leases {
		out[k] = v
	}
	return out
}

// Upstreams returns dnsmasq upstream servers: lease DNS first (in WAN
// config order), then statically configured servers, deduplicated.
func (r *Registry) Upstreams(cfg models.Config) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, w := range cfg.WANs {
		if l := r.Get(w.Interface); l != nil && w.IsEnabled() && w.Mode == models.WANModeDHCP {
			for _, d := range l.DNS {
				add(d)
			}
		}
	}
	for _, w := range cfg.WANs {
		for _, d := range w.DNS {
			add(d)
		}
	}
	for _, u := range cfg.DNS.Upstreams {
		add(u)
	}
	return out
}

// WANStatus adapts the registry to monitor.WANStatusProvider: lease-derived
// address, gateway, DNS and expiry for one interface.
func (r *Registry) WANStatus(iface string) state.WANStatus {
	l := r.Get(iface)
	if l == nil {
		return state.WANStatus{}
	}
	st := state.WANStatus{Address: l.CIDR()}
	if l.Gateway != nil {
		st.Gateway = l.Gateway.String()
	}
	st.DNS = l.DNS
	st.Lease = &state.Lease{Expiry: l.Expire, IP: l.Addr.IP.String()}
	return st
}

// Transport abstracts the UDP socket so the state machine is testable
// without root or network access.
type Transport interface {
	Send(b []byte, dst *net.UDPAddr) error
	Recv() ([]byte, *net.UDPAddr, error)
	Close() error
}

// TransportFactory opens a per-interface transport (SO_BINDTODEVICE on
// Linux, simulated in tests).
type TransportFactory func(iface string, mac net.HardwareAddr) (Transport, error)

// Deps wires the Manager into the daemon.
type Deps struct {
	Exec          platform.Executor
	Reg           *Registry
	Sync          func() // nudge reconcile after registry changes
	Make          TransportFactory
	Event         func(kind, detail string)
	Hostname      string
	LeaseFallback time.Duration // used when the server omits lease time
}

type clientHandle struct {
	cancel  context.CancelFunc
	release chan struct{} // closed by runClient when done
}

// Manager keeps one client per enabled DHCP WAN in sync with configuration.
type Manager struct {
	deps Deps
	mu   sync.Mutex
	run  map[string]*clientHandle
}

// NewManager creates a manager (clients start via Sync).
func NewManager(d Deps) *Manager {
	if d.LeaseFallback == 0 {
		d.LeaseFallback = 15 * time.Minute
	}
	return &Manager{deps: d, run: map[string]*clientHandle{}}
}

// Sync starts clients for DHCP WANs in cfg and stops/releases the rest.
func (m *Manager) Sync(cfg models.Config) {
	want := map[string]models.WAN{}
	for _, w := range cfg.WANs {
		if w.Mode == models.WANModeDHCP && w.IsEnabled() {
			want[w.Interface] = w
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for iface, h := range m.run {
		if _, ok := want[iface]; !ok {
			h.cancel()
			delete(m.run, iface)
		}
	}
	for iface, w := range want {
		if _, ok := m.run[iface]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		h := &clientHandle{cancel: cancel, release: make(chan struct{})}
		m.run[iface] = h
		go m.runClient(ctx, iface, w, h)
	}
}

// Shutdown stops all clients (each sends a RELEASE).
func (m *Manager) Shutdown() {
	m.mu.Lock()
	for iface, h := range m.run {
		h.cancel()
		delete(m.run, iface)
	}
	m.mu.Unlock()
}

// Release stops the client for one interface.
func (m *Manager) Release(iface string) {
	m.mu.Lock()
	if h, ok := m.run[iface]; ok {
		h.cancel()
		delete(m.run, iface)
	}
	m.mu.Unlock()
}

func (m *Manager) runClient(ctx context.Context, iface string, w models.WAN, h *clientHandle) {
	defer close(h.release)
	defer m.deps.Reg.Remove(iface)
	mac := m.linkMAC(ctx, iface, w)
	c := &client{
		iface: iface, mac: mac, deps: m.deps,
		xid: rand.Uint32(),
		after: func(d time.Duration) <-chan time.Time {
			return time.NewTimer(d).C
		},
	}
	c.run(ctx)
}

func (m *Manager) linkMAC(ctx context.Context, iface string, w models.WAN) net.HardwareAddr {
	if w.MACAddr != "" {
		if mac, err := net.ParseMAC(w.MACAddr); err == nil {
			return mac
		}
	}
	out, err := m.deps.Exec.Run(ctx, nil, "ip", "-j", "link", "show", "dev", iface)
	if err != nil {
		return nil
	}
	var links []struct {
		Ifname  string `json:"ifname"`
		Address string `json:"address"`
	}
	if json.Unmarshal(out, &links) != nil {
		return nil
	}
	for _, l := range links {
		if l.Ifname == iface && l.Address != "" {
			if mac, err := net.ParseMAC(l.Address); err == nil {
				return mac
			}
		}
	}
	return nil
}

func (m *Manager) event(kind, detail string) {
	if m.deps.Event != nil {
		m.deps.Event(kind, detail)
	}
}

// Runtime projects current leases into a reconcile.RuntimeInput: lease
// addresses and default routes for enabled DHCP WANs, plus DNS upstreams.
func (r *Registry) Runtime(cfg models.Config) *reconcile.RuntimeInput {
	rt := &reconcile.RuntimeInput{Addrs: map[string][]string{}}
	for _, w := range cfg.WANs {
		if w.Mode != models.WANModeDHCP || !w.IsEnabled() {
			continue
		}
		l := r.Get(w.Interface)
		if l == nil {
			continue
		}
		rt.Addrs[w.Interface] = []string{l.CIDR()}
		if l.Gateway != nil {
			metric := w.Metric
			if metric == 0 {
				metric = 100
			}
			rt.Routes = append(rt.Routes, reconcile.DesiredRoute{
				Dst: "0.0.0.0/0", Via: l.Gateway.String(), Dev: w.Interface, Metric: metric})
		}
	}
	rt.Upstreams = r.Upstreams(cfg)
	if len(rt.Addrs) == 0 && len(rt.Routes) == 0 {
		rt.Addrs = nil
		return &reconcile.RuntimeInput{Upstreams: rt.Upstreams}
	}
	return rt
}

// SetOnChange installs the change callback after construction (the API
// server needs to exist first).
func (r *Registry) SetOnChange(f func()) {
	r.mu.Lock()
	r.onChange = f
	r.mu.Unlock()
}
