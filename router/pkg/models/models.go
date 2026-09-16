// Package models defines the canonical configuration model for routerd.
package models

// Config is the authoritative desired configuration of the router.
type Config struct {
	Version         int               `json:"version" yaml:"version"`
	System          SystemConfig      `json:"system" yaml:"system"`
	WANs            []WAN             `json:"wans" yaml:"wans"`
	Networks        []Network         `json:"networks" yaml:"networks"`
	StaticRoutes    []StaticRoute     `json:"static_routes,omitempty" yaml:"static_routes,omitempty"`
	FirewallRules   []FirewallRule    `json:"firewall_rules,omitempty" yaml:"firewall_rules,omitempty"`
	PortForwards    []PortForward     `json:"port_forwards,omitempty" yaml:"port_forwards,omitempty"`
	WireGuard       []WireGuardTunnel `json:"wireguard,omitempty" yaml:"wireguard,omitempty"`
	TrafficPolicies []TrafficPolicy   `json:"traffic_policies,omitempty" yaml:"traffic_policies,omitempty"`
	DNS             DNSConfig         `json:"dns" yaml:"dns"`
}

// SystemConfig holds global system settings.
type SystemConfig struct {
	Hostname   string   `json:"hostname" yaml:"hostname"`
	TimeZone   string   `json:"timezone,omitempty" yaml:"timezone,omitempty"`
	NTPServers []string `json:"ntp_servers,omitempty" yaml:"ntp_servers,omitempty"`
}

// WANMode enumerates supported WAN modes.
type WANMode string

const (
	WANModeDHCP   WANMode = "dhcp"
	WANModeStatic WANMode = "static"
	WANModePPPoE  WANMode = "pppoe"
)

// WAN describes a upstream connection.
type WAN struct {
	ID         string         `json:"id" yaml:"id"`
	Name       string         `json:"name" yaml:"name"`
	Interface  string         `json:"interface" yaml:"interface"`
	Mode       WANMode        `json:"mode" yaml:"mode"`
	Enabled    *bool          `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Metric     int            `json:"metric" yaml:"metric"`
	MACAddr    string         `json:"mac,omitempty" yaml:"mac,omitempty"`
	Static     *StaticWAN     `json:"static,omitempty" yaml:"static,omitempty"`
	PPPoE      *PPPoEWAN      `json:"pppoe,omitempty" yaml:"pppoe,omitempty"`
	DNS        []string       `json:"dns,omitempty" yaml:"dns,omitempty"`
	IPv6Mode   string         `json:"ipv6_mode,omitempty" yaml:"ipv6_mode,omitempty"` // none|slaac|dhcpv6|dhcpv6-pd|static
	IPv6Static *IPv6StaticWAN `json:"ipv6_static,omitempty" yaml:"ipv6_static,omitempty"`
}

// StaticWAN is static WAN addressing.
type StaticWAN struct {
	Address string   `json:"address" yaml:"address"` // CIDR, e.g. 203.0.113.5/24
	Gateway string   `json:"gateway" yaml:"gateway"`
	DNS     []string `json:"dns,omitempty" yaml:"dns,omitempty"`
}

// PPPoEWAN holds PPPoE credentials.
type PPPoEWAN struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

// IPv6StaticWAN holds static IPv6 WAN configuration.
type IPv6StaticWAN struct {
	Address string `json:"address" yaml:"address"` // CIDR
	Gateway string `json:"gateway" yaml:"gateway"`
}

// VLANConfig describes an 802.1Q interface attached to a network.
type VLANConfig struct {
	Parent string `json:"parent" yaml:"parent"`
	ID     int    `json:"id" yaml:"id"`
}

// DHCPServer describes per-network DHCP service.
type DHCPServer struct {
	Enabled      bool              `json:"enabled" yaml:"enabled"`
	Start        string            `json:"start,omitempty" yaml:"start,omitempty"`
	End          string            `json:"end,omitempty" yaml:"end,omitempty"`
	LeaseSeconds int               `json:"lease_seconds,omitempty" yaml:"lease_seconds,omitempty"`
	DNS          []string          `json:"dns,omitempty" yaml:"dns,omitempty"`
	Reservations []DHCPReservation `json:"reservations,omitempty" yaml:"reservations,omitempty"`
}

// DHCPReservation maps a MAC to a fixed address.
type DHCPReservation struct {
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	MAC  string `json:"mac" yaml:"mac"`
	IP   string `json:"ip" yaml:"ip"`
}

// Network is a routed LAN segment served by the router.
type Network struct {
	ID         string      `json:"id" yaml:"id"`
	Name       string      `json:"name" yaml:"name"`
	Interface  string      `json:"interface" yaml:"interface"` // bridge or plain interface
	VLAN       *VLANConfig `json:"vlan,omitempty" yaml:"vlan,omitempty"`
	Members    []string    `json:"members,omitempty" yaml:"members,omitempty"` // bridge ports
	Subnet     string      `json:"subnet" yaml:"subnet"`                       // router IPv4 address in CIDR form
	IPv6Subnet string      `json:"ipv6_subnet,omitempty" yaml:"ipv6_subnet,omitempty"`
	DHCP       DHCPServer  `json:"dhcp" yaml:"dhcp"`
	Zone       string      `json:"zone" yaml:"zone"`
	// Policy flags (default: internet allowed, LAN access denied for untrusted zones)
	InternetAccess *bool `json:"internet_access,omitempty" yaml:"internet_access,omitempty"`
	AccessToLAN    *bool `json:"access_to_lan,omitempty" yaml:"access_to_lan,omitempty"`
	IPv6RA         bool  `json:"ipv6_ra,omitempty" yaml:"ipv6_ra,omitempty"`
}

// HasInternet reports the effective internet-access flag (default true).
func (n Network) HasInternet() bool {
	return n.InternetAccess == nil || *n.InternetAccess
}

// CanAccessLAN reports the effective LAN-access flag (default false for non-LAN zones).
func (n Network) CanAccessLAN() bool {
	return n.AccessToLAN != nil && *n.AccessToLAN
}

// StaticRoute is a kernel static route.
type StaticRoute struct {
	ID          string `json:"id" yaml:"id"`
	Destination string `json:"destination" yaml:"destination"` // CIDR
	Via         string `json:"via,omitempty" yaml:"via,omitempty"`
	Device      string `json:"device,omitempty" yaml:"device,omitempty"`
	Metric      int    `json:"metric,omitempty" yaml:"metric,omitempty"`
	Table       int    `json:"table,omitempty" yaml:"table,omitempty"`
}

// Action is a firewall action.
type Action string

const (
	ActionAccept Action = "accept"
	ActionDrop   Action = "drop"
	ActionReject Action = "reject"
	ActionLog    Action = "log"
)

// PortRange is an inclusive port range.
type PortRange struct {
	Start uint16 `json:"start" yaml:"start"`
	End   uint16 `json:"end" yaml:"end"`
}

// FirewallRule is a zone-to-zone policy rule.
type FirewallRule struct {
	ID          string      `json:"id" yaml:"id"`
	Name        string      `json:"name,omitempty" yaml:"name,omitempty"`
	SourceZone  string      `json:"source_zone" yaml:"source_zone"`
	DestZone    string      `json:"dest_zone" yaml:"dest_zone"`
	Protocol    string      `json:"protocol" yaml:"protocol"` // any|tcp|udp|icmp
	Source      []string    `json:"source,omitempty" yaml:"source,omitempty"`
	Destination []string    `json:"destination,omitempty" yaml:"destination,omitempty"`
	Ports       []PortRange `json:"ports,omitempty" yaml:"ports,omitempty"`
	Action      Action      `json:"action" yaml:"action"`
	Enabled     bool        `json:"enabled" yaml:"enabled"`
}

// PortForward is a WAN DNAT rule.
type PortForward struct {
	ID           string `json:"id" yaml:"id"`
	Name         string `json:"name,omitempty" yaml:"name,omitempty"`
	WAN          string `json:"wan" yaml:"wan"`
	Protocol     string `json:"protocol" yaml:"protocol"` // tcp|udp
	ExternalPort uint16 `json:"external_port" yaml:"external_port"`
	InternalIP   string `json:"internal_ip" yaml:"internal_ip"`
	InternalPort uint16 `json:"internal_port" yaml:"internal_port"`
	Enabled      bool   `json:"enabled" yaml:"enabled"`
}

// WireGuardPeer is one peer of a tunnel.
type WireGuardPeer struct {
	Name                string   `json:"name,omitempty" yaml:"name,omitempty"`
	PublicKey           string   `json:"public_key" yaml:"public_key"`
	AllowedIPs          []string `json:"allowed_ips" yaml:"allowed_ips"`
	Endpoint            string   `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty" yaml:"persistent_keepalive,omitempty"`
}

// WireGuardTunnel is a WG interface definition. PrivateKey is write-only via API.
type WireGuardTunnel struct {
	Name           string          `json:"name,omitempty" yaml:"name,omitempty"`
	PrivateKey     string          `json:"private_key,omitempty" yaml:"private_key,omitempty"`
	ListenPort     int             `json:"listen_port,omitempty" yaml:"listen_port,omitempty"`
	Address        string          `json:"address" yaml:"address"` // tunnel network CIDR
	Table          int             `json:"table,omitempty" yaml:"table,omitempty"`
	PeerAllowedIPs []string        `json:"peer_allowed_ips,omitempty" yaml:"peer_allowed_ips,omitempty"` // routes installed for tunnel subnet
	Peers          []WireGuardPeer `json:"peers,omitempty" yaml:"peers,omitempty"`
	Zone           string          `json:"zone,omitempty" yaml:"zone,omitempty"` // firewall zone, default VPN
}

// TrafficPolicy shapes bandwidth on an interface.
type TrafficPolicy struct {
	Name      string `json:"name" yaml:"name"`
	Interface string `json:"interface" yaml:"interface"`
	UpMbps    int    `json:"up_mbps" yaml:"up_mbps"`
	DownMbps  int    `json:"down_mbps" yaml:"down_mbps"`
	SQM       bool   `json:"sqm" yaml:"sqm"`
	Qdisc     string `json:"qdisc,omitempty" yaml:"qdisc,omitempty"` // cake|fq_codel|tbf
}

// DNSRecord is a static local DNS entry.
type DNSRecord struct {
	Name string `json:"name" yaml:"name"`
	IP   string `json:"ip" yaml:"ip"`
}

// DNSConfig configures the local resolver/forwarder.
type DNSConfig struct {
	Upstreams    []string    `json:"upstreams,omitempty" yaml:"upstreams,omitempty"`
	ListenPort   int         `json:"listen_port,omitempty" yaml:"listen_port,omitempty"`
	LocalRecords []DNSRecord `json:"local_records,omitempty" yaml:"local_records,omitempty"`
}

// Bool returns a pointer to b (helper for optional flags).
func Bool(b bool) *bool { return &b }

// IsEnabled reports whether the WAN is enabled (default true when unset).
func (w WAN) IsEnabled() bool { return w.Enabled == nil || *w.Enabled }

// IsWANIface reports whether the named interface is used by a WAN.
func (c Config) IsWANIface(name string) bool {
	for _, w := range c.WANs {
		if w.Interface == name {
			return true
		}
	}
	return false
}
