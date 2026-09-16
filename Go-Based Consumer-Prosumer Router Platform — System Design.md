# Go-Based Consumer/Prosumer Router Platform

## 1. Purpose

The purpose of this project is to build a maintainable, reliable consumer/prosumer router platform using:

- Go for the primary management and control daemon
- Linux for packet forwarding and kernel networking
- nftables for firewalling and NAT
- Linux routing and netlink for Layer 3 configuration
- Linux bridges and VLAN interfaces for Layer 2 networking
- WireGuard for VPN functionality
- Linux traffic control for QoS and traffic shaping
- Existing mature DNS/DHCP services where appropriate
- A browser-based interface for administration

The system is intended to provide functionality comparable to a capable home, small-office, or prosumer router rather than an ISP or carrier-class router.

Typical deployment targets include:

- home gateways
- small offices
- homelabs
- prosumer routers
- multi-VLAN residential networks
- remote-office gateways
- x86 mini PCs
- ARM64 router appliances
- virtual machines

The central design principle is:

> Go controls networking state; Linux performs packet forwarding.

The platform should avoid implementing packet forwarding, TCP/IP, NAT, connection tracking, bridging, and similar mature Linux networking functionality from scratch.

---

# 2. Primary Goals

The platform should provide:

- WAN connectivity
- LAN connectivity
- IPv4 routing
- IPv6 routing
- NAT
- stateful firewalling
- DHCP
- DNS forwarding
- VLANs
- multiple network segments
- guest network isolation
- IoT network isolation
- static routing
- policy-based routing
- WireGuard VPN
- port forwarding
- QoS and bandwidth management
- device discovery
- network monitoring
- configuration persistence
- configuration rollback
- REST API
- web administration
- command-line administration
- system health reporting
- auditable configuration changes

The system should be usable on a router with approximately:

- 2–8 Ethernet interfaces
- 1–50 VLANs
- 1–500 client devices
- 1–10 WAN connections
- up to several gigabits per second of forwarding depending on hardware

Linux, not Go, determines the actual forwarding capacity.

---

# 3. Non-Goals

The initial system will not attempt to provide:

- BGP
- IS-IS
- MPLS
- EVPN
- carrier-grade NAT
- large-scale dynamic routing
- ISP subscriber management
- broadband aggregation
- custom Ethernet forwarding
- custom TCP/IP implementation
- custom connection tracking
- software packet forwarding in userspace
- DPDK
- AF_XDP forwarding
- switch ASIC control

OSPF may eventually be supported as an optional advanced feature, but it is not required for the core product.

---

# 4. High-Level Architecture

The system consists of a privileged Go daemon named:

`routerd`

The architecture is:

```text
                     ┌───────────────────────┐
                     │      Web Browser      │
                     └───────────┬───────────┘
                                 │ HTTPS
                                 ▼
                     ┌───────────────────────┐
                     │        routerd        │
                     │                       │
                     │ REST / API            │
                     │ configuration         │
                     │ reconciliation        │
                     │ monitoring            │
                     │ service management    │
                     └───────────┬───────────┘
                                 │
           ┌─────────────────────┼──────────────────────┐
           │                     │                      │
           ▼                     ▼                      ▼
       Netlink               nftables                  tc
           │                     │                      │
           ▼                     ▼                      ▼
     Interfaces/routes       Firewall/NAT           QoS/SQM
           │                     │                      │
           └─────────────────────┼──────────────────────┘
                                 │
                         Linux kernel
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
          ▼                      ▼                      ▼
        WAN                     LAN                   VLANs
```

Additional system services can be controlled by `routerd`:

```text
routerd
   │
   ├── DHCP service
   ├── DNS service
   ├── WireGuard
   ├── NTP
   └── optional UPnP/NAT-PMP service
```

---

# 5. Architectural Model

The core daemon should use a desired-state model.

The administrator expresses what the network should look like.

For example:

```yaml
networks:
  - name: lan
    interface: br-lan
    subnet: 192.168.1.1/24
    dhcp: true

  - name: iot
    vlan: 20
    subnet: 192.168.20.1/24
    dhcp: true
    internet_access: true
    access_to_lan: false
```

`routerd` converts this configuration into Linux networking state.

```text
Configuration
      │
      ▼
Validation
      │
      ▼
Desired State
      │
      ▼
Reconciliation Engine
      │
      ├── Interfaces
      ├── Routes
      ├── nftables
      ├── DHCP
      ├── DNS
      ├── WireGuard
      └── QoS
```

The daemon continuously compares:

```text
desired state
      vs.
actual system state
```

and corrects differences.

This makes configuration deterministic and recoverable.

---

# 6. Core Process

The main daemon is:

```text
/usr/sbin/routerd
```

Responsibilities:

- load configuration
- validate configuration
- maintain authoritative desired state
- observe Linux networking state
- reconcile desired state with actual state
- manage supporting services
- provide management API
- provide metrics
- maintain event logs
- perform atomic configuration changes
- perform rollback when configuration fails

The daemon should be supervised using:

```text
systemd
```

or an equivalent init system.

---

# 7. Internal Go Architecture

Suggested repository layout:

```text
router/
├── cmd/
│   ├── routerd/
│   └── routerctl/
│
├── internal/
│   ├── config/
│   ├── state/
│   ├── reconcile/
│   ├── network/
│   │   ├── link/
│   │   ├── address/
│   │   ├── route/
│   │   ├── bridge/
│   │   ├── vlan/
│   │   └── neighbor/
│   │
│   ├── firewall/
│   ├── nat/
│   ├── qos/
│   ├── dhcp/
│   ├── dns/
│   ├── wireguard/
│   ├── policy/
│   ├── monitor/
│   ├── auth/
│   ├── audit/
│   ├── api/
│   └── platform/
│
├── pkg/
│   └── models/
│
├── web/
│
├── configs/
│
├── migrations/
│
└── tests/
```

---

# 8. Core Configuration Model

The router should have a canonical configuration representation.

Suggested major objects:

```text
System
Interface
WAN
Network
VLAN
DHCPPool
DNSConfig
Route
FirewallZone
FirewallRule
PortForward
NATRule
WireGuardTunnel
WireGuardPeer
TrafficPolicy
User
Service
```

An interface definition might resemble:

```go
type Interface struct {
    ID       string
    Name     string
    Type     InterfaceType
    Enabled  bool
    MTU      int
}
```

A network:

```go
type Network struct {
    ID          string
    Name        string
    InterfaceID string

    IPv4 *IPv4Config
    IPv6 *IPv6Config

    DHCP DHCPConfig

    Zone string
}
```

WAN configuration:

```go
type WANConfig struct {
    Mode WANMode

    DHCP   *DHCPWANConfig
    Static *StaticWANConfig
    PPPoE  *PPPoEConfig

    DNS       []netip.Addr
    Metric    int
    Enabled   bool
}
```

Supported modes:

```text
DHCP
Static
PPPoE
```

---

# 9. Network Interface Management

The interface manager controls:

- Ethernet interfaces
- bridges
- VLAN interfaces
- loopback interfaces
- WireGuard interfaces

It should support:

- administrative up/down
- MTU
- MAC address override
- IPv4 addresses
- IPv6 addresses
- interface membership
- bridge membership
- VLAN tagging

Linux configuration is performed through netlink.

Example:

```text
eth0
 │
 └── WAN

eth1
 │
 └── br-lan
       │
       ├── VLAN 1   LAN
       ├── VLAN 20  IoT
       └── VLAN 30  Guest
```

---

# 10. WAN Management

WAN should support:

### IPv4

- DHCP client
- static addressing
- PPPoE

### IPv6

- DHCPv6
- prefix delegation
- static IPv6
- SLAAC where appropriate

WAN state should expose:

```text
link status
IP address
gateway
DNS
DHCP lease
prefix delegation
uptime
RX/TX statistics
packet errors
```

---

# 11. LAN Management

LAN networks should support:

- static router address
- IPv4 subnet
- IPv6 prefix
- DHCP
- DHCP reservations
- DNS configuration
- VLAN assignment
- firewall zone
- isolation policies

Example:

```text
LAN
192.168.1.0/24

IoT
192.168.20.0/24

Guest
192.168.30.0/24

Servers
192.168.40.0/24
```

---

# 12. VLAN Support

Support IEEE 802.1Q VLANs.

Required operations:

- create VLAN
- delete VLAN
- assign VLAN ID
- assign parent interface
- assign IP configuration
- attach VLAN to bridge
- assign firewall zone

VLAN ID range:

```text
1–4094
```

The configuration layer should prevent conflicting VLAN assignments.

---

# 13. Routing

Routing should rely on the Linux kernel routing subsystem.

Required capabilities:

- connected routes
- default routes
- static routes
- multiple routing tables
- route metrics
- policy routing

Example:

```text
0.0.0.0/0        via WAN
192.168.1.0/24    LAN
192.168.20.0/24   IoT
192.168.30.0/24   Guest
10.50.0.0/24      WireGuard
```

Optional later support:

- route health checking
- WAN failover
- weighted multi-WAN
- source-based routing

---

# 14. Firewall

Firewalling should use nftables.

Users should not normally interact directly with nftables syntax.

Instead, the configuration system should expose concepts such as:

```text
zones
rules
services
port forwards
device groups
address groups
```

Example zones:

```text
WAN
LAN
GUEST
IOT
VPN
```

A rule might be represented as:

```go
type FirewallRule struct {
    ID          string
    Name        string
    SourceZone  string
    DestZone    string
    Protocol    string
    Source      []netip.Prefix
    Destination []netip.Prefix
    Ports       []PortRange
    Action      Action
    Enabled     bool
}
```

Supported actions:

```text
accept
drop
reject
log
```

---

# 15. Default Firewall Policy

Default configuration:

```text
WAN -> router      DROP
WAN -> LAN         DROP

LAN -> WAN         ACCEPT
LAN -> router      ACCEPT

Guest -> WAN       ACCEPT
Guest -> LAN       DROP
Guest -> IoT       DROP

IoT -> WAN         ACCEPT
IoT -> LAN         DROP
```

Stateful return traffic should be allowed through Linux connection tracking.

---

# 16. NAT

NAT should use nftables.

Required functionality:

- IPv4 masquerading
- SNAT
- DNAT
- port forwarding
- hairpin NAT
- optional 1:1 NAT

Example port-forward model:

```go
type PortForward struct {
    Name         string
    WAN          string
    Protocol     Protocol

    ExternalPort uint16

    InternalIP   netip.Addr
    InternalPort uint16

    Enabled bool
}
```

Example:

```text
WAN TCP/443
   ↓
192.168.40.10:443
```

---

# 17. DHCP

DHCP services should initially be provided by an existing daemon rather than implemented from scratch.

`routerd` should manage:

- subnet configuration
- DHCP ranges
- lease duration
- reservations
- DNS options
- gateway options
- NTP options

Example:

```text
network: LAN
subnet: 192.168.1.0/24

pool:
192.168.1.100
-
192.168.1.220

gateway:
192.168.1.1

DNS:
192.168.1.1
```

The router API should expose active DHCP leases.

---

# 18. DNS

The router should provide a local DNS resolver/forwarder.

Required functionality:

- forward DNS queries
- cache responses
- local hostname registration
- DHCP hostname integration
- configurable upstream DNS
- split DNS
- per-network DNS configuration

Possible upstream modes:

```text
ISP DNS
manual DNS
DNS-over-TLS
DNS-over-HTTPS
```

Encrypted DNS can be a later feature.

---

# 19. IPv6

IPv6 should be considered a core capability rather than an afterthought.

Support:

- DHCPv6
- prefix delegation
- router advertisements
- SLAAC
- IPv6 firewalling
- static IPv6 routes
- multiple LAN prefixes

Typical model:

```text
ISP
 │
 │ DHCPv6-PD /56
 ▼
Router
 │
 ├── LAN    /64
 ├── IoT    /64
 ├── Guest  /64
 └── Server /64
```

IPv6 should generally not use NAT.

Firewall behavior should provide equivalent isolation to IPv4.

---

# 20. WireGuard

WireGuard should be the primary VPN technology.

Supported use cases:

### Remote-access VPN

```text
Laptop
   │
Internet
   │
WireGuard
   │
Router
   │
LAN
```

### Site-to-site VPN

```text
Site A
10.10.0.0/24
   │
WireGuard
   │
Site B
10.20.0.0/24
```

Configuration entities:

```text
Tunnel
Peer
Public key
Private key
Allowed IPs
Endpoint
Keepalive
Route policy
```

Private keys should never be exposed through normal API responses.

---

# 21. Multi-WAN

Prosumer deployments should optionally support multiple WAN connections.

Example:

```text
              ┌── WAN1 fiber
Router ───────┤
              └── WAN2 cellular
```

Initial multi-WAN support should include:

- priority-based failover
- health checks
- route switching

Later:

- load balancing
- policy-based WAN selection
- per-device WAN policies

---

# 22. QoS and Traffic Management

QoS should use Linux traffic control.

Initial scope:

- bandwidth limits
- per-interface shaping
- WAN upload shaping
- WAN download shaping
- queue management

Prosumer features may include:

- SQM
- CAKE
- fq_codel

Configuration might expose:

```text
WAN bandwidth:
940 Mbps down
40 Mbps up

SQM:
enabled
```

The management layer should hide most qdisc implementation details.

---

# 23. Device Management

The router should maintain an inventory of known devices.

Information may come from:

- DHCP leases
- ARP
- IPv6 neighbor discovery
- bridge forwarding database
- hostname resolution

Device model:

```text
MAC address
IPv4 address
IPv6 addresses
hostname
interface
network
first seen
last seen
manufacturer
traffic usage
```

Users should be able to assign friendly names.

Example:

```text
MAC:       AA:BB:CC:DD:EE:FF
Name:      Living Room TV
Network:   IoT
IPv4:      192.168.20.42
```

---

# 24. Service Discovery

Optional support:

- mDNS reflection
- SSDP handling
- limited cross-VLAN discovery

These features should be explicit because blindly forwarding discovery traffic across isolated networks can weaken segmentation.

Example:

```text
IoT VLAN
   │
mDNS reflector
   │
LAN
```

---

# 25. Configuration Engine

Configuration changes should follow:

```text
request
   ↓
parse
   ↓
validate
   ↓
calculate desired state
   ↓
generate execution plan
   ↓
apply changes
   ↓
verify
   ↓
commit
```

If verification fails:

```text
rollback
```

The system should avoid partially applying configurations whenever possible.

---

# 26. Configuration Transactions

The API should support transactional configuration.

Example:

```text
BEGIN

create VLAN 20
create network IoT
create DHCP pool
create firewall zone
create isolation rule

VALIDATE

APPLY

COMMIT
```

If a step fails:

```text
ROLLBACK
```

This becomes especially important when remote administration is used.

---

# 27. Safe Remote Configuration

Network configuration has an unusual failure mode:

The administrator can accidentally lock themselves out.

The system should therefore support confirmed commits.

Example:

```text
apply configuration

start 120-second confirmation timer

if user confirms:
    commit

otherwise:
    rollback
```

This is particularly important for:

- changing LAN address
- changing VLANs
- modifying firewall rules
- modifying management access
- changing routes

---

# 28. Reconciliation Engine

The reconciliation engine is the heart of `routerd`.

Each subsystem should implement roughly:

```go
type Reconciler interface {
    Observe(ctx context.Context) (ActualState, error)

    Plan(
        desired DesiredState,
        actual ActualState,
    ) ([]Operation, error)

    Apply(
        ctx context.Context,
        operations []Operation,
    ) error
}
```

Individual reconcilers:

```text
LinkReconciler
AddressReconciler
RouteReconciler
BridgeReconciler
VLANReconciler
FirewallReconciler
NATReconciler
DHCPReconciler
DNSReconciler
WireGuardReconciler
QoSReconciler
```

---

# 29. Event Model

`routerd` should react to system events instead of relying entirely on polling.

Examples:

```text
interface connected
interface disconnected
IP address changed
default route changed
DHCP lease acquired
DHCP lease expired
WireGuard peer changed
client joined network
client left network
WAN failed
WAN recovered
```

Internal events can be distributed through Go channels or a lightweight internal event bus.

---

# 30. Concurrency Model

Go's concurrency model fits the daemon well.

A simplified runtime could be:

```text
main
 │
 ├── config manager goroutine
 ├── netlink listener goroutine
 ├── reconciliation worker
 ├── DHCP state watcher
 ├── WireGuard monitor
 ├── metrics collector
 ├── API server
 └── audit logger
```

Subsystems should communicate through typed messages rather than shared mutable state wherever practical.

---

# 31. Management API

The daemon should expose a versioned API:

```text
/api/v1/
```

Example endpoints:

```text
GET    /api/v1/system

GET    /api/v1/interfaces
GET    /api/v1/interfaces/{id}

GET    /api/v1/networks
POST   /api/v1/networks
PATCH  /api/v1/networks/{id}
DELETE /api/v1/networks/{id}

GET    /api/v1/routes

GET    /api/v1/firewall/rules
POST   /api/v1/firewall/rules

GET    /api/v1/devices

GET    /api/v1/wireguard/tunnels

GET    /api/v1/wan/status

GET    /api/v1/events
```

JSON should be the primary API representation.

---

# 32. CLI

A companion utility:

```text
routerctl
```

Example commands:

```text
routerctl status

routerctl interfaces

routerctl networks list

routerctl networks add

routerctl firewall rules

routerctl devices

routerctl wireguard peers

routerctl config validate

routerctl config apply
```

The CLI should communicate with `routerd` rather than modifying Linux networking directly.

---

# 33. Web Interface

The browser UI should use the same API as the CLI.

Suggested sections:

```text
Dashboard

Internet
Networks
Wi-Fi
Devices
Firewall
Port Forwards
VPN
Traffic Management
System
Logs
```

If wireless access points are eventually managed externally, Wi-Fi management can be separated from the router core.

---

# 34. Authentication

Administrative authentication should support:

- local administrator accounts
- password hashing
- secure sessions
- API tokens
- optional MFA later

Administrative management should be HTTPS-only except possibly during initial device provisioning.

---

# 35. Authorization

Initial implementation can support:

```text
Administrator
Read-only
```

Later:

```text
Network Administrator
Security Administrator
Viewer
API Service Account
```

---

# 36. Security Architecture

`routerd` requires elevated networking privileges, so attack surface should be minimized.

Security requirements:

- never execute arbitrary shell input
- validate every configuration value
- avoid generating shell commands where native APIs exist
- use netlink directly where possible
- restrict filesystem permissions
- protect private keys
- use secure defaults
- bind management services to trusted networks
- disable WAN administration by default

The web interface should never directly modify kernel state.

All changes must pass through `routerd`.

---

# 37. Privilege Model

Initially, the daemon may run as root for simplicity.

Longer term, capabilities should be reduced to the minimum required set.

Potential Linux capabilities include:

```text
CAP_NET_ADMIN
CAP_NET_RAW
```

Supporting services should run under separate unprivileged users wherever practical.

---

# 38. Persistence

Persistent configuration should be stored separately from runtime state.

Example:

```text
/var/lib/routerd/
    config.db
    state.db
    backups/
```

Configuration storage could use SQLite.

SQLite is appropriate because:

- the database is local
- configuration size is small
- transactions are important
- backup is simple
- operational overhead is minimal

---

# 39. Configuration History

Every successful configuration should create a version.

Example:

```text
Revision 104
2026-09-16 11:32

Changed:
- created IoT VLAN
- added DHCP pool
- blocked IoT -> LAN
```

Users should be able to:

```text
view revision
compare revision
restore revision
```

---

# 40. Audit Logging

Security-sensitive actions should be recorded.

Example:

```text
timestamp
user
source IP
action
object
old value
new value
result
```

Examples:

```text
admin created firewall rule
admin changed WAN configuration
admin added WireGuard peer
admin changed password
```

---

# 41. Operational Logging

Use structured logging.

Example:

```json
{
  "level": "info",
  "component": "wan",
  "interface": "eth0",
  "event": "dhcp_lease_acquired"
}
```

Logs should include:

```text
system
network
firewall
VPN
DHCP
DNS
configuration
authentication
```

---

# 42. Metrics

Prometheus-compatible metrics are desirable.

Example metrics:

```text
router_interface_rx_bytes
router_interface_tx_bytes

router_interface_rx_packets
router_interface_tx_packets

router_wan_up

router_dhcp_active_leases

router_wireguard_peer_rx_bytes
router_wireguard_peer_tx_bytes

router_config_apply_duration_seconds

router_firewall_dropped_packets
```

---

# 43. Health Monitoring

The system should continuously assess:

```text
WAN availability
default gateway reachability
DNS health
DHCP health
WireGuard state
interface state
storage space
memory
CPU
temperature
```

Health status:

```text
healthy
degraded
unhealthy
```

---

# 44. Hardware Targets

Initial hardware support should focus on standard Linux-compatible systems.

Recommended architecture targets:

```text
amd64
arm64
```

Typical hardware:

```text
Intel N100/N150 router
Intel Atom
AMD embedded systems
ARM64 SBC
virtual machine
```

The networking layer should avoid hardware-specific assumptions.

---

# 45. Performance Targets

Because Linux performs the dataplane work, `routerd` should have modest requirements.

Management-plane targets:

```text
idle CPU: <1%

normal memory:
50–150 MB

configuration apply:
<1 second for normal changes

API response:
<100 ms for common local requests

startup:
<5 seconds
```

These are engineering targets rather than forwarding guarantees.

Forwarding speed depends on:

- NIC
- CPU
- kernel
- offload configuration
- nftables rule complexity
- QoS
- VPN encryption
- packet size

---

# 46. Reliability Requirements

The router should continue forwarding traffic if `routerd` crashes.

This is an important architectural property.

Because Linux maintains:

```text
routes
addresses
firewall rules
NAT
WireGuard interfaces
```

existing traffic should generally continue while the management daemon restarts.

The daemon should reconstruct actual state on startup.

---

# 47. Boot Sequence

Recommended startup:

```text
Linux boots
     │
     ▼
basic interfaces available
     │
     ▼
routerd starts
     │
     ▼
load persistent config
     │
     ▼
inspect actual Linux state
     │
     ▼
calculate difference
     │
     ▼
reconcile interfaces
     │
     ▼
reconcile firewall
     │
     ▼
start DHCP/DNS
     │
     ▼
start API
     │
     ▼
router ready
```

---

# 48. Failure Handling

Each subsystem should distinguish:

```text
temporary failure
permanent configuration error
system error
```

Examples:

```text
WAN DHCP timeout
    -> retry

invalid subnet
    -> reject configuration

netlink failure
    -> retry/reconcile

DNS daemon crash
    -> restart

firewall apply failure
    -> rollback configuration
```

---

# 49. Testing Strategy

Testing should happen at several levels.

## Unit tests

Test:

```text
configuration validation
address calculations
firewall policy generation
routing decisions
API validation
```

## Integration tests

Use Linux network namespaces.

Example:

```text
namespace-wan
      │
   veth pair
      │
   router namespace
      │
   veth pair
      │
namespace-lan
```

This permits realistic router tests without physical hardware.

Test scenarios:

```text
DHCP
NAT
firewall
routing
VLANs
IPv6
WireGuard
WAN failure
configuration rollback
```

## Hardware tests

Maintain a small physical lab with:

```text
router appliance
managed switch
test client
WAN emulator
```

---

# 50. Network Namespace Test Topology

A CI environment can create:

```text
┌────────────┐
│ fake ISP   │
└─────┬──────┘
      │
     veth
      │
┌─────┴──────┐
│   router   │
│ namespace  │
└─────┬──────┘
      │
     veth
      │
┌─────┴──────┐
│ LAN client │
└────────────┘
```

Tests can verify:

```text
client receives DHCP
client reaches Internet
NAT occurs
WAN cannot initiate LAN traffic
DNS works
port forwarding works
```

---

# 51. Dependencies

Prefer a relatively small dependency set.

Important categories:

```text
netlink library
HTTP router
JSON/YAML
SQLite driver
structured logging
metrics
WireGuard control
```

Avoid unnecessary frameworks.

Go's standard library should be used heavily.

---

# 52. External Service Philosophy

Do not reimplement mature network services unless there is a compelling reason.

Good candidates for external services include:

```text
DHCP
DNS
NTP
mDNS
UPnP
```

`routerd` should:

```text
generate configuration
start/reload service
monitor service
consume runtime state
```

This keeps the core project focused on orchestration and policy.

---

# 53. Component Boundaries

The system can be summarized as:

```text
┌─────────────────────────────┐
│          Management         │
│                             │
│ Web / CLI / REST API        │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│           routerd           │
│                             │
│ config                      │
│ state                       │
│ validation                  │
│ reconciliation              │
│ security policy             │
│ monitoring                  │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│        Linux services       │
│                             │
│ DHCP / DNS / WireGuard      │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│         Linux kernel        │
│                             │
│ netlink                     │
│ routing                     │
│ bridges                     │
│ VLAN                        │
│ nftables                    │
│ conntrack                   │
│ tc                          │
│ WireGuard                   │
└──────────────┬──────────────┘
               │
               ▼
              NICs
```

---

# 54. Initial MVP

The first useful version should be intentionally small.

## MVP requirements

Two interfaces:

```text
WAN
LAN
```

WAN:

```text
DHCP IPv4
```

LAN:

```text
192.168.1.1/24
```

Services:

```text
DHCP server
DNS forwarding
```

Firewall:

```text
WAN -> LAN blocked
LAN -> WAN allowed
```

NAT:

```text
LAN -> WAN masquerade
```

Management:

```text
REST API
CLI
persistent config
```

If these work reliably, the project is already a functional router.

---

# 55. Phase 2

Add:

```text
VLANs
multiple LAN networks
guest network
IoT isolation
port forwarding
DHCP reservations
IPv6
configuration rollback
web UI
```

---

# 56. Phase 3

Add:

```text
WireGuard
multi-WAN failover
policy routing
SQM
device inventory
traffic statistics
configuration history
```

---

# 57. Phase 4

Advanced prosumer functionality:

```text
site-to-site VPN
per-device policies
DNS filtering
mDNS reflection
traffic analytics
API integrations
OSPF
high availability
```

OSPF should only be added if actual users need dynamic routing.

---

# 58. Technology Stack

Recommended stack:

```text
Core daemon
    Go

Forwarding
    Linux kernel

Networking configuration
    Netlink

Firewall
    nftables

NAT
    nftables

Connection tracking
    Linux conntrack

VPN
    WireGuard

QoS
    Linux tc / CAKE / fq_codel

Configuration database
    SQLite

API
    Go net/http or lightweight HTTP framework

CLI
    Go

Web UI
    TypeScript

Testing
    Go + Python

Integration testing
    Linux network namespaces

Service management
    systemd
```

---

# 59. Design Principles

The system should adhere to several principles.

### Linux is the dataplane

Do not unnecessarily move packet forwarding into userspace.

### Go is the authoritative control plane

Other applications should not independently alter router configuration.

### Configuration is declarative

Describe desired network state rather than maintaining scripts of commands.

### Reconciliation is continuous

The daemon should repair unexpected divergence.

### Configuration is transactional

Avoid half-applied network configurations.

### Routing survives management failure

A crashed web UI or management daemon should not immediately stop forwarding.

### Secure defaults

New networks should not accidentally become reachable from the WAN.

### Advanced features remain optional

A basic home deployment should remain understandable.

---

# 60. Final Scope

The resulting product is not a custom TCP/IP stack.

It is better described as:

> A Go-based network operating and management system built on the Linux networking dataplane.

Its responsibilities are:

```text
configuration
policy
orchestration
state management
monitoring
security
management APIs
```

Linux remains responsible for:

```text
Ethernet forwarding
IP forwarding
neighbor handling
connection tracking
NAT
firewall execution
traffic scheduling
WireGuard encryption
```

This division gives the project a practical balance between reliability, maintainability, development speed, and performance while still allowing substantial control over the complete router experience.