// Package dhcp4 implements a minimal RFC 2131/2132 DHCPv4 client: packet
// codec, state machine and per-WAN lifecycle manager. The client itself
// never touches the kernel: acquired leases land in a Registry which feeds
// the reconciliation engine as runtime input, preserving the single write
// path and working against both the real and the simulated backends.
package dhcp4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// MessageType is DHCP option 53.
type MessageType uint8

// DHCP message types used by the client.
const (
	Discover MessageType = 1
	Offer    MessageType = 2
	Request  MessageType = 3
	Decline  MessageType = 4
	Ack      MessageType = 5
	Nak      MessageType = 6
	Release  MessageType = 7
)

// DHCP option codes.
const (
	optPad        = 0
	optSubnet     = 1
	optRouter     = 3
	optDNS        = 6
	optDomain     = 15
	optHostName   = 12
	optReqIP      = 50
	optLease      = 51
	optMsgType    = 53
	optServerID   = 54
	optParamReq   = 55
	optRenewT1    = 58
	optRebindT2   = 59
	optClassRoute = 121
	optVendor     = 60
	optClientID   = 61
	optEnd        = 255
)

var magicCookie = []byte{99, 130, 83, 69} // RFC 2131 magic: 99.130.83.69

// Packet is a BOOTP/DHCP message.
type Packet struct {
	Op     uint8
	HType  uint8
	HLen   uint8
	Hops   uint8
	XID    uint32
	Secs   uint16
	Flags  uint16
	CIAddr net.IP
	YIAddr net.IP
	SIAddr net.IP
	GIAddr net.IP
	CHAddr net.HardwareAddr
	SName  string
	File   string
	Opts   map[uint8][]byte
}

// Type returns the message type option (0 when absent).
func (p *Packet) Type() MessageType {
	if b, ok := p.Opts[optMsgType]; ok && len(b) == 1 {
		return MessageType(b[0])
	}
	return 0
}

func (p *Packet) set(b []byte)          { p.Opts[optMsgType] = []byte{byte(b[0])} } //nolint:unused
func (p *Packet) setType(t MessageType) { p.Opts[optMsgType] = []byte{byte(t)} }

// IP returns a single-IPv4 option.
func (p *Packet) IP(code uint8) net.IP {
	if b, ok := p.Opts[code]; len(b) == 4 && ok {
		return net.IPv4(b[0], b[1], b[2], b[3])
	}
	return nil
}

// IPv4List parses a packed IPv4 list option (router, DNS).
func (p *Packet) IPv4List(code uint8) []net.IP {
	b := p.Opts[code]
	var out []net.IP
	for i := 0; i+3 < len(b) && (i+4)%4 == 0; i += 4 {
		out = append(out, net.IPv4(b[i], b[i+1], b[i+2], b[i+3]))
	}
	return out
}

// Uint32 returns a 4-byte numeric option.
func (p *Packet) Uint32(code uint8) (uint32, bool) {
	b := p.Opts[code]
	if len(b) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

func (p *Packet) setIP(code uint8, ip net.IP) {
	if ip == nil {
		return
	}
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	p.Opts[code] = append([]byte{}, v4...)
}

func setU32(opts map[uint8][]byte, code uint8, v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	opts[code] = b
}

// NewRequestPacket builds a DISCOVER/REQUEST/RENEW base packet.
func NewPacket(xid uint32, mac net.HardwareAddr, hostname string) *Packet {
	opts := map[uint8][]byte{
		optParamReq: {optSubnet, optRouter, optDNS, optDomain, optHostName,
			optLease, optRenewT1, optRebindT2, optClassRoute, optVendor},
		optVendor:   []byte("routerd"),
		optClientID: append([]byte{1}, mac...), // type 1 = Ethernet
	}
	if hostname != "" {
		opts[optHostName] = []byte(hostname)
	}
	return &Packet{Op: 1, HType: 1, HLen: 6, XID: xid, Flags: 0x8000,
		CHAddr: mac, Opts: opts}
}

// Marshal serializes the packet.
func (p *Packet) Marshal() ([]byte, error) {
	if len(p.CHAddr) > 16 {
		return nil, errors.New("chaddr too long")
	}
	if p.HLen > 16 {
		return nil, errors.New("hlen too long")
	}
	buf := make([]byte, 236, 512)
	buf[0] = p.Op
	buf[1] = p.HType
	buf[2] = p.HLen
	buf[3] = p.Hops
	binary.BigEndian.PutUint32(buf[4:], p.XID)
	binary.BigEndian.PutUint16(buf[8:], p.Secs)
	binary.BigEndian.PutUint16(buf[10:], p.Flags)
	copyTo4(buf[12:], p.CIAddr)
	copyTo4(buf[16:], p.YIAddr)
	copyTo4(buf[20:], p.SIAddr)
	copyTo4(buf[24:], p.GIAddr)
	copy(buf[28:], p.CHAddr)
	copyString(buf[40:], p.SName)
	copyString(buf[104:], p.File)
	buf = append(buf, magicCookie...)
	codes := optionOrder(p.Opts)
	for _, c := range codes {
		v := p.Opts[c]
		if c == optPad || c == optEnd {
			continue
		}
		if len(v) > 255 {
			return nil, fmt.Errorf("option %d too long", c)
		}
		buf = append(buf, c, uint8(len(v)))
		buf = append(buf, v...)
	}
	buf = append(buf, optEnd)
	return buf, nil
}

// Unmarshal parses a DHCP packet.
func Unmarshal(b []byte) (*Packet, error) {
	if len(b) < 244 {
		return nil, errors.New("packet too short")
	}
	p := &Packet{Op: b[0], HType: b[1], HLen: b[2], Hops: b[3],
		XID: binary.BigEndian.Uint32(b[4:]), Secs: binary.BigEndian.Uint16(b[8:]),
		Flags:  binary.BigEndian.Uint16(b[10:]),
		CIAddr: ipFrom(b[12:]), YIAddr: ipFrom(b[16:]), SIAddr: ipFrom(b[20:]),
		GIAddr: ipFrom(b[24:]), Opts: map[uint8][]byte{}}
	hlen := int(b[2])
	if hlen > 16 {
		return nil, errors.New("bad hlen")
	}
	p.CHAddr = net.HardwareAddr(append([]byte{}, b[28:28+hlen]...))
	p.SName = stringFrom(b[40:104])
	p.File = stringFrom(b[104:236])
	if b[236] != 99 || b[237] != 130 || b[238] != 83 || b[239] != 69 {
		return nil, errors.New("bad magic cookie")
	}
	i := 240
	for i < len(b) {
		c := b[i]
		if c == optEnd {
			break
		}
		if c == optPad {
			i++
			continue
		}
		if i+1 >= len(b) {
			return nil, errors.New("truncated option")
		}
		l := int(b[i+1])
		if i+2+l > len(b) {
			return nil, errors.New("truncated option value")
		}
		p.Opts[c] = b[i+2 : i+2+l]
		i += 2 + l
	}
	return p, nil
}

// LeaseFromAck extracts the runtime lease fields from an ACK.
func LeaseFromAck(p *Packet, cfgLeaseSec uint32) (ip, router, serverID net.IP, mask net.IPMask, dns []net.IP, leaseSec, t1, t2 uint32) {
	ip = p.YIAddr
	serverID = p.IP(optServerID)
	if serverID == nil {
		serverID = p.SIAddr
	}
	if m := p.IP(optSubnet); m != nil {
		mask = net.IPMask(m.To4())
	} else {
		mask = net.CIDRMask(24, 32)
	}
	if rs := p.IPv4List(optRouter); len(rs) > 0 {
		router = rs[0]
	}
	dns = p.IPv4List(optDNS)
	leaseSec = cfgLeaseSec
	if v, ok := p.Uint32(optLease); ok {
		leaseSec = v
	}
	t1 = leaseSec / 2
	if v, ok := p.Uint32(optRenewT1); ok {
		t1 = v
	}
	t2 = leaseSec * 7 / 8
	if v, ok := p.Uint32(optRebindT2); ok {
		t2 = v
	}
	return
}

func copyTo4(dst []byte, ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		copy(dst, v4)
	}
}

func ipFrom(b []byte) net.IP {
	for _, x := range b[:4] {
		if x != 0 {
			return net.IPv4(b[0], b[1], b[2], b[3])
		}
	}
	return nil
}

func copyString(dst []byte, s string) { copy(dst, s) }

func stringFrom(b []byte) string {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	return string(b[:i])
}

// deterministic option emission order (RFC allows any, stability helps tests)
func optionOrder(opts map[uint8][]byte) []uint8 {
	order := []uint8{optMsgType, optReqIP, optServerID, optClientID, optVendor,
		optHostName, optParamReq, optLease, optRenewT1, optRebindT2,
		optSubnet, optRouter, optDNS, optDomain, optClassRoute}
	var out []uint8
	seen := map[uint8]bool{}
	for _, c := range order {
		if _, ok := opts[c]; ok {
			out = append(out, c)
			seen[c] = true
		}
	}
	for c := range opts {
		if !seen[c] {
			out = append(out, c)
		}
	}
	return out
}
