package dhcp4

import (
	"bytes"
	"net"
	"testing"
)

func mustMAC(t *testing.T) net.HardwareAddr {
	t.Helper()
	m, err := net.ParseMAC("02:11:22:33:44:55")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPacketRoundTrip(t *testing.T) {
	p := NewPacket(0xdeadbeef, mustMAC(t), "router")
	p.setType(Discover)
	p.Secs = 3
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if q.XID != p.XID || q.Type() != Discover || q.Secs != 3 {
		t.Fatalf("roundtrip mismatch: %+v", q)
	}
	if q.CHAddr.String() != "02:11:22:33:44:55" {
		t.Fatalf("chaddr=%v", q.CHAddr)
	}
	if string(q.Opts[optVendor]) != "routerd" {
		t.Fatalf("vendor=%q", q.Opts[optVendor])
	}
	if cid := q.Opts[optClientID]; cid[0] != 1 || !bytes.Equal(cid[1:], mustMAC(t)) {
		t.Fatalf("clientid=%v", cid)
	}
}

func TestAckParsing(t *testing.T) {
	p := NewPacket(1, mustMAC(t), "")
	p.setType(Ack)
	p.YIAddr = net.IPv4(192, 0, 2, 50)
	p.setIP(optServerID, net.IPv4(192, 0, 2, 1))
	p.setIP(optSubnet, net.IPv4(255, 255, 255, 0))
	p.Opts[optRouter] = []byte{192, 0, 2, 1}
	p.Opts[optDNS] = []byte{192, 0, 2, 1, 9, 9, 9, 9}
	setU32(p.Opts, optLease, 3600)
	setU32(p.Opts, optRenewT1, 1800)
	setU32(p.Opts, optRebindT2, 3150)
	b, _ := p.Marshal()
	q, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	ip, router, sid, mask, dns, ls, t1, t2 := LeaseFromAck(q, 0)
	if ip.String() != "192.0.2.50" || !bytes.Equal(mask, net.CIDRMask(24, 32)) {
		t.Fatalf("ip=%v mask=%v", ip, mask)
	}
	if router.String() != "192.0.2.1" || sid.String() != "192.0.2.1" {
		t.Fatalf("router=%v sid=%v", router, sid)
	}
	if len(dns) != 2 || dns[1].String() != "9.9.9.9" {
		t.Fatalf("dns=%v", dns)
	}
	if ls != 3600 || t1 != 1800 || t2 != 3150 {
		t.Fatalf("timers=%d/%d/%d", ls, t1, t2)
	}
}

func TestAckDefaults(t *testing.T) {
	p := NewPacket(1, mustMAC(t), "")
	p.setType(Ack)
	p.YIAddr = net.IPv4(10, 0, 0, 9)
	p.SIAddr = net.IPv4(10, 0, 0, 1) // server-id falls back to siaddr
	ip, _, sid, mask, _, ls, t1, _ := LeaseFromAck(p, 7200)
	if ip == nil || !bytes.Equal(mask, net.CIDRMask(24, 32)) {
		t.Fatalf("mask default: %v", mask)
	}
	if sid.String() != "10.0.0.1" {
		t.Fatalf("sid fallback=%v", sid)
	}
	if ls != 7200 || t1 != 3600 {
		t.Fatalf("cfg lease/timing=%d/%d", ls, t1)
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	if _, err := Unmarshal([]byte("short")); err == nil {
		t.Fatal("short packet accepted")
	}
	bad := make([]byte, 244)
	if _, err := Unmarshal(bad); err == nil {
		t.Fatal("bad cookie accepted")
	}
}

// TestMagicCookieRFC pins the wire bytes against RFC 2131 (99.130.83.69):
// third-party servers reject anything else. A self-consistent constant on
// both encode and decode sides hides the typo, hence the literal here.
func TestMagicCookieRFC(t *testing.T) {
	p := &Packet{Op: 1, HType: 1, HLen: 6, XID: 1,
		Opts: map[uint8][]byte{53: {1}}}
	b, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 240 || b[236] != 99 || b[237] != 130 || b[238] != 83 || b[239] != 69 {
		t.Fatalf("magic cookie wrong: %x", b[236:240])
	}
}
