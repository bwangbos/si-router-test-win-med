package dhcp4

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Sim is a scripted, in-memory DHCP server used by unit tests and by the
// simulated (fake) backend: it answers DISCOVER/REQUEST with OFFER/ACK and
// can inject NAKs or silence to exercise retry paths.
type Sim struct {
	IP     net.IP // offered address
	Mask   net.IPMask
	GW     net.IP
	DNS    []string
	Lease  time.Duration
	Silent bool // drop everything (retry/backoff testing)
	NAKOn  int  // NAK the Nth REQUEST (0 = never)

	mu     sync.Mutex
	served int
}

// Factory returns a TransportFactory backed by this simulator.
func (s *Sim) Factory() TransportFactory {
	return func(_ string, mac net.HardwareAddr) (Transport, error) {
		return &simTransport{sim: s, mac: mac, rx: make(chan []byte, 8)}, nil
	}
}

type simTransport struct {
	sim    *Sim
	mac    net.HardwareAddr
	rx     chan []byte
	mu     sync.Mutex
	closed bool
}

func (t *simTransport) Send(b []byte, _ *net.UDPAddr) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return fmt.Errorf("closed")
	}
	t.mu.Unlock()
	p, err := Unmarshal(b)
	if err != nil {
		return nil
	}
	switch p.Type() {
	case Discover:
		if t.sim.Silent {
			return nil
		}
		off := t.reply(p, Offer)
		t.push(off)
	case Request:
		if t.sim.Silent {
			return nil
		}
		t.sim.mu.Lock()
		t.sim.served++
		n := t.sim.served
		t.sim.mu.Unlock()
		if t.sim.NAKOn != 0 && n == t.sim.NAKOn {
			b := t.reply(p, Nak)
			t.push(b)
			return nil
		}
		ack := t.reply(p, Ack)
		t.push(ack)
	}
	return nil
}

func (t *simTransport) reply(req *Packet, mt MessageType) []byte {
	s := t.sim
	p := NewPacket(req.XID, t.mac, "")
	p.setType(mt)
	p.YIAddr = s.IP
	sid := net.IPv4(198, 18, 0, 1)
	p.setIP(optServerID, sid)
	p.SIAddr = sid
	if mt == Ack || mt == Offer {
		p.Opts[optSubnet] = append([]byte{}, s.Mask...)
		if s.GW != nil {
			p.Opts[optRouter] = append([]byte{}, s.GW.To4()...)
		}
		var d []byte
		for _, ds := range s.DNS {
			if ip := net.ParseIP(ds).To4(); ip != nil {
				d = append(d, ip...)
			}
		}
		if len(d) > 0 {
			p.Opts[optDNS] = d
		}
		ls := s.Lease
		if ls == 0 {
			ls = time.Hour
		}
		setU32(p.Opts, optLease, uint32(ls.Seconds()))
		setU32(p.Opts, optRenewT1, uint32((ls / 2).Seconds()))
		setU32(p.Opts, optRebindT2, uint32((ls * 7 / 8).Seconds()))
	}
	b, _ := p.Marshal()
	return b
}

func (t *simTransport) push(b []byte) {
	select {
	case t.rx <- b:
	default: // drop when the client is not reading
	}
}

func (t *simTransport) Recv() ([]byte, *net.UDPAddr, error) {
	b, ok := <-t.rx
	if !ok {
		return nil, nil, fmt.Errorf("closed")
	}
	return b, &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: dhcpPort}, nil
}

func (t *simTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.rx)
	}
	return nil
}
