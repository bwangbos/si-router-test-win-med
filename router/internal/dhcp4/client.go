package dhcp4

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	dhcpPort   = 67
	broadcast  = "255.255.255.255"
	discoverTO = 4 * time.Second  // wait for OFFERs per round
	reqTO      = 4 * time.Second  // wait for ACK per REQUEST
	maxBackoff = 64 * time.Second // DISCOVER retry cap (design: timeout -> retry)
)

// client runs the DHCP state machine for one interface.
type client struct {
	iface string
	mac   net.HardwareAddr
	deps  Deps
	xid   uint32
	after func(time.Duration) <-chan time.Time

	// bound lease state
	lease *Lease
	tr    Transport
}

func (c *client) run(ctx context.Context) {
	var backoff time.Duration = 4 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if c.mac == nil {
			// link not ready / MAC unknown: retry quietly
			select {
			case <-ctx.Done():
				return
			case <-c.after(5 * time.Second):
				c.event("dhcp.waiting", c.iface+" (no link)")
			}
			continue
		}
		lease, err := c.discoverLoop(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.event("dhcp.retry", c.iface+": "+err.Error())
			select {
			case <-ctx.Done():
				c.releaseQuiet()
				return
			case <-c.after(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = 4 * time.Second
		c.lease = lease
		c.deps.Reg.set(lease)
		c.event("dhcp.bound", c.iface+" "+lease.CIDR())
		if !c.bound(ctx) {
			c.release()
			return
		}
		// expired or NACKed: forget and restart
		c.deps.Reg.Remove(c.iface)
		c.event("dhcp.expired", c.iface)
	}
}

// discoverLoop performs DISCOVER -> OFFER -> REQUEST -> ACK. Returns the
// bound lease or an error to retry (DISCOVER produced nothing).
func (c *client) discoverLoop(ctx context.Context) (*Lease, error) {
	if err := c.openTransport(); err != nil {
		return nil, err
	}
	defer c.closeTransport()

	c.xid++
	d := NewPacket(c.xid, c.mac, c.deps.Hostname)
	d.setType(Discover)
	if err := c.send(d, broadcast); err != nil {
		return nil, err
	}
	var offer *Packet
	deadline := time.Now().Add(discoverTO)
	for time.Now().Before(deadline) {
		p, _, err := c.recvUntil(ctx, time.Until(deadline))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			break // timeout
		}
		if p.XID != c.xid || p.Type() != Offer || p.YIAddr == nil {
			continue
		}
		offer = p
		break
	}
	if offer == nil {
		return nil, errors.New("no offer")
	}

	req := NewPacket(c.xid, c.mac, c.deps.Hostname)
	req.setType(Request)
	req.setIP(optReqIP, offer.YIAddr)
	req.setIP(optServerID, offer.IP(optServerID))
	if err := c.send(req, broadcast); err != nil {
		return nil, err
	}
	ack, err := c.awaitAck(ctx, c.xid, reqTO)
	if err != nil {
		return nil, err
	}
	return c.leaseFrom(ack), nil
}

// bound maintains the lease until expiry/NACK/cancel. Returns false when
// the client should stop (cancelled); true when it must reacquire.
func (c *client) bound(ctx context.Context) bool {
	for {
		l := c.lease
		t1 := l.Acquired.Add(l.T1)
		t2 := l.Acquired.Add(l.T2)
		if t2.After(l.Expire) {
			t2 = l.Expire
		}
		if t1.After(t2) {
			t1 = t2
		}
		d := time.Until(t1)
		if d <= 0 {
			d = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return false
		case <-c.after(d):
		}
		l = c.lease // renewal may have replaced the lease
		if !time.Now().Before(l.Expire) {
			return true // expired
		}
		if time.Now().Before(l.Acquired.Add(l.T2)) {
			if c.renew(ctx, l, false) {
				continue
			}
			if wait := time.Until(l.Acquired.Add(l.T2)); wait > 0 {
				select {
				case <-ctx.Done():
					return false
				case <-c.after(wait):
				}
			}
		}
		l = c.lease
		if !time.Now().Before(l.Expire) {
			return true
		}
		if !c.renew(ctx, l, true) {
			return true
		}
	}
}

// renew sends a REQUEST (R1 unicast, R2 broadcast) and applies the ACK.
func (c *client) renew(ctx context.Context, l *Lease, broadcastMode bool) bool {
	c.event("dhcp.renew", c.iface)
	if err := c.openTransport(); err != nil {
		return false
	}
	defer c.closeTransport()
	req := NewPacket(c.xid, c.mac, c.deps.Hostname)
	req.setType(Request)
	req.CIAddr = l.Addr.IP
	req.setIP(optReqIP, l.Addr.IP)
	dst := broadcast
	if !broadcastMode && l.ServerID != "" {
		req.setIP(optServerID, net.ParseIP(l.ServerID))
		dst = l.ServerID
	}
	return c.doRenew(ctx, req, dst)
}

func (c *client) doRenew(ctx context.Context, req *Packet, dst string) bool {
	for attempt := 0; attempt < 3; attempt++ {
		if err := c.send(req, dst); err != nil {
			return false
		}
		ack, err := c.awaitAck(ctx, req.XID, reqTO)
		if err == nil {
			nl := c.leaseFrom(ack)
			c.lease = nl
			c.deps.Reg.set(nl)
			c.event("dhcp.renewed", c.iface+" "+nl.CIDR())
			return true
		}
		if errors.Is(err, errNak) {
			return false // server refused: full restart
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

var errNak = errors.New("dhcp: NAK")

func (c *client) awaitAck(ctx context.Context, xid uint32, to time.Duration) (*Packet, error) {
	deadline := time.Now().Add(to)
	for time.Now().Before(deadline) {
		p, _, err := c.recvUntil(ctx, time.Until(deadline))
		if err != nil {
			return nil, err
		}
		if p.XID != xid {
			continue
		}
		switch p.Type() {
		case Ack:
			if p.YIAddr == nil {
				continue
			}
			return p, nil
		case Nak:
			return nil, errNak
		}
	}
	return nil, errors.New("timeout")
}

// leaseFrom converts an ACK into a runtime lease.
func (c *client) leaseFrom(ack *Packet) *Lease {
	ip, gw, sid, mask, dns, ls, t1, t2 := LeaseFromAck(ack, uint32(c.deps.LeaseFallback.Seconds()))
	now := time.Now()
	return &Lease{
		Iface:   c.iface,
		Addr:    &net.IPNet{IP: ip, Mask: mask},
		Gateway: gw, DNS: ipsToStrings(dns), ServerID: ntos(sid),
		Acquired: now, Expire: now.Add(time.Duration(ls) * time.Second),
		T1: time.Duration(t1) * time.Second, T2: time.Duration(t2) * time.Second,
		State: "bound",
	}
}

func (c *client) openTransport() error {
	if c.tr != nil {
		return nil
	}
	tr, err := c.deps.Make(c.iface, c.mac)
	if err != nil {
		return err
	}
	c.tr = tr
	return nil
}

func (c *client) closeTransport() {
	if c.tr != nil {
		c.tr.Close()
		c.tr = nil
	}
}

func (c *client) send(p *Packet, dstIP string) error {
	b, err := p.Marshal()
	if err != nil {
		return err
	}
	return c.tr.Send(b, &net.UDPAddr{IP: net.ParseIP(dstIP), Port: dhcpPort})
}

// recvUntil receives one relevant packet or times out. ctx cancellation
// surfaces as an error.
func (c *client) recvUntil(ctx context.Context, to time.Duration) (*Packet, *net.UDPAddr, error) {
	type res struct {
		b    []byte
		from *net.UDPAddr
		err  error
	}
	ch := make(chan res, 1)
	tr := c.tr // capture: the FSM may replace/close c.tr while reading
	go func() {
		b, from, err := tr.Recv()
		ch <- res{b, from, err}
	}()
	t := time.NewTimer(to)
	defer t.Stop()
	select {
	case <-ctx.Done():
		c.tr.Close() // unblock the reader
		c.tr = nil
		return nil, nil, ctx.Err()
	case <-t.C:
		return nil, nil, errors.New("recv timeout")
	case r := <-ch:
		if r.err != nil {
			return nil, nil, r.err
		}
		p, err := Unmarshal(r.b)
		if err != nil {
			return nil, nil, nil // ignore garbage, keep waiting
		}
		return p, r.from, nil
	}
}

func (c *client) release() {
	l := c.lease
	if l == nil {
		return
	}
	if err := c.openTransport(); err != nil {
		return
	}
	defer c.closeTransport()
	r := NewPacket(c.xid, c.mac, "")
	r.setType(Release)
	r.CIAddr = l.Addr.IP
	_ = c.send(r, broadcast)
	c.event("dhcp.released", c.iface)
}

func (c *client) releaseQuiet() { c.release() }

func (c *client) event(k, d string) {
	if c.deps.Event != nil {
		c.deps.Event(k, d)
	}
}

func ipsToStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		}
	}
	return out
}

func ntos(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
