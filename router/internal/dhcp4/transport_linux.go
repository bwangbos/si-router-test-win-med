//go:build linux

package dhcp4

import (
	"context"
	"net"
	"syscall"
)

// UDPTransportFactory opens a DHCP client socket bound to one interface:
// UDP/68 with SO_REUSEADDR, SO_BROADCAST and SO_BINDTODEVICE so replies
// (broadcast or unicast) are filtered per WAN interface. Requires root,
// which routerd runs as anyway.
func UDPTransportFactory(iface string, _ net.HardwareAddr) (Transport, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			f := int(fd)
			serr = syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if serr != nil {
				return
			}
			serr = syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
			if serr != nil {
				return
			}
			serr = syscall.SetsockoptString(f, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
	if err != nil {
		return nil, err
	}
	return &udpTransport{pc: pc}, nil
}

type udpTransport struct{ pc net.PacketConn }

func (t *udpTransport) Send(b []byte, dst *net.UDPAddr) error {
	_, err := t.pc.WriteTo(b, dst)
	return err
}

func (t *udpTransport) Recv() ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, 1500)
	n, from, err := t.pc.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	up, ok := from.(*net.UDPAddr)
	if !ok {
		up = &net.UDPAddr{}
	}
	return buf[:n], up, nil
}

func (t *udpTransport) Close() error { return t.pc.Close() }
