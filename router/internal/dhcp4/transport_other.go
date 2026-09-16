//go:build !linux

package dhcp4

import (
	"errors"
	"net"
)

// UDPTransportFactory is only available on Linux.
func UDPTransportFactory(_ string, _ net.HardwareAddr) (Transport, error) {
	return nil, errors.New("dhcp4: raw DHCP transport is Linux-only")
}
