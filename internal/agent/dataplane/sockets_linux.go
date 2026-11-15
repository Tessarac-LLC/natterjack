/*
Copyright 2026 Tessarac, LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// DialProbe opens a UDP socket whose packets carry mark, so policy routing
// sends them through the tunnel to that mark's gateway: a probe takes the
// path steered traffic takes.
func DialProbe(ctx context.Context, mark uint32, dst netip.AddrPort) (net.Conn, error) {
	d := net.Dialer{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return fmt.Errorf("probe socket: %w", err)
		}
		if serr != nil {
			return fmt.Errorf("mark probe socket: %w", serr)
		}
		return nil
	}}
	c, err := d.DialContext(ctx, "udp4", dst.String())
	if err != nil {
		return nil, fmt.Errorf("probe %s with mark %#x: %w", dst, mark, err)
	}
	return c, nil
}

var errNoGateway = errors.New("this node serves no slot")

// DialGateway connects from inside the gateway namespace, so the connection
// leaves through the slot like gateway traffic. addr must be an IP address
// and port: name resolution stays in the host namespace.
func (d *Dataplane) DialGateway(ctx context.Context, network, addr string) (net.Conn, error) {
	gw := d.Gateway()
	if gw == nil {
		return nil, errNoGateway
	}
	var c net.Conn
	err := gw.Do(func() error {
		var err error
		c, err = (&net.Dialer{}).DialContext(ctx, network, addr)
		return err //nolint:wrapcheck // wrapped below
	})
	if err != nil {
		return nil, fmt.Errorf("dial %s from the gateway namespace: %w", addr, err)
	}
	return c, nil
}
