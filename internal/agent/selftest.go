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

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Dialer opens a connection to an IP address and port.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// SelfTest fetches url through dial, which leaves through the slot, and
// checks that the service saw want, the slot's public IP. Names resolve in
// the host namespace; only the connection uses the slot.
func SelfTest(ctx context.Context, dial Dialer, url string, want netip.Addr) error {
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("self-test address %q: %w", addr, err)
			}
			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("self-test port %q: %w", port, err)
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if err != nil {
				return nil, fmt.Errorf("resolve self-test host: %w", err)
			}
			var errs []error
			for _, ip := range ips {
				c, err := dial(ctx, "tcp4", netip.AddrPortFrom(ip.Unmap(), uint16(p)).String())
				if err == nil {
					return c, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("self-test request: %w", err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return fmt.Errorf("self-test through the slot: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return fmt.Errorf("self-test response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("self-test service answered %s", resp.Status)
	}
	seen, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return fmt.Errorf("self-test service answered %q, not an IP address", strings.TrimSpace(string(body)))
	}
	if seen.Unmap() != want {
		return fmt.Errorf("traffic leaves from %s, not the slot's public IP %s", seen, want)
	}
	return nil
}
