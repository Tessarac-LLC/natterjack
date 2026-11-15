//go:build !linux

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
	"net"
	"net/netip"

	"github.com/go-logr/logr"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

var errLinuxOnly = errors.New("the natterjack data path runs only on Linux")

// Dataplane is unavailable off Linux; the type exists so the agent builds
// for development on other systems.
type Dataplane struct{}

// GatewayNS is unavailable off Linux.
type GatewayNS struct{}

// New always fails off Linux.
func New(Config, logr.Logger) (*Dataplane, error) { return nil, errLinuxOnly }

// Apply always fails off Linux.
func (*Dataplane) Apply(*agent.Desired) (Status, error) { return Status{}, errLinuxOnly }

// Gateway is always nil off Linux.
func (*Dataplane) Gateway() *GatewayNS { return nil }

// SetMarks does nothing off Linux.
func (*Dataplane) SetMarks(map[uint32]netip.Addr) {}

// Teardown always fails off Linux.
func (*Dataplane) Teardown() error { return errLinuxOnly }

// Do always fails off Linux.
func (*GatewayNS) Do(func() error) error { return errLinuxOnly }

// DialProbe always fails off Linux.
func DialProbe(context.Context, uint32, netip.AddrPort) (net.Conn, error) { return nil, errLinuxOnly }

// ListenProbe always fails off Linux.
func (*Dataplane) ListenProbe(context.Context) (net.PacketConn, error) { return nil, errLinuxOnly }

// DialGateway always fails off Linux.
func (*Dataplane) DialGateway(context.Context, string, string) (net.Conn, error) {
	return nil, errLinuxOnly
}

// WireGuardKey is empty off Linux.
func (*Dataplane) WireGuardKey() string { return "" }

// Config returns the configuration.
func (*Dataplane) Config() Config { return Config{} }
