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
	"net"
	"net/netip"
	"testing"
	"time"
)

func responder(t *testing.T) (*Responder, netip.AddrPort) {
	t.Helper()
	c, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := NewResponder(c)
	t.Cleanup(func() { _ = r.Close() })
	return r, c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// waitFor polls cond for up to two seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestProberDetectsAndRecovers(t *testing.T) {
	live, liveAddr := responder(t)
	live.SetServing(true)
	dead, deadAddr := responder(t)
	// The mark stands in for the route: each gateway is a different socket.
	byMark := map[uint32]netip.AddrPort{1: liveAddr, 2: deadAddr}
	dial := func(ctx context.Context, mark uint32, _ netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", byMark[mark].String())
	}
	p := NewProber(dial, netip.MustParseAddrPort("169.254.73.2:6086"))
	defer p.Stop()
	a, b := netip.MustParseAddr("10.0.1.10"), netip.MustParseAddr("10.0.1.11")
	p.Update(map[netip.Addr]ProbeTarget{
		a: {Mark: 1, Interval: 10 * time.Millisecond, Threshold: 3},
		b: {Mark: 2, Interval: 10 * time.Millisecond, Threshold: 3},
	})

	waitFor(t, "the silent gateway to be down", func() bool { return p.Down()[b] })
	<-p.Changed()
	time.Sleep(100 * time.Millisecond)
	if p.Down()[a] {
		t.Fatal("an answering gateway was declared down")
	}

	dead.SetServing(true)
	waitFor(t, "the gateway to come back", func() bool { return !p.Down()[b] })
	<-p.Changed()

	// A gateway no longer wanted is forgotten.
	dead.SetServing(false)
	p.Update(map[netip.Addr]ProbeTarget{a: {Mark: 1, Interval: 10 * time.Millisecond, Threshold: 3}})
	time.Sleep(100 * time.Millisecond)
	if len(p.Down()) != 0 {
		t.Fatalf("down %v after the gateway was removed", p.Down())
	}
}

func TestResponderIgnoresOtherDatagrams(t *testing.T) {
	r, addr := responder(t)
	r.SetServing(true)
	c, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for _, msg := range []string{"NJP1short", "XXXX12345678", "NJP1123456789"} {
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Write([]byte("NJP112345678")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 64)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "NJP112345678" {
		t.Fatalf("first reply %q, %v; want only the well-formed probe echoed", b[:n], err)
	}
}
