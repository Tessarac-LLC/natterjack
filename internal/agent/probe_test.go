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
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func responder(t *testing.T) (*echoer, netip.AddrPort) {
	t.Helper()
	c, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := newEchoer(c)
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

// echoer answers probes like a gateway, in user space.
type echoer struct {
	conn    net.PacketConn
	serving atomic.Bool
	done    chan struct{}
}

func newEchoer(conn net.PacketConn) *echoer {
	r := &echoer{conn: conn, done: make(chan struct{})}
	go r.run()
	return r
}

func (r *echoer) SetServing(v bool) { r.serving.Store(v) }

func (r *echoer) Close() error {
	err := r.conn.Close()
	<-r.done
	return err //nolint:wrapcheck // closing a socket
}

func (r *echoer) run() {
	defer close(r.done)
	var b [probeLen + 1]byte
	for {
		n, from, err := r.conn.ReadFrom(b[:])
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		if n != probeLen || string(b[:len(probeMagic)]) != probeMagic || !r.serving.Load() {
			continue
		}
		_, _ = r.conn.WriteTo(b[:n], from)
	}
}
