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
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// A probe is a 12-byte UDP datagram: a magic word and a sequence number.
// The gateway echoes it unchanged.
const (
	probeMagic = "NJP1"
	probeLen   = len(probeMagic) + 8
)

// ProbeTarget is how one gateway is probed.
type ProbeTarget struct {
	// Mark routes the probe through the tunnel to the gateway.
	Mark uint32
	// Interval between probes.
	Interval time.Duration
	// Threshold is the number of consecutive unanswered probes after which
	// the gateway is down.
	Threshold int
}

// ProbeDialer opens a socket whose packets carry mark to dst.
type ProbeDialer func(ctx context.Context, mark uint32, dst netip.AddrPort) (net.Conn, error)

// Prober probes every gateway a node may use, through the tunnel, and
// reports which are down. It decides only liveness from this node: which
// gateways exist and are ready comes from the cluster.
type Prober struct {
	dial    ProbeDialer
	dst     netip.AddrPort
	changed chan struct{}

	mu      sync.Mutex
	targets map[netip.Addr]*prober
}

type prober struct {
	target ProbeTarget
	cancel context.CancelFunc
	done   chan struct{}
	down   atomic.Bool
}

// NewProber probes dst, the gateway namespace's probe address, through each
// gateway's mark.
func NewProber(dial ProbeDialer, dst netip.AddrPort) *Prober {
	return &Prober{dial: dial, dst: dst, changed: make(chan struct{}, 1), targets: map[netip.Addr]*prober{}}
}

// Changed receives a value whenever a gateway goes down or comes back.
func (p *Prober) Changed() <-chan struct{} { return p.changed }

// Down returns the gateways that stopped answering.
func (p *Prober) Down() map[netip.Addr]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[netip.Addr]bool{}
	for ip, t := range p.targets {
		if t.down.Load() {
			out[ip] = true
		}
	}
	return out
}

// Update probes exactly want. A gateway whose target changes starts again
// as up; a new gateway starts as up, since the cluster already says it is
// ready.
func (p *Prober) Update(want map[netip.Addr]ProbeTarget) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip, t := range p.targets {
		if w, ok := want[ip]; !ok || w != t.target {
			t.stop()
			delete(p.targets, ip)
		}
	}
	for ip, w := range want {
		if _, ok := p.targets[ip]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		t := &prober{target: w, cancel: cancel, done: make(chan struct{})}
		p.targets[ip] = t
		go p.run(ctx, t)
	}
}

// Stop ends all probing.
func (p *Prober) Stop() { p.Update(nil) }

func (t *prober) stop() {
	t.cancel()
	<-t.done
}

func (p *Prober) notify() {
	select {
	case p.changed <- struct{}{}:
	default:
	}
}

func (p *Prober) run(ctx context.Context, t *prober) {
	defer close(t.done)
	var (
		conn   net.Conn
		sent   uint64
		acked  atomic.Uint64
		misses int
	)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	tick := time.NewTicker(t.target.Interval)
	defer tick.Stop()
	for {
		// The previous probe had one interval to come back.
		if sent > 0 {
			if acked.Load() >= sent {
				misses = 0
				if t.down.CompareAndSwap(true, false) {
					p.notify()
				}
			} else if misses++; misses >= t.target.Threshold && t.down.CompareAndSwap(false, true) {
				p.notify()
			}
		}
		if conn == nil {
			c, err := p.dial(ctx, t.target.Mark, p.dst)
			if err == nil {
				conn = c
				go readReplies(c, &acked)
			}
		}
		sent++
		if conn != nil {
			var b [probeLen]byte
			copy(b[:], probeMagic)
			binary.BigEndian.PutUint64(b[len(probeMagic):], sent)
			if _, err := conn.Write(b[:]); err != nil {
				// A route change or an ICMP error; open a fresh socket.
				_ = conn.Close()
				conn = nil
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// readReplies records the highest sequence number echoed back, until the
// socket closes.
func readReplies(c net.Conn, acked *atomic.Uint64) {
	var b [probeLen + 1]byte
	for {
		n, err := c.Read(b[:])
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			continue // an ICMP error reported once on a connected socket
		}
		if n != probeLen || string(b[:len(probeMagic)]) != probeMagic {
			continue
		}
		seq := binary.BigEndian.Uint64(b[len(probeMagic):probeLen])
		for {
			cur := acked.Load()
			if seq <= cur || acked.CompareAndSwap(cur, seq) {
				break
			}
		}
	}
}

// Responder answers probes on a gateway while its slot carries traffic.
type Responder struct {
	conn    net.PacketConn
	serving atomic.Bool
	done    chan struct{}
}

// NewResponder answers probes arriving on conn until Close.
func NewResponder(conn net.PacketConn) *Responder {
	r := &Responder{conn: conn, done: make(chan struct{})}
	go r.run()
	return r
}

// SetServing starts or stops answering. A gateway that does not answer is
// dropped by every source node within its probe threshold.
func (r *Responder) SetServing(v bool) { r.serving.Store(v) }

// Close stops the responder.
func (r *Responder) Close() error {
	err := r.conn.Close()
	<-r.done
	return err //nolint:wrapcheck // closing a socket
}

func (r *Responder) run() {
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
