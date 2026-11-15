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
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/testr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

// These tests change the kernel of the machine they run on. They run only
// as root with NATTERJACK_PRIVILEGED_TESTS=1, which CI sets inside a
// throwaway privileged container (make test-privileged).
func privileged(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 || os.Getenv("NATTERJACK_PRIVILEGED_TESTS") != "1" {
		t.Skip("needs root and NATTERJACK_PRIVILEGED_TESTS=1; run make test-privileged")
	}
}

const (
	slotMAC   = "02:00:00:00:09:0a"
	internet  = "203.0.113.1"
	podIP     = "10.244.0.5"
	slotIP    = "10.0.9.10"
	routerIP  = "10.0.9.1"
	echoPort  = 9000
	poolName  = "p"
	firstMark = 0x00010000
)

// inNS runs fn on a thread inside ns.
func inNS(t *testing.T, ns netns.NsHandle, fn func() error) {
	t.Helper()
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with the goroutine
		if err := netns.Set(ns); err != nil {
			ch <- err
			return
		}
		ch <- fn()
	}()
	if err := <-ch; err != nil {
		t.Fatal(err)
	}
}

func newNS(t *testing.T) netns.NsHandle {
	t.Helper()
	var ns netns.NsHandle
	ch := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		var err error
		ns, err = netns.New()
		ch <- err
	}()
	if err := <-ch; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	return ns
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func ipnet(s string) *netlink.Addr {
	a, err := netlink.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// world builds the slot's subnet router and an internet host behind it, and
// returns a channel of the source addresses the internet host sees.
func world(t *testing.T) (<-chan string, netns.NsHandle) {
	t.Helper()
	w := newNS(t)
	mac, _ := net.ParseMAC(slotMAC)
	must(t, netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "eni-test", HardwareAddr: mac},
		PeerName:  "rtr0", PeerNamespace: netlink.NsFd(w),
	}))
	t.Cleanup(func() {
		if l, err := netlink.LinkByName("eni-test"); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	seen := make(chan string, 16)
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := netns.Set(w); err != nil {
			ready <- err
			return
		}
		lo, _ := netlink.LinkByName("lo")
		rtr, _ := netlink.LinkByName("rtr0")
		for _, step := range []error{
			netlink.LinkSetUp(lo), netlink.LinkSetUp(rtr),
			netlink.AddrAdd(rtr, ipnet(routerIP+"/24")),
			netlink.AddrAdd(lo, ipnet(internet+"/32")),
		} {
			if step != nil {
				ready <- step
				return
			}
		}
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(internet), Port: echoPort})
		if err != nil {
			ready <- err
			return
		}
		// A checkip service: it answers with the caller's address.
		web, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", net.JoinHostPort(internet, "80"))
		if err != nil {
			ready <- err
			return
		}
		srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			_, _ = fmt.Fprintln(w, host)
		})}
		go func() { _ = srv.Serve(web) }()
		ready <- nil
		buf := make([]byte, 64)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case seen <- from.IP.String() + " " + string(buf[:n]):
			default: // no one is checking
			}
			_, _ = c.WriteToUDP([]byte(from.IP.String()), from)
		}
	}()
	must(t, <-ready)
	return seen, w
}

// pod builds a pod network namespace routed through the host.
func pod(t *testing.T) netns.NsHandle {
	t.Helper()
	p := newNS(t)
	must(t, netlink.LinkAdd(&netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "vpod"}, PeerName: "eth0", PeerNamespace: netlink.NsFd(p),
	}))
	t.Cleanup(func() {
		if l, err := netlink.LinkByName("vpod"); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	host, _ := netlink.LinkByName("vpod")
	must(t, netlink.AddrAdd(host, ipnet("10.244.0.1/24")))
	must(t, netlink.LinkSetUp(host))
	inNS(t, p, func() error {
		eth, err := netlink.LinkByName("eth0")
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(eth, ipnet(podIP+"/24")); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(eth); err != nil {
			return err
		}
		return netlink.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Dst: defaultDst(), Gw: net.ParseIP("10.244.0.1")})
	})
	return p
}

func echo(t *testing.T, seen <-chan string) string {
	t.Helper()
	return echoWith(t, seen, "hi")
}

// echoWith sends payload to the internet host and returns the source address
// it saw, or why there was no reply.
func echoWith(t *testing.T, seen <-chan string, payload string) string {
	t.Helper()
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(t.Context(), "udp4", net.JoinHostPort(internet, strconv.Itoa(echoPort)))
	if err != nil {
		return "dial: " + err.Error()
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(payload)); err != nil {
		return "write: " + err.Error()
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil {
		return "no reply: " + err.Error()
	}
	if seen != nil {
		<-seen
	}
	return string(buf[:n]) // the internet host replies with the source it saw
}

// probeOnce sends one probe through mark's gateway and reports whether it
// was answered.
func probeOnce(t *testing.T, cfg Config, mark uint32) bool {
	t.Helper()
	c, err := DialProbe(t.Context(), mark, netip.AddrPortFrom(cfg.GatewayAddr(), cfg.ProbePort))
	must(t, err)
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("NJP100000001"))
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	b := make([]byte, 32)
	n, err := c.Read(b)
	return err == nil && n == 12
}

func nodeAddr(t *testing.T) netip.Addr {
	t.Helper()
	l, err := netlink.LinkByName("eth0")
	must(t, err)
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
	must(t, err)
	if len(addrs) == 0 {
		t.Fatal("eth0 has no IPv4 address")
	}
	a, _ := netip.AddrFromSlice(addrs[0].IP.To4())
	return a
}

func desired(node netip.Addr) *agent.Desired {
	var ring [agent.Buckets]uint32
	for i := range ring {
		ring[i] = firstMark
	}
	return &agent.Desired{
		NodeIP: node, Nodes: []netip.Addr{node}, Excluded: agent.DefaultExcluded,
		Steers:   []agent.Steer{{Name: "cluster/all", Pool: poolName, Sources: []netip.Addr{netip.MustParseAddr(podIP)}, Node: true}},
		Rings:    map[string][agent.Buckets]uint32{poolName: ring},
		Gateways: map[uint32]netip.Addr{firstMark: node},
		Gateway: &agent.GatewayRole{
			Pool: poolName, MAC: slotMAC, Address: netip.MustParsePrefix(slotIP + "/24"),
			Router: netip.MustParseAddr(routerIP), Public: netip.MustParseAddr("198.51.100.7"),
		},
	}
}

// listenOnce reports the first datagram a UDP socket on port 9100 receives.
func listenOnce(addr string, got chan<- string) error {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(addr), Port: 9100})
	if err != nil {
		return err
	}
	go func() {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 8)
		if _, from, err := c.ReadFromUDP(buf); err == nil {
			got <- fmt.Sprintf("%s from %s", addr, from)
		}
	}()
	return nil
}

func nftDump() string {
	out, _ := exec.CommandContext(context.Background(), "nft", "list", "ruleset").CombinedOutput()
	return string(out)
}

func TestSingleNodeGateway(t *testing.T) {
	privileged(t)
	must(t, writeSysctl("net/ipv4/ip_forward", "1"))
	must(t, writeSysctl("net/ipv4/conf/all/rp_filter", "2"))
	cfg := DefaultConfig()
	cfg.StateDir = t.TempDir()
	seen, w := world(t)
	p := pod(t)
	node := nodeAddr(t)
	want := desired(node)

	dp, err := New(cfg, testr.New(t))
	must(t, err)
	t.Cleanup(func() { _ = dp.Teardown() })
	for i := range 2 { // a second Apply must change nothing
		st, err := dp.Apply(want)
		must(t, err)
		if !st.Serving {
			t.Fatalf("apply %d: not serving: %s", i, st.Reason)
		}
	}
	if _, err := netlink.LinkByName("eni-test"); err == nil {
		t.Fatal("slot interface is still in the host namespace")
	}

	if got := echo(t, seen); got != slotIP {
		t.Fatalf("node traffic reached the internet from %q, want %s\n%s", got, slotIP, nftDump())
	}
	var fromPod string
	inNS(t, p, func() error { fromPod = echo(t, seen); return nil })
	if fromPod != slotIP {
		t.Fatalf("pod traffic reached the internet from %q, want %s\n%s", fromPod, slotIP, nftDump())
	}

	// The self-test, dialed from the gateway namespace, sees the slot.
	must(t, agent.SelfTest(t.Context(), dp.DialGateway, "http://"+internet+"/", netip.MustParseAddr(slotIP)))

	// Probes through the local gateway are answered only while it serves.
	pc, err := dp.ListenProbe(t.Context())
	must(t, err)
	responder := agent.NewResponder(pc)
	defer func() { _ = responder.Close() }()
	if probeOnce(t, cfg, firstMark) {
		t.Fatal("a gateway that is not serving answered a probe")
	}
	responder.SetServing(true)
	if !probeOnce(t, cfg, firstMark) {
		t.Fatalf("the local gateway did not answer a probe\n%s", nftDump())
	}

	// Nothing on the internet side reaches the node, its pods or the
	// gateway namespace through the slot, even with a route pointing at it,
	// and the probe responder answers nobody there.
	inbound := make(chan string, 4)
	for _, dst := range []string{node.String(), podIP, cfg.GatewayAddr().String(), slotIP} {
		listen := dst
		if dst == slotIP || dst == cfg.GatewayAddr().String() {
			listen = "0.0.0.0" // nothing listens there; any reply would be a leak
		}
		if dst == podIP {
			inNS(t, p, func() error { return listenOnce(listen, inbound) })
		} else if dst == node.String() {
			must(t, listenOnce(listen, inbound))
		}
	}
	inNS(t, w, func() error {
		rtr, err := netlink.LinkByName("rtr0")
		if err != nil {
			return err
		}
		for _, dst := range []string{node.String(), podIP, cfg.GatewayAddr().String()} {
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: rtr.Attrs().Index, Dst: hostPrefix(netip.MustParseAddr(dst)), Gw: net.ParseIP(slotIP)}); err != nil {
				return err
			}
		}
		for _, dst := range []string{node.String(), podIP, cfg.GatewayAddr().String(), slotIP} {
			for _, port := range []int{9100, int(cfg.ProbePort), 22} {
				c, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", net.JoinHostPort(dst, strconv.Itoa(port)))
				if err != nil {
					return err
				}
				_, _ = c.Write([]byte("NJP100000001"))
				_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, err := c.Read(make([]byte, 32))
				_ = c.Close()
				if err == nil {
					return fmt.Errorf("%d bytes came back from %s:%d through the slot", n, dst, port)
				}
			}
		}
		return nil
	})
	select {
	case got := <-inbound:
		t.Fatalf("internet traffic reached %s through the slot\n%s", got, nftDump())
	case <-time.After(time.Second):
	}

	// A restarted agent finds the pinned namespace and keeps serving.
	dp2, err := New(cfg, testr.New(t))
	must(t, err)
	if dp2.Gateway() == nil {
		t.Fatal("restarted agent did not find the gateway namespace")
	}
	st, err := dp2.Apply(want)
	must(t, err)
	if !st.Serving {
		t.Fatalf("restarted agent not serving: %s", st.Reason)
	}
	if got := echo(t, seen); got != slotIP {
		t.Fatalf("after restart node traffic left from %q", got)
	}

	// No live gateway: traffic is no longer steered.
	unsteered := *want
	unsteered.Rings = nil
	unsteered.Gateway = nil
	_, err = dp2.Apply(&unsteered)
	must(t, err)
	if dp2.Gateway() == nil {
		t.Fatal("gateway namespace removed while the slot interface is still inside")
	}
	if got := echo(t, seen); got == slotIP {
		t.Fatal("traffic still steered with no ring")
	}

	// The cloud detaches the slot; the namespace goes on the next Apply.
	inNS(t, dp2.gw.ns, func() error {
		l, err := netlink.LinkByName(EgressLink)
		if err != nil {
			return err
		}
		return netlink.LinkDel(l)
	})
	_, err = dp2.Apply(&unsteered)
	must(t, err)
	if dp2.Gateway() != nil {
		t.Fatal("gateway namespace kept after the slot was detached")
	}
	must(t, dp2.Teardown())
	if _, err := netlink.LinkByName(TunnelLink); err == nil {
		t.Fatal("teardown left the tunnel device")
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	must(t, err)
	for _, f := range flows {
		if f.Mark&cfg.MarkMask != 0 {
			t.Fatalf("teardown left a steered flow: %s", f)
		}
	}
}

func TestStaleFlowsAreFlushed(t *testing.T) {
	privileged(t)
	cfg := DefaultConfig()
	cfg.StateDir = t.TempDir()
	dp, err := New(cfg, testr.New(t))
	must(t, err)
	t.Cleanup(func() { _ = dp.Teardown() })
	node := nodeAddr(t)
	other := netip.MustParseAddr("192.0.2.77")
	want := &agent.Desired{NodeIP: node, Nodes: []netip.Addr{node, other}, Gateways: map[uint32]netip.Addr{firstMark: other}}
	_, err = dp.Apply(want)
	must(t, err)

	// A conntrack entry pinned to the gateway's mark.
	flow := &netlink.ConntrackFlow{
		FamilyType: netlink.FAMILY_V4, Forward: netlink.IPTuple{
			SrcIP: net.ParseIP("10.244.0.9").To4(), DstIP: net.ParseIP(internet).To4(), Protocol: 17, SrcPort: 4000, DstPort: 53,
		},
		Reverse: netlink.IPTuple{
			SrcIP: net.ParseIP(internet).To4(), DstIP: net.ParseIP("10.244.0.9").To4(), Protocol: 17, SrcPort: 53, DstPort: 4000,
		},
		Mark: firstMark | 0x1, TimeOut: 60,
	}
	must(t, netlink.ConntrackCreate(netlink.ConntrackTable, netlink.FAMILY_V4, flow))
	count := func() int {
		flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
		must(t, err)
		n := 0
		for _, f := range flows {
			if f.Forward.SrcPort == 4000 && f.Mark&cfg.MarkMask == firstMark {
				n++
			}
		}
		return n
	}
	if count() != 1 {
		t.Fatal("test flow not created")
	}
	want.Failed = []uint32{firstMark}
	_, err = dp.Apply(want)
	must(t, err)
	if n := count(); n != 0 {
		t.Fatalf("%d flows still pinned to the failed gateway", n)
	}
}

// TestTunnel runs in three containers on one network, started by
// hack/test-privileged.sh: a gateway node with the slot, a source node that
// steers through it, and a host outside the cluster that tries to use the
// gateway by sending its own GENEVE packets and, for an encrypted pool, by
// bringing its own WireGuard key.
func TestTunnel(t *testing.T) {
	privileged(t)
	role := os.Getenv("NATTERJACK_TUNNEL_ROLE")
	if role == "" {
		t.Skip("run by hack/test-privileged.sh")
	}
	dir := os.Getenv("NATTERJACK_TUNNEL_DIR")
	gateway := netip.MustParseAddr(os.Getenv("NATTERJACK_TUNNEL_GATEWAY"))
	source := netip.MustParseAddr(os.Getenv("NATTERJACK_TUNNEL_SOURCE"))
	encrypted := os.Getenv("NATTERJACK_TUNNEL_TYPE") == "WireGuard"
	must(t, writeSysctl("net/ipv4/ip_forward", "1"))
	must(t, writeSysctl("net/ipv4/conf/all/rp_filter", "2"))
	cfg := DefaultConfig()
	// Not t.TempDir: the gateway namespace stays pinned at exit, with the
	// slot inside, as it would on a node.
	state, err := os.MkdirTemp("", "natterjack")
	must(t, err)
	cfg.StateDir = state
	node := nodeAddr(t)
	signal := func(name string) { must(t, os.WriteFile(dir+"/"+name, nil, 0o600)) }
	await := func(name string) {
		for range 600 {
			if _, err := os.Stat(dir + "/" + name); err == nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", name)
	}
	// Nodes learn each other's WireGuard keys from their pods; here, from
	// files.
	publish := func(role string, dp *Dataplane) {
		if encrypted {
			must(t, os.WriteFile(dir+"/"+role+".key", []byte(dp.WireGuardKey()), 0o600))
		}
	}
	keyOf := func(role string) string {
		await(role + ".key")
		b, err := os.ReadFile(dir + "/" + role + ".key")
		must(t, err)
		return string(b)
	}
	var ring [agent.Buckets]uint32
	for i := range ring {
		ring[i] = firstMark
	}

	switch role {
	case "gateway":
		seen, _ := world(t)
		cniMasquerade(t)
		dp, err := New(cfg, testr.New(t))
		must(t, err)
		t.Cleanup(func() { _ = dp.Teardown() })
		want := desired(node)
		want.Nodes = []netip.Addr{gateway, source}
		want.Steers, want.Rings = nil, nil
		publish("gateway", dp)
		if encrypted {
			want.Gateway.WireGuard = true
			want.Gateway.Peers = map[netip.Addr]string{source: keyOf("source")}
		}
		st, err := dp.Apply(want)
		must(t, err)
		if !st.Serving {
			t.Fatalf("not serving: %s", st.Reason)
		}
		if encrypted {
			got, err := wireGuardPeerAddrs(WireGuardLink)
			must(t, err)
			if len(got) != 1 || got[0] != netip.PrefixFrom(source, 32) {
				t.Fatalf("%s peers may send from %v; want only the source node's address", WireGuardLink, got)
			}
		}
		pc, err := dp.ListenProbe(t.Context())
		must(t, err)
		responder := agent.NewResponder(pc)
		defer func() { _ = responder.Close() }()
		responder.SetServing(true)
		signal("gateway-ready")
		await("source-done")
		await("outsider-done")
		for {
			select {
			case got := <-seen:
				if strings.HasSuffix(got, " outsider") {
					t.Fatalf("a packet from outside the cluster left through the slot: %s", got)
				}
				continue
			default:
			}
			break
		}

	case "source":
		p := pod(t)
		dp, err := New(cfg, testr.New(t))
		must(t, err)
		t.Cleanup(func() { _ = dp.Teardown() })
		want := desired(node)
		want.Nodes = []netip.Addr{gateway, source}
		want.Gateways = map[uint32]netip.Addr{firstMark: gateway}
		want.Rings = map[string][agent.Buckets]uint32{poolName: ring}
		want.Gateway = nil
		publish("source", dp)
		await("gateway-ready")
		if encrypted {
			want.WireGuard = map[uint32]string{firstMark: keyOf("gateway")}
		}
		_, err = dp.Apply(want)
		must(t, err)
		defer signal("source-done")
		if os.Getenv("NATTERJACK_TUNNEL_HOLD") != "" {
			defer time.Sleep(30 * time.Second)
		}
		if got := echo(t, nil); got != slotIP {
			t.Errorf("node traffic left from %q, want %s\n%s", got, slotIP, nftDump())
		}
		var fromPod string
		inNS(t, p, func() error { fromPod = echo(t, nil); return nil })
		if fromPod != slotIP {
			t.Errorf("pod traffic left from %q, want %s", fromPod, slotIP)
		}
		if !probeOnce(t, cfg, firstMark) {
			t.Errorf("the gateway did not answer a probe through the tunnel\n%s", nftDump())
		}
		if encrypted {
			// The traffic went through WireGuard...
			if hs, err := wireGuardHandshake(dp.wireGuardName(firstMark)); err != nil || hs.IsZero() {
				t.Errorf("no WireGuard handshake with the gateway (%v)", err)
			}
			// ...and the gateway refuses the same node over plain GENEVE.
			tun, err := netlink.LinkByName(TunnelLink)
			must(t, err)
			must(t, netlink.RouteReplace(&netlink.Route{
				Table: dp.table(firstMark), Dst: defaultDst(), LinkIndex: tun.Attrs().Index, Encap: &tunnelEncap{ID: VNI, Dst: gateway},
			}))
			flushFlows(t)
			if got := echoWith(t, nil, "downgrade"); !strings.HasPrefix(got, "no reply") {
				t.Errorf("a gateway of an encrypted pool took traffic over GENEVE: %q", got)
			}
		}

	case "outsider":
		// Not a cluster node: it builds its own tunnel to the gateway.
		await("gateway-ready")
		defer signal("outsider-done")
		must(t, netlink.LinkAdd(&netlink.Geneve{LinkAttrs: netlink.LinkAttrs{Name: "evil0"}, FlowBased: true, InnerProtoInherit: true, Dport: cfg.TunnelPort}))
		l, err := netlink.LinkByName("evil0")
		must(t, err)
		must(t, netlink.LinkSetUp(l))
		must(t, netlink.RouteAdd(&netlink.Route{
			Dst: hostPrefix(netip.MustParseAddr(internet)), LinkIndex: l.Attrs().Index,
			Encap: &tunnelEncap{ID: VNI, Dst: gateway},
		}))
		if got := echoWith(t, nil, "outsider"); !strings.HasPrefix(got, "no reply") {
			t.Fatalf("a host outside the cluster used the gateway: %q", got)
		}
		// Nor does the gateway answer its probes.
		must(t, netlink.RouteAdd(&netlink.Route{
			Dst: hostPrefix(cfg.GatewayAddr()), LinkIndex: l.Attrs().Index,
			Encap: &tunnelEncap{ID: VNI, Dst: gateway},
		}))
		if probeOnce(t, cfg, 0) {
			t.Fatal("the gateway answered a probe from outside the cluster")
		}
		if encrypted {
			outsiderWireGuard(t, cfg, gateway, keyOf("gateway"))
		}
	default:
		t.Fatalf("unknown role %q", role)
	}
}

// cniMasquerade translates, as kindnet does and as the AWS VPC CNI does for
// addresses outside the VPC, every flow to a destination not on this host
// to the address of the device it leaves by.
func cniMasquerade(t *testing.T) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table ip cni {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		fib daddr type != local masquerade
	}
}
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install the CNI's masquerade: %v: %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.CommandContext(context.Background(), "nft", "delete", "table", "ip", "cni").Run()
	})
}

// wireGuardPeerAddrs are the addresses the peers of a WireGuard device may
// send from.
func wireGuardPeerAddrs(name string) ([]netip.Prefix, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	dev, err := c.Device(name)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, p := range dev.Peers {
		for _, a := range p.AllowedIPs {
			ip, _ := netip.AddrFromSlice(a.IP.To4())
			ones, _ := a.Mask.Size()
			out = append(out, netip.PrefixFrom(ip, ones))
		}
	}
	return out, nil
}

// wireGuardHandshake is when a device's only peer last completed a
// handshake.
func wireGuardHandshake(name string) (time.Time, error) {
	c, err := wgctrl.New()
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = c.Close() }()
	dev, err := c.Device(name)
	if err != nil {
		return time.Time{}, err
	}
	if len(dev.Peers) != 1 {
		return time.Time{}, fmt.Errorf("%s has %d peers", name, len(dev.Peers))
	}
	return dev.Peers[0].LastHandshakeTime, nil
}

// flushFlows forgets the node's flows, so the next packet is routed afresh.
func flushFlows(t *testing.T) {
	t.Helper()
	if _, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, anyMark{^uint32(0)}); err != nil {
		t.Fatal(err)
	}
}

// outsiderWireGuard brings its own key to an encrypted gateway: it knows the
// gateway's public key, as anyone who can read pods does, but is not a peer.
func outsiderWireGuard(t *testing.T, cfg Config, gateway netip.Addr, gatewayKey string) {
	t.Helper()
	must(t, netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "evilwg"}}))
	l, err := netlink.LinkByName("evilwg")
	must(t, err)
	t.Cleanup(func() { _ = netlink.LinkDel(l) })
	key, err := wgtypes.GeneratePrivateKey()
	must(t, err)
	pub, err := wgtypes.ParseKey(gatewayKey)
	must(t, err)
	c, err := wgctrl.New()
	must(t, err)
	defer func() { _ = c.Close() }()
	must(t, c.ConfigureDevice("evilwg", wgtypes.Config{PrivateKey: &key, Peers: []wgtypes.PeerConfig{{
		PublicKey: pub, Endpoint: &net.UDPAddr{IP: net.IP(gateway.AsSlice()), Port: int(cfg.WireGuardPort)},
		AllowedIPs: []net.IPNet{*defaultDst()},
	}}}))
	must(t, netlink.AddrAdd(l, ipnet(nodeAddr(t).String()+"/32")))
	must(t, netlink.LinkSetUp(l))
	must(t, netlink.RouteReplace(&netlink.Route{Dst: hostPrefix(netip.MustParseAddr(internet)), LinkIndex: l.Attrs().Index}))
	if got := echoWith(t, nil, "outsider"); !strings.HasPrefix(got, "no reply") {
		t.Fatalf("a host outside the cluster used the gateway over WireGuard: %q", got)
	}
	if hs, err := wireGuardHandshake("evilwg"); err != nil || !hs.IsZero() {
		t.Fatalf("the gateway completed a WireGuard handshake with a key it does not know (%v, %v)", hs, err)
	}
}
