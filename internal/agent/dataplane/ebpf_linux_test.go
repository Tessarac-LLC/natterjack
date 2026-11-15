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
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/go-logr/logr/testr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

const (
	tcxNext        = 0xffffffff // TCX_NEXT, -1
	tcActRedirect  = 7
	testDivertIdx  = 42
	testDivertMAC  = "02:00:00:00:0d:01"
	inboundRemote  = "198.51.100.20"
	excludedTarget = "10.96.0.10"
)

// packet builds an Ethernet frame with an IPv4 header and, for TCP and UDP,
// the ports.
func packet(src, dst string, proto uint8, sport, dport uint16) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x02, 0, 0, 0, 0, 0xaa, 0x02, 0, 0, 0, 0, 0xbb, 0x08, 0x00})
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 28)
	ip[8] = 64
	ip[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	b.Write(ip)
	l4 := make([]byte, 8)
	binary.BigEndian.PutUint16(l4[0:], sport)
	binary.BigEndian.PutUint16(l4[2:], dport)
	b.Write(l4)
	b.Write(make([]byte, 32)) // the kernel wants room past the headers
	return b.Bytes()
}

// steerPrograms loads the fast path unpinned, diverting to a made-up device.
func steerPrograms(t *testing.T) *ebpf.Collection {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(steerObject))
	must(t, err)
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	mac, _ := net.ParseMAC(testDivertMAC)
	must(t, spec.Variables["divert_ifindex"].Set(uint32(testDivertIdx)))
	must(t, spec.Variables["divert_mac"].Set([6]byte(mac)))
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("%+v", ve)
		}
		t.Fatal(err)
	}
	t.Cleanup(coll.Close)
	return coll
}

// run passes pkt to prog as if it had arrived on ingressIfindex and returns
// the verdict and the packet as the program left it.
func run(t *testing.T, prog *ebpf.Program, pkt []byte, ingressIfindex uint32) (uint32, []byte) {
	t.Helper()
	// struct __sk_buff up to and including ingress_ifindex; the kernel
	// takes a shorter context and zeroes the rest.
	ctx := make([]byte, 40)
	binary.NativeEndian.PutUint32(ctx[36:], ingressIfindex)
	out := make([]byte, len(pkt))
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt, DataOut: out, Context: ctx})
	must(t, err)
	return ret, out
}

// TestSteerPrograms checks each decision the fast path makes.
func TestSteerPrograms(t *testing.T) {
	privileged(t)
	coll := steerPrograms(t)
	egress, ingress := coll.Programs["nj_egress"], coll.Programs["nj_ingress"]
	want := &agent.Desired{
		Excluded: agent.DefaultExcluded,
		Steers:   []agent.Steer{{Sources: []netip.Addr{netip.MustParseAddr(podIP)}}},
	}
	must(t, syncSteered(coll.Maps["nj_steered"], want))
	must(t, syncExcluded(coll.Maps["nj_excluded"], want.Excluded))
	divertMAC, _ := net.ParseMAC(testDivertMAC)

	ret, out := run(t, egress, packet(podIP, internet, unix.IPPROTO_UDP, 40000, echoPort), 3)
	if ret != tcActRedirect {
		t.Fatalf("a steered pod's packet to the internet: verdict %#x, want redirect", ret)
	}
	if !bytes.Equal(out[:6], divertMAC) {
		t.Fatalf("diverted packet goes to %s, want %s", net.HardwareAddr(out[:6]), divertMAC)
	}
	n, err := diverted(coll.Maps["nj_diverted"])
	must(t, err)
	if n != 1 {
		t.Fatalf("diverted count %d, want 1", n)
	}

	for _, c := range []struct {
		name    string
		pkt     []byte
		ingress uint32
	}{
		{"an excluded destination", packet(podIP, excludedTarget, unix.IPPROTO_TCP, 40000, 443), 3},
		{"a pod that is not steered", packet("10.244.0.99", internet, unix.IPPROTO_UDP, 40000, echoPort), 3},
		{"a packet back from the divert device", packet(podIP, internet, unix.IPPROTO_UDP, 40000, echoPort), testDivertIdx},
		{"a packet that is not IPv4", append([]byte{2, 0, 0, 0, 0, 0xaa, 2, 0, 0, 0, 0, 0xbb, 0x86, 0xdd}, make([]byte, 60)...), 3},
		{"an ARP packet", append([]byte{2, 0, 0, 0, 0, 0xaa, 2, 0, 0, 0, 0, 0xbb, 0x08, 0x06}, make([]byte, 60)...), 3},
	} {
		if ret, _ := run(t, egress, c.pkt, 3); c.ingress == 3 && ret != tcxNext {
			t.Errorf("%s: verdict %#x, want next", c.name, ret)
		}
		if c.ingress != 3 {
			if ret, _ := run(t, egress, c.pkt, c.ingress); ret != tcxNext {
				t.Errorf("%s: verdict %#x, want next", c.name, ret)
			}
		}
	}

	// A connection that came in to the pod: its replies are left alone,
	// a new connection from the pod to the same host is still steered.
	if ret, _ := run(t, ingress, packet(inboundRemote, podIP, unix.IPPROTO_TCP, 51000, 8080), 3); ret != tcxNext {
		t.Fatalf("ingress verdict %#x, want next", ret)
	}
	if ret, _ := run(t, egress, packet(podIP, inboundRemote, unix.IPPROTO_TCP, 8080, 51000), 3); ret != tcxNext {
		t.Fatalf("a reply to an inbound connection was diverted (verdict %#x)", ret)
	}
	if ret, _ := run(t, egress, packet(podIP, inboundRemote, unix.IPPROTO_UDP, 8080, 51000), 3); ret != tcActRedirect {
		t.Fatalf("UDP from the port of an inbound TCP connection: verdict %#x, want redirect", ret)
	}
	if ret, _ := run(t, egress, packet(podIP, inboundRemote, unix.IPPROTO_TCP, 8081, 51000), 3); ret != tcActRedirect {
		t.Fatalf("a new connection to an inbound peer: verdict %#x, want redirect", ret)
	}
	// Excluded peers are never recorded.
	_, _ = run(t, ingress, packet(excludedTarget, podIP, unix.IPPROTO_TCP, 51000, 8080), 3)
	if c := count(t, coll.Maps["nj_inbound"]); c != 1 {
		t.Fatalf("%d inbound connections recorded, want 1", c)
	}

	// The maps follow what is wanted.
	want.Steers = nil
	must(t, syncSteered(coll.Maps["nj_steered"], want))
	if c := count(t, coll.Maps["nj_steered"]); c != 0 {
		t.Fatalf("%d steered addresses left, want 0", c)
	}
	must(t, syncExcluded(coll.Maps["nj_excluded"], agent.DefaultExcluded[:2]))
	if c := count(t, coll.Maps["nj_excluded"]); c != 2 {
		t.Fatalf("%d excluded prefixes, want 2", c)
	}
}

func count(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var n int
	it := m.Iterate()
	k := make([]byte, m.KeySize())
	v := make([]byte, m.ValueSize())
	for it.Next(&k, &v) {
		n++
	}
	must(t, it.Err())
	return n
}

// tcProgs names the tcx programs on a hook of eth0, first first.
func tcProgs(t *testing.T, typ ebpf.AttachType) []string {
	t.Helper()
	eth, err := netlink.LinkByName("eth0")
	must(t, err)
	res, err := link.QueryPrograms(link.QueryOptions{Target: eth.Attrs().Index, Attach: typ})
	must(t, err)
	var names []string
	for _, p := range res.Programs {
		prog, err := ebpf.NewProgramFromID(p.ID)
		must(t, err)
		info, err := prog.Info()
		must(t, err)
		names = append(names, info.Name)
		_ = prog.Close()
	}
	return names
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// fastPathDump shows where a diverted packet went.
func fastPathDump(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, c := range [][]string{
		{"ip", "-s", "link", "show", DivertLink},
		{"ip", "-s", "link", "show", "eth0"},
		{"ip", "rule"},
		{"cat", "/proc/net/snmp"},
		{"cat", "/proc/net/netstat"},
		{"sysctl", "-a", "--pattern", "njd0|conf.all"},
		{"nft", "list", "ruleset"},
	} {
		out, _ := exec.CommandContext(t.Context(), c[0], c[1:]...).CombinedOutput()
		b.WriteString("$ " + strings.Join(c, " ") + "\n" + string(out))
	}
	return b.String()
}

// TestEBPFFastPath emulates a CNI that moves pod traffic from the pod's
// device straight to the uplink, past netfilter, as Cilium's eBPF host
// routing and Calico's eBPF mode do, and checks that the fast path still
// steers it.
func TestEBPFFastPath(t *testing.T) {
	privileged(t)
	must(t, writeSysctl("net/ipv4/ip_forward", "1"))
	must(t, writeSysctl("net/ipv4/conf/all/rp_filter", "2"))
	seen, _ := world(t)
	p := pod(t)
	node := nodeAddr(t)
	want := desired(node)

	// The bypass: everything the pod sends is redirected to eth0 at once,
	// as the CNIs' programs on the pod's device do.
	eth, err := netlink.LinkByName("eth0")
	must(t, err)
	vpod, err := netlink.LinkByName("vpod")
	must(t, err)
	bypass, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "bypass", Type: ebpf.SchedCLS, License: "Apache-2.0",
		Instructions: asm.Instructions{
			// IPv4 only: the kernel still answers the pod's ARP, which
			// the CNIs' programs answer themselves.
			asm.LoadMem(asm.R2, asm.R1, 16, asm.Word), // skb->protocol
			asm.JNE.Imm(asm.R2, int32(htons(unix.ETH_P_IP)), "pass"),
			asm.Mov.Imm(asm.R1, int32(eth.Attrs().Index)),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnRedirect.Call(),
			asm.Return(),
			asm.Mov.Imm(asm.R0, -1).WithSymbol("pass"),
			asm.Return(),
		},
	})
	must(t, err)
	defer func() { _ = bypass.Close() }()
	bl, err := link.AttachTCX(link.TCXOptions{Interface: vpod.Attrs().Index, Program: bypass, Attach: ebpf.AttachTCXIngress})
	must(t, err)
	defer func() { _ = bl.Close() }()

	// With netfilter alone, the pod's traffic is not steered.
	cfg := DefaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.Mode = ModeNFTables
	nft, err := New(cfg, testr.New(t))
	must(t, err)
	st, err := nft.Apply(want)
	must(t, err)
	if !st.Serving || st.Mode != ModeNFTables {
		t.Fatalf("nftables mode: serving %v, mode %s: %s", st.Serving, st.Mode, st.Reason)
	}
	var fromPod string
	inNS(t, p, func() error { fromPod = echoWith(t, nil, "bypass"); return nil })
	if fromPod == slotIP {
		t.Fatal("the bypass emulation did not bypass netfilter: the pod was steered in nftables mode")
	}

	cfg.Mode = ModeEBPF
	dp, err := New(cfg, testr.New(t))
	must(t, err)
	t.Cleanup(func() { _ = dp.Teardown() })
	st, err = dp.Apply(want)
	must(t, err)
	if !st.Serving || st.Mode != ModeEBPF {
		t.Fatalf("eBPF mode: serving %v, mode %s: %s", st.Serving, st.Mode, st.Reason)
	}
	for _, typ := range []ebpf.AttachType{ebpf.AttachTCXEgress, ebpf.AttachTCXIngress} {
		if got := tcProgs(t, typ); len(got) != 1 || !strings.HasPrefix(got[0], "nj_") {
			t.Fatalf("%s programs on eth0: %v", typ, got)
		}
	}
	inNS(t, p, func() error { fromPod = echo(t, seen); return nil })
	if fromPod != slotIP {
		st, _ := dp.Apply(want)
		t.Fatalf("pod traffic reached the internet from %q, want %s; %d packets diverted\n%s", fromPod, slotIP, st.Diverted, fastPathDump(t))
	}
	if got := echo(t, seen); got != slotIP {
		t.Fatalf("node traffic reached the internet from %q, want %s", got, slotIP)
	}
	st, err = dp.Apply(want)
	must(t, err)
	if st.Diverted == 0 {
		t.Fatal("the diverted count did not move")
	}

	// Traffic to an excluded destination is not diverted.
	before := st.Diverted
	inNS(t, p, func() error {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "udp4", net.JoinHostPort(routerIP, "9"))
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		_, err = c.Write([]byte("excluded"))
		return err
	})
	st, err = dp.Apply(want)
	must(t, err)
	if st.Diverted != before {
		t.Fatalf("traffic to an excluded destination was diverted: %d -> %d", before, st.Diverted)
	}

	// A program attached ahead of the fast path, as a CNI starting after
	// the agent would, is moved behind it on the next Apply and kept.
	foreign, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "foreign", Type: ebpf.SchedCLS, License: "Apache-2.0",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()},
	})
	must(t, err)
	defer func() { _ = foreign.Close() }()
	fl, err := link.AttachTCX(link.TCXOptions{Interface: eth.Attrs().Index, Program: foreign, Attach: ebpf.AttachTCXEgress, Anchor: link.Head()})
	must(t, err)
	defer func() { _ = fl.Close() }()
	if got := tcProgs(t, ebpf.AttachTCXEgress); got[0] != "foreign" {
		t.Fatalf("egress programs %v, want foreign first", got)
	}
	_, err = dp.Apply(want)
	must(t, err)
	if got := tcProgs(t, ebpf.AttachTCXEgress); len(got) != 2 || got[0] != "nj_egress" || got[1] != "foreign" {
		t.Fatalf("egress programs after Apply %v, want [nj_egress foreign]", got)
	}

	// A restarted agent takes over the pinned links: no second copy.
	dp2, err := New(cfg, testr.New(t))
	must(t, err)
	st, err = dp2.Apply(want)
	must(t, err)
	if !st.Serving {
		t.Fatalf("restarted agent not serving: %s", st.Reason)
	}
	if got := tcProgs(t, ebpf.AttachTCXEgress); len(got) != 2 || got[0] != "nj_egress" {
		t.Fatalf("egress programs after a restart %v", got)
	}
	inNS(t, p, func() error { fromPod = echo(t, seen); return nil })
	if fromPod != slotIP {
		t.Fatalf("after restart pod traffic left from %q", fromPod)
	}

	// Back to nftables mode: the fast path is removed, other programs stay.
	cfg.Mode = ModeNFTables
	dp3, err := New(cfg, testr.New(t))
	must(t, err)
	_, err = dp3.Apply(want)
	must(t, err)
	if got := tcProgs(t, ebpf.AttachTCXEgress); len(got) != 1 || got[0] != "foreign" {
		t.Fatalf("egress programs in nftables mode %v, want [foreign]", got)
	}
	if got := tcProgs(t, ebpf.AttachTCXIngress); len(got) != 0 {
		t.Fatalf("ingress programs in nftables mode %v", got)
	}
	if _, err := netlink.LinkByName(DivertLink); err == nil {
		t.Fatalf("%s left in nftables mode", DivertLink)
	}
	if _, err := os.Stat(cfg.BPFDir); !os.IsNotExist(err) {
		t.Fatalf("%s left in nftables mode: %v", cfg.BPFDir, err)
	}

	// Teardown from eBPF mode removes everything too.
	cfg.Mode = ModeEBPF
	dp4, err := New(cfg, testr.New(t))
	must(t, err)
	_, err = dp4.Apply(want)
	must(t, err)
	inNS(t, dp4.gw.ns, func() error { // the cloud detaches the slot
		l, err := netlink.LinkByName(EgressLink)
		if err != nil {
			return err
		}
		return netlink.LinkDel(l)
	})
	must(t, dp4.Teardown())
	if got := tcProgs(t, ebpf.AttachTCXEgress); len(got) != 1 {
		t.Fatalf("egress programs after teardown %v, want [foreign]", got)
	}
	if _, err := netlink.LinkByName(DivertLink); err == nil {
		t.Fatalf("teardown left %s", DivertLink)
	}
	if _, err := os.Stat(cfg.BPFDir); !os.IsNotExist(err) {
		t.Fatalf("teardown left %s: %v", cfg.BPFDir, err)
	}
}

// TestRemoveEBPFReadOnly runs the nftables-mode clean-up where /sys/fs/bpf
// is a read-only directory with no pins, as on a node that never ran the
// fast path: there is nothing to remove, so it must not fail.
func TestRemoveEBPFReadOnly(t *testing.T) {
	privileged(t)
	ro := t.TempDir()
	must(t, unix.Mount("tmpfs", ro, "tmpfs", unix.MS_RDONLY, ""))
	t.Cleanup(func() { _ = unix.Unmount(ro, 0) })
	d := &Dataplane{cfg: Config{BPFDir: ro + "/natterjack"}, log: testr.New(t)}
	if err := d.removeEBPF(); err != nil {
		t.Fatalf("removeEBPF on a read-only file system with no pins: %v", err)
	}
}
