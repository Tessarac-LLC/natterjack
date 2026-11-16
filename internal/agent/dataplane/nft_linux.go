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
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/Tessarac-LLC/natterjack/internal/agent"
)

// Registers as the kernel numbers them: 0 is the verdict, 1-4 are 16-byte
// registers, 8-23 their 4-byte views. Register 2 starts at view 12.
const (
	regVerdict = 0
	reg1       = 1
	reg2       = 2
)

// Conntrack directions, as the ct direction key returns them.
const (
	ctDirOriginal = 0
	ctDirReply    = 1
)

// ruleset collects one table's objects for one atomic transaction.
type ruleset struct {
	c     *nftables.Conn
	t     *nftables.Table
	mask  uint32
	chain map[string]*nftables.Chain
}

// replaceTable starts a transaction that swaps the whole table: adding it
// first makes the delete valid when it does not exist yet.
func replaceTable(c *nftables.Conn, mask uint32) *ruleset {
	t := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: TableName}
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)
	return &ruleset{c: c, t: t, mask: mask, chain: map[string]*nftables.Chain{}}
}

func (r *ruleset) base(name string, typ nftables.ChainType, hook *nftables.ChainHook, prio int32, policy *nftables.ChainPolicy) *nftables.Chain {
	ch := r.c.AddChain(&nftables.Chain{
		Name: name, Table: r.t, Type: typ, Hooknum: hook, Priority: nftables.ChainPriorityRef(nftables.ChainPriority(prio)), Policy: policy,
	})
	r.chain[name] = ch
	return ch
}

func (r *ruleset) regular(name string) *nftables.Chain {
	ch := r.c.AddChain(&nftables.Chain{Name: name, Table: r.t})
	r.chain[name] = ch
	return ch
}

func (r *ruleset) rule(ch *nftables.Chain, exprs ...[]expr.Any) {
	var all []expr.Any
	for _, e := range exprs {
		all = append(all, e...)
	}
	r.c.AddRule(&nftables.Rule{Table: r.t, Chain: ch, Exprs: all})
}

func (r *ruleset) addrSet(name string, addrs []netip.Addr) (*nftables.Set, error) {
	s := &nftables.Set{Table: r.t, Name: name, KeyType: nftables.TypeIPAddr}
	var el []nftables.SetElement
	for _, a := range addrs {
		b := a.As4()
		el = append(el, nftables.SetElement{Key: b[:]})
	}
	if err := r.c.AddSet(s, el); err != nil {
		return nil, fmt.Errorf("set %s: %w", name, err)
	}
	return s, nil
}

func (r *ruleset) prefixSet(name string, prefixes []netip.Prefix) (*nftables.Set, error) {
	s := &nftables.Set{Table: r.t, Name: name, KeyType: nftables.TypeIPAddr, Interval: true}
	if err := r.c.AddSet(s, intervals(prefixes)); err != nil {
		return nil, fmt.Errorf("set %s: %w", name, err)
	}
	return s, nil
}

func (r *ruleset) verdictMap(name string, elems map[uint32]string) (*nftables.Set, error) {
	s := &nftables.Set{Table: r.t, Name: name, IsMap: true, KeyType: nftables.TypeMark, DataType: nftables.TypeVerdict}
	keys := make([]uint32, 0, len(elems))
	for k := range elems {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var el []nftables.SetElement
	for _, k := range keys {
		el = append(el, nftables.SetElement{Key: binaryutil.NativeEndian.PutUint32(k), VerdictData: &expr.Verdict{Kind: expr.VerdictJump, Chain: elems[k]}})
	}
	if err := r.c.AddSet(s, el); err != nil {
		return nil, fmt.Errorf("map %s: %w", name, err)
	}
	return s, nil
}

// intervals turns prefixes into the disjoint, sorted ranges an interval set
// needs: overlapping or adjacent prefixes are merged.
func intervals(prefixes []netip.Prefix) []nftables.SetElement {
	type rng struct{ lo, hi uint32 }
	var rs []rng
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		lo := binary.BigEndian.Uint32(p.Addr().AsSlice())
		hi := lo | (uint32(1)<<(32-p.Bits()) - 1)
		if p.Bits() == 0 {
			hi = ^uint32(0)
		}
		rs = append(rs, rng{lo, hi})
	}
	slices.SortFunc(rs, func(a, b rng) int { return int(int64(a.lo) - int64(b.lo)) })
	var merged []rng
	for _, r := range rs {
		if n := len(merged); n > 0 && uint64(r.lo) <= uint64(merged[n-1].hi)+1 {
			merged[n-1].hi = max(merged[n-1].hi, r.hi)
			continue
		}
		merged = append(merged, r)
	}
	be := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
	var el []nftables.SetElement
	if len(merged) > 0 && merged[0].lo != 0 {
		el = append(el, nftables.SetElement{Key: be(0), IntervalEnd: true})
	}
	for _, r := range merged {
		el = append(el, nftables.SetElement{Key: be(r.lo)})
		if r.hi != ^uint32(0) {
			el = append(el, nftables.SetElement{Key: be(r.hi + 1), IntervalEnd: true})
		}
	}
	return el
}

// Expression builders, each mirroring what nft itself generates.

func native(v uint32) []byte { return binaryutil.NativeEndian.PutUint32(v) }

func ifname(name string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, name)
	return b
}

func verdict(kind expr.VerdictKind) []expr.Any { return []expr.Any{&expr.Verdict{Kind: kind}} }

func jump(chain string) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: expr.VerdictJump, Chain: chain}}
}

func ctReply() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: reg1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{ctDirReply}},
	}
}

func ctOriginal() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: reg1, Key: expr.CtKeyDIRECTION},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{ctDirOriginal}},
	}
}

func ctEstablished() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: reg1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 4, Mask: native(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: native(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: reg1, Data: native(0)},
	}
}

// markBits loads the masked meta mark (or ct mark) and compares it with 0.
func markBits(ct bool, mask uint32, op expr.CmpOp) []expr.Any {
	return append(loadMarkBits(ct, mask), &expr.Cmp{Op: op, Register: reg1, Data: native(0)})
}

func loadMarkBits(ct bool, mask uint32) []expr.Any {
	var load expr.Any = &expr.Meta{Key: expr.MetaKeyMARK, Register: reg1}
	if ct {
		load = &expr.Ct{Key: expr.CtKeyMARK, Register: reg1}
	}
	return []expr.Any{load, &expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 4, Mask: native(mask), Xor: native(0)}}
}

// setMarkBits writes v into the masked bits and keeps every other bit, which
// belong to kube-proxy and the CNI.
func setMarkBits(ct bool, mask, v uint32) []expr.Any {
	if ct {
		return []expr.Any{
			&expr.Ct{Key: expr.CtKeyMARK, Register: reg1},
			&expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 4, Mask: native(^mask), Xor: native(v)},
			&expr.Ct{Key: expr.CtKeyMARK, Register: reg1, SourceRegister: true},
		}
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: reg1},
		&expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 4, Mask: native(^mask), Xor: native(v)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: reg1, SourceRegister: true},
	}
}

func ifIs(in bool, name string, eq bool) []expr.Any {
	key := expr.MetaKeyOIFNAME
	if in {
		key = expr.MetaKeyIIFNAME
	}
	op := expr.CmpOpEq
	if !eq {
		op = expr.CmpOpNeq
	}
	return []expr.Any{&expr.Meta{Key: key, Register: reg1}, &expr.Cmp{Op: op, Register: reg1, Data: ifname(name)}}
}

// ifWireGuard matches a source node's WireGuard devices: every interface
// whose name starts with WireGuardPrefix.
func ifWireGuard(in bool) []expr.Any {
	key := expr.MetaKeyOIFNAME
	if in {
		key = expr.MetaKeyIIFNAME
	}
	return []expr.Any{&expr.Meta{Key: key, Register: reg1}, &expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte(WireGuardPrefix)}}
}

func addr(src bool) expr.Any {
	off := uint32(16)
	if src {
		off = 12
	}
	return &expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: 4}
}

func addrIn(src bool, s *nftables.Set, in bool) []expr.Any {
	return []expr.Any{addr(src), &expr.Lookup{SourceRegister: reg1, SetName: s.Name, SetID: s.ID, Invert: !in}}
}

func addrIs(src bool, a netip.Addr, eq bool) []expr.Any {
	b := a.As4()
	op := expr.CmpOpEq
	if !eq {
		op = expr.CmpOpNeq
	}
	return []expr.Any{addr(src), &expr.Cmp{Op: op, Register: reg1, Data: b[:]}}
}

func l4(proto byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg1}, &expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{proto}}}
}

func dport(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

func tcpSyn() []expr.Any {
	return append(l4(unix.IPPROTO_TCP),
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 13, Len: 1},
		&expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 1, Mask: []byte{0x02}, Xor: []byte{0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: reg1, Data: []byte{0}},
	)
}

const tcpOptMaxseg = 2

// clampToRoute sets the MSS to the route MTU's, like iptables TCPMSS
// --clamp-mss-to-pmtu.
func clampToRoute() []expr.Any {
	return []expr.Any{
		&expr.Rt{Register: reg1, Key: expr.RtTCPMSS},
		&expr.Byteorder{SourceRegister: reg1, DestRegister: reg1, Op: expr.ByteorderHton, Len: 2, Size: 2},
		&expr.Exthdr{SourceRegister: reg1, Type: tcpOptMaxseg, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	}
}

// clampTo lowers an MSS above limit to limit.
func clampTo(limit uint16) []expr.Any {
	return []expr.Any{
		&expr.Exthdr{DestRegister: reg1, Type: tcpOptMaxseg, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
		&expr.Cmp{Op: expr.CmpOpGt, Register: reg1, Data: binaryutil.BigEndian.PutUint16(limit)},
		&expr.Immediate{Register: reg1, Data: binaryutil.BigEndian.PutUint16(limit)},
		&expr.Exthdr{SourceRegister: reg1, Type: tcpOptMaxseg, Offset: 2, Len: 2, Op: expr.ExthdrOpTcpopt},
	}
}

func snat(to netip.Addr) []expr.Any {
	b := to.As4()
	return []expr.Any{
		&expr.Immediate{Register: reg1, Data: b[:]},
		&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: reg1, Random: true},
	}
}

// keepSource translates a flow's source address to itself. It changes
// nothing but claims the flow's translation, so later source NAT chains,
// such as a CNI's masquerade, pass it by.
func keepSource() []expr.Any {
	return []expr.Any{
		addr(true),
		&expr.NAT{Type: expr.NATTypeSourceNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: reg1},
	}
}

// flowHash picks a bucket from the flow's addresses and ports and jumps to
// the bucket's gateway.
func flowHash(ring *nftables.Set) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 12, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Payload{DestRegister: 13, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Payload{DestRegister: 14, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Payload{DestRegister: 15, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Hash{SourceRegister: reg2, DestRegister: reg1, Length: 16, Modulus: agent.Buckets, Type: expr.HashTypeJenkins},
		&expr.Lookup{SourceRegister: reg1, SetName: ring.Name, SetID: ring.ID, IsDestRegSet: true, DestRegister: regVerdict},
	}
}

func markLookup(m *nftables.Set, mask uint32) []expr.Any {
	return append(loadMarkBits(true, mask), &expr.Lookup{SourceRegister: reg1, SetName: m.Name, SetID: m.ID, IsDestRegSet: true, DestRegister: regVerdict})
}

// Chain priorities, as nft names them.
const (
	prioMangle = -150
	prioFilter = 0
	prioSrcNAT = 100

	// routedMark marks, in the gateway namespace only, flows a VPC route
	// table sent to the slot.
	routedMark = 0x1
)

// hostRuleset is the host namespace table: steering, the tunnel's source
// translation and MSS clamp, and the tunnel's sender check. gatewayTunnel is
// the device a serving gateway takes traffic from, nj0 or njwg, or empty.
func hostRuleset(c *nftables.Conn, d *agent.Desired, mask uint32, cfg Config, gatewayTunnel string) error {
	r := replaceTable(c, mask)
	nodes, err := r.addrSet("nodes", d.Nodes)
	if err != nil {
		return err
	}
	excluded, err := r.prefixSet("excluded", d.Excluded)
	if err != nil {
		return err
	}

	// One pick chain (sets the flow's gateway) and one set chain (marks the
	// packet from it) per gateway.
	marks := map[uint32]string{}
	for m := range d.Gateways {
		pick, set := fmt.Sprintf("pick_%08x", m), fmt.Sprintf("set_%08x", m)
		r.rule(r.regular(pick), setMarkBits(true, mask, m))
		r.rule(r.regular(set), setMarkBits(false, mask, m))
		marks[m] = set
	}
	markMap, err := r.verdictMap("marks", marks)
	if err != nil {
		return err
	}

	pools := map[string]string{}
	for _, st := range d.Steers {
		pools[st.Pool] = ""
	}
	poolNames := make([]string, 0, len(pools))
	for p := range pools {
		poolNames = append(poolNames, p)
	}
	slices.Sort(poolNames)
	for i, p := range poolNames {
		name := fmt.Sprintf("pool_%d", i)
		pools[p] = name
		ch := r.regular(name)
		ring, ok := d.Rings[p]
		if !ok {
			continue
		}
		elems := map[uint32]string{}
		for b, m := range ring {
			elems[uint32(b)] = fmt.Sprintf("pick_%08x", m)
		}
		rm, err := r.verdictMap(fmt.Sprintf("ring_%d", i), elems)
		if err != nil {
			return err
		}
		r.rule(ch, markBits(true, mask, expr.CmpOpEq), flowHash(rm))
		r.rule(ch, markLookup(markMap, mask))
	}

	// Steering of pod traffic happens before routing, of node traffic in the
	// output hook, where a changed mark re-routes the packet.
	steer := r.regular("steer")
	output := r.base("output", nftables.ChainTypeRoute, nftables.ChainHookOutput, prioMangle, nil)
	for _, ch := range []*nftables.Chain{steer, output} {
		r.rule(ch, ctReply(), verdict(expr.VerdictReturn))
		r.rule(ch, markBits(false, mask, expr.CmpOpNeq), verdict(expr.VerdictReturn))
		r.rule(ch, addrIn(false, excluded, true), verdict(expr.VerdictReturn))
	}
	for i, st := range d.Steers {
		var notExcluded []expr.Any
		if len(st.Excluded) > 0 {
			ex, err := r.prefixSet(fmt.Sprintf("excl_%d", i), st.Excluded)
			if err != nil {
				return err
			}
			notExcluded = addrIn(false, ex, false)
		}
		if len(st.Sources) > 0 {
			src, err := r.addrSet(fmt.Sprintf("src_%d", i), st.Sources)
			if err != nil {
				return err
			}
			r.rule(steer, addrIn(true, src, true), notExcluded, jump(pools[st.Pool]))
		}
		if st.Node {
			r.rule(output, notExcluded, jump(pools[st.Pool]))
		}
	}

	pre := r.base("prerouting", nftables.ChainTypeFilter, nftables.ChainHookPrerouting, prioMangle, nil)
	// New flows out of a tunnel come only from cluster nodes, and never out
	// of a device to a gateway: a gateway only answers.
	for _, link := range []string{TunnelLink, WireGuardLink} {
		r.rule(pre, ifIs(true, link, true), ctOriginal(), addrIn(true, nodes, false), verdict(expr.VerdictDrop))
	}
	r.rule(pre, ifWireGuard(true), ctOriginal(), verdict(expr.VerdictDrop))
	r.rule(pre, jump("steer"))

	// Tunnel packets are accepted only from cluster nodes.
	input := r.base("input", nftables.ChainTypeFilter, nftables.ChainHookInput, prioFilter-10, nil)
	for _, port := range []uint16{cfg.TunnelPort, cfg.WireGuardPort} {
		r.rule(input, l4(unix.IPPROTO_UDP), dport(port), addrIn(true, nodes, false), verdict(expr.VerdictDrop))
	}

	// A node only forwards new flows out of a tunnel into its gateway
	// namespace, and only out of the tunnel its pool uses: a gateway of an
	// encrypted pool takes nothing over GENEVE. Replies to its own steered
	// flows pass.
	fwd := r.base("forward", nftables.ChainTypeFilter, nftables.ChainHookForward, prioFilter-10, nil)
	for _, link := range []string{TunnelLink, WireGuardLink} {
		if link == gatewayTunnel {
			r.rule(fwd, ifIs(true, link, true), ctOriginal(), ifIs(false, VethHost, false), verdict(expr.VerdictDrop))
		} else {
			r.rule(fwd, ifIs(true, link, true), ctOriginal(), verdict(expr.VerdictDrop))
		}
	}
	r.rule(fwd, ifWireGuard(true), ctOriginal(), verdict(expr.VerdictDrop))

	// Steered flows leave with the node's address, so replies return here,
	// and an encrypted gateway accepts them from this node's key.
	post := r.base("postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, prioSrcNAT-10, nil)
	for _, link := range []string{TunnelLink, VethHost} {
		r.rule(post, markBits(false, mask, expr.CmpOpNeq), ifIs(false, link, true), snat(d.NodeIP))
	}
	r.rule(post, markBits(false, mask, expr.CmpOpNeq), ifWireGuard(false), snat(d.NodeIP))
	// A serving gateway hands tunneled flows to its namespace with their
	// node's address, which the namespace's firewall checks. Binding the
	// address to itself, before the CNI's own source translation, keeps a
	// masquerade of every destination off the pod network (kindnet's, the AWS
	// VPC CNI's of addresses outside the VPC) from rewriting it.
	if gatewayTunnel != "" {
		r.rule(post, ifIs(true, gatewayTunnel, true), ifIs(false, VethHost, true), keepSource())
	}
	mss := r.base("mss", nftables.ChainTypeFilter, nftables.ChainHookPostrouting, prioMangle, nil)
	r.rule(mss, ifIs(false, TunnelLink, true), tcpSyn(), clampToRoute())
	r.rule(mss, ifWireGuard(false), tcpSyn(), clampToRoute())
	return nil
}

// gatewayRuleset is the gateway namespace table: only flows started from the
// cluster or VPC leave, translated to the slot's address; nothing enters.
func gatewayRuleset(c *nftables.Conn, d *agent.Desired, cfg Config) error {
	r := replaceTable(c, 0)
	nodes, err := r.addrSet("nodes", d.Nodes)
	if err != nil {
		return err
	}
	private, err := r.prefixSet("private", d.Excluded)
	if err != nil {
		return err
	}
	drop := nftables.ChainPolicyDrop

	// Flows routed to the slot by a VPC route table come from addresses this
	// namespace routes to the host. Their connection carries routedMark, which
	// picks the slot's own table: the reverse-path check passes, and replies
	// go back out the slot, not through the host, whose interface would drop
	// a source that is not its own.
	pre := r.base("prerouting", nftables.ChainTypeFilter, nftables.ChainHookPrerouting, prioMangle, nil)
	r.rule(pre, ifIs(true, EgressLink, true), ctOriginal(), addrIn(true, private, true), setMarkBits(true, routedMark, routedMark))
	r.rule(pre, markBits(true, routedMark, expr.CmpOpNeq), setMarkBits(false, routedMark, routedMark))

	input := r.base("input", nftables.ChainTypeFilter, nftables.ChainHookInput, prioFilter, &drop)
	r.rule(input, ctEstablished(), verdict(expr.VerdictAccept))
	r.rule(input, ifIs(true, "lo", true), verdict(expr.VerdictAccept))
	r.rule(input, ifIs(true, VethGateway, true), addrIn(true, nodes, true), l4(unix.IPPROTO_UDP), dport(cfg.ProbePort), verdict(expr.VerdictAccept))

	fwd := r.base("forward", nftables.ChainTypeFilter, nftables.ChainHookForward, prioFilter, &drop)
	r.rule(fwd, ctEstablished(), verdict(expr.VerdictAccept))
	// Tunneled flows: their source is always a node, translated there.
	r.rule(fwd, ifIs(true, VethGateway, true), ifIs(false, EgressLink, true), addrIn(true, nodes, true), verdict(expr.VerdictAccept))
	// Flows routed to the slot by a VPC route table, before agents steer.
	r.rule(fwd, ifIs(true, EgressLink, true), ifIs(false, EgressLink, true), addrIn(true, private, true), addrIn(false, private, false), verdict(expr.VerdictAccept))

	mss := r.base("mss", nftables.ChainTypeFilter, nftables.ChainHookForward, prioMangle, nil)
	r.rule(mss, ifIs(false, EgressLink, true), tcpSyn(), clampTo(cfg.MSS))

	post := r.base("postrouting", nftables.ChainTypeNAT, nftables.ChainHookPostrouting, prioSrcNAT, nil)
	r.rule(post, ifIs(false, EgressLink, true), addrIs(true, d.Gateway.Address.Addr(), false), snat(d.Gateway.Address.Addr()))
	return nil
}
