package dataplane

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func loadMeta() expr.Any { return &expr.Meta{Key: expr.MetaKeyMARK, Register: reg1} }
func storeMeta() expr.Any {
	return &expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: reg1}
}
func loadCt() expr.Any  { return &expr.Ct{Key: expr.CtKeyMARK, Register: reg1} }
func storeCt() expr.Any { return &expr.Ct{Key: expr.CtKeyMARK, SourceRegister: true, Register: reg1} }

func and(mask, xor uint32) expr.Any {
	return &expr.Bitwise{SourceRegister: reg1, DestRegister: reg1, Len: 4, Mask: native(mask), Xor: native(xor)}
}
func eq(v uint32) expr.Any { return &expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: native(v)} }

func xtInfo(words ...uint32) *xt.Unknown {
	b := make([]byte, 0, 4*len(words)+1)
	for _, w := range words {
		b = binary.NativeEndian.AppendUint32(b, w)
	}
	u := xt.Unknown(b)
	return &u
}

func TestMarkUse(t *testing.T) {
	connmarkRestore := xtInfo(0, 0x80, 0x80)
	*connmarkRestore = append(*connmarkRestore, 2, 0, 0, 0) // mode restore
	for _, tc := range []struct {
		name  string
		exprs []expr.Any
		want  markUsage
	}{
		{"meta mark & 0x01f00000 == 0x01800000", []expr.Any{loadMeta(), and(0x01f00000, 0), eq(0x01800000)}, markUsage{Meta: 0x01f00000}},
		{"meta mark 0x4000 reads every bit", []expr.Any{loadMeta(), eq(0x4000)}, markUsage{Meta: ^uint32(0)}},
		{"meta mark set meta mark & 0xe00fffff", []expr.Any{loadMeta(), and(0xe00fffff, 0), storeMeta()}, markUsage{Meta: 0x1ff00000}},
		{"meta mark set meta mark | 0x08000000", []expr.Any{loadMeta(), and(^uint32(0x08000000), 0x08000000), storeMeta()}, markUsage{Meta: 0x08000000, MetaSet: 0x08000000}},
		{"meta mark set 0x10 replaces every bit", []expr.Any{&expr.Immediate{Register: reg1, Data: native(0x10)}, storeMeta()}, markUsage{Meta: ^uint32(0), MetaSet: 0x10}},
		{"meta mark set ct mark & 0x80", []expr.Any{loadCt(), and(0x80, 0), storeMeta()}, markUsage{Meta: ^uint32(0), Ct: 0x80, MetaSet: 0x80}},
		{"ct mark set ct mark & 0xff01ffff | 0x10000", []expr.Any{loadCt(), and(0xff01ffff, 0x10000), storeCt()}, markUsage{Ct: 0x00fe0000 | 0x10000}},
		{"meta mark & 0xff0000 vmap", []expr.Any{loadMeta(), and(0xff0000, 0), &expr.Lookup{SourceRegister: reg1, SetName: "marks", IsDestRegSet: true}}, markUsage{Meta: 0xff0000}},
		{"a register reused for an address forgets the mark", []expr.Any{loadMeta(), &expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, &expr.Immediate{Register: reg1, Data: []byte{10, 0, 0, 1}}, eq(0)}, markUsage{}},
		{"ip saddr 10.0.0.1 does not use the mark", []expr.Any{&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, &expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{10, 0, 0, 1}}}, markUsage{}},
		{"-m mark --mark 0x4000/0x4000", []expr.Any{&expr.Match{Name: "mark", Rev: 1, Info: xtInfo(0x4000, 0x4000)}}, markUsage{Meta: 0x4000}},
		{"-j MARK --set-xmark 0x200/0xf00", []expr.Any{&expr.Target{Name: "MARK", Rev: 2, Info: xtInfo(0x200, 0xf00)}}, markUsage{Meta: 0xf00, MetaSet: 0x200}},
		{"-m connmark --mark 0x80/0x80", []expr.Any{&expr.Match{Name: "connmark", Rev: 1, Info: xtInfo(0x80, 0x80)}}, markUsage{Ct: 0x80}},
		{"-j CONNMARK --restore-mark --nfmask 0x80 --ctmask 0x80", []expr.Any{&expr.Target{Name: "CONNMARK", Rev: 2, Info: connmarkRestore}}, markUsage{Meta: 0x80, Ct: 0x80, MetaSet: 0x80}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := markUse(tc.exprs); got != tc.want {
				t.Fatalf("markUse = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestMarkUseJumps(t *testing.T) {
	_, jumps := markUse([]expr.Any{loadMeta(), eq(0x03500000), &expr.Verdict{Kind: expr.VerdictGoto, Chain: "untracked"}})
	if !slices.Equal(jumps, []string{"untracked"}) {
		t.Fatalf("jumps = %v, want [untracked]", jumps)
	}
}

// The rules the agent writes itself read and change only its own bits.
func TestOwnRulesStayInTheMask(t *testing.T) {
	const mask = 0x00ff0000
	for _, exprs := range [][]expr.Any{
		{loadMeta(), and(mask, 0), &expr.Cmp{Op: expr.CmpOpNeq, Register: reg1, Data: native(0)}},
		{loadMeta(), and(^uint32(mask), 0x00010000), storeMeta()},
		{loadCt(), and(^uint32(mask), 0x00020000), storeCt()},
	} {
		if u, _ := markUse(exprs); (u.Meta|u.Ct|u.MetaSet)&^uint32(mask) != 0 {
			t.Fatalf("rule uses bits outside the mask: %+v", u)
		}
	}
}

// markConflicts finds a CNI's rules and policy routing rules that use the
// agent's bits, as Calico's do, and passes over ones that keep clear of them
// or, like Calico's raw chains, only read the mark before the agent sets it.
// It runs in the test container's own network namespace: the nftables and
// netlink libraries open their sockets on threads of their own.
func TestMarkConflicts(t *testing.T) {
	privileged(t)
	cmd := exec.CommandContext(t.Context(), "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table ip calico {
	chain nat-outgoing {
		type nat hook postrouting priority srcnat; policy accept;
		meta mark & 0x01f00000 == 0x01800000 masquerade fully-random
	}
	chain clear {
		meta mark set meta mark & 0xe00fffff
	}
	chain raw-prerouting {
		type filter hook prerouting priority raw; policy accept;
		meta mark 0x03500000 goto untracked
		fib daddr type local meta mark set meta mark | 0x01100000
	}
	chain raw-output {
		type filter hook output priority raw; policy accept;
		meta mark & 0x00010000 == 0x00010000 meta mark set meta mark & 0x03000000 | 0x03000000
		meta mark 0x03000000 accept
	}
	chain untracked {
		meta mark 0x03500000 accept
	}
}
table ip quiet {
	chain c {
		type filter hook prerouting priority 0; policy accept;
		meta mark & 0x4000 == 0x4000 accept
		ip saddr 10.0.0.1 accept
	}
}
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install rules: %v: %s", err, out)
	}
	t.Cleanup(func() {
		for _, table := range []string{"calico", "quiet"} {
			_ = exec.CommandContext(context.Background(), "nft", "delete", "table", "ip", table).Run()
		}
	})
	rule := netlink.NewRule()
	rule.Priority, rule.Table, rule.Mark, rule.Family = 100, 52, 0x80000, unix.AF_INET
	mask := uint32(0xff0000)
	rule.Mask = &mask
	must(t, netlink.RuleAdd(rule))
	t.Cleanup(func() { _ = netlink.RuleDel(rule) })

	c, err := nftables.New()
	must(t, err)
	owns := func(t int) bool { return t >= 7700 && t <= 7972 }
	found, err := markConflicts(c, 0x00ff0000, owns)
	must(t, err)
	var where []string
	for _, f := range found {
		where = append(where, f.String())
	}
	slices.Sort(where)
	want := []string{
		"chain clear of table ip calico uses packet mark bits 0x00f00000",
		"chain nat-outgoing of table ip calico uses packet mark bits 0x00f00000",
		"chain raw-prerouting of table ip calico uses packet mark bits 0x00100000",
		"policy routing rule 100 (fwmark 0x80000, table 52) uses packet mark bits 0x00ff0000",
	}
	if !slices.Equal(where, want) {
		t.Fatalf("conflicts:\n%s\nwant:\n%s", strings.Join(where, "\n"), strings.Join(want, "\n"))
	}

	found, err = markConflicts(c, 0x00003f00, owns)
	must(t, err)
	if len(found) != 0 {
		t.Fatalf("mask 0x3f00 conflicts with %v, want none", found)
	}
}

// rulesAhead finds the AWS VPC CNI's rules when the agent's sort after them,
// which sent every steered pod connection to the zone's bootstrap slot, and
// passes over the local table, destination-only rules, the agent's own and
// anything that sorts after it.
func TestRulesAhead(t *testing.T) {
	rule := func(prio, table int, set func(*netlink.Rule)) netlink.Rule {
		r := netlink.NewRule()
		r.Priority, r.Table = prio, table
		if set != nil {
			set(r)
		}
		return *r
	}
	cniMask := uint32(0x80)
	pod := netip.MustParseAddr("10.0.5.7")
	rules := []netlink.Rule{
		rule(0, unix.RT_TABLE_LOCAL, nil),
		rule(512, unix.RT_TABLE_MAIN, func(r *netlink.Rule) { r.Dst = hostPrefix(pod) }),
		rule(1024, unix.RT_TABLE_MAIN, func(r *netlink.Rule) { r.Mark, r.Mask = 0x80, &cniMask }),
		rule(1536, 2, func(r *netlink.Rule) { r.Src = hostPrefix(pod) }),
		rule(7702, 7717, func(r *netlink.Rule) { r.Mark = 0x10000 }),
		rule(32766, unix.RT_TABLE_MAIN, nil),
	}
	owns := func(t int) bool { return t >= 7700 && t <= 7972 }
	var got []string
	for _, r := range rulesAhead(rules, 7700, owns) {
		got = append(got, describeRule(&r))
	}
	want := []string{
		"rule 1024 (from all fwmark 0x80/0x80 lookup 254)",
		"rule 1536 (from 10.0.5.7/32 lookup 2)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("rules ahead of 7700:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if ahead := rulesAhead(rules, DefaultConfig().RulePriority, owns); len(ahead) != 0 {
		t.Fatalf("the default priority sorts after %s", describeRule(&ahead[0]))
	}
}
