package dataplane

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// markScanEvery is how often the host's rules are read for uses of the
// agent's mark bits. A node with many services carries thousands of rules,
// and a component that claims the bits later is still found within it.
const markScanEvery = time.Minute

// checkMarks fails when another component's nftables rules or policy
// routing rules use the mark bits the agent owns. Such a component, for
// example Calico, which keeps its own marks in 0xffff0000, makes the agent's
// steering skip or misroute packets without any error, so the clash is
// reported instead, with the setting that ends it.
func (d *Dataplane) checkMarks(c *nftables.Conn) error {
	if time.Since(d.marksChecked) < markScanEvery {
		return d.marksErr
	}
	found, err := markConflicts(c, d.cfg.MarkMask, d.ownsTable)
	if err != nil {
		return err
	}
	d.marksChecked, d.marksErr = time.Now(), nil
	if len(found) > 0 {
		msgs := make([]string, 0, len(found))
		for _, f := range found {
			msgs = append(msgs, f.String())
		}
		d.marksErr = fmt.Errorf("other rules on the node use the agent's mark bits 0x%08x, so steering would fail: %s; set agent.markMask to bits none of them use",
			d.cfg.MarkMask, strings.Join(msgs, "; "))
	}
	return d.marksErr
}

// The agent marks packets at mangle priority on the prerouting and output
// hooks (its prerouting and output chains).
const ownMarkPriority = -150

// Where a chain runs relative to the agent's marking.
const (
	runsBefore = 1 << iota
	runsAfter
)

// markConflicts lists the nftables chains outside the agent's table, and
// the policy routing rules outside its tables, that use bits of mask. A
// chain that runs before the agent marks a packet, such as Calico's raw
// prerouting chain, may read the mark freely and conflicts only when it can
// turn on the agent's bits. Every other chain conflicts when it reads or
// changes them, and any use of the agent's bits of the connection mark,
// which outlives the packet, conflicts. A chain that no base chain jumps
// to, for example one reached through a verdict map, counts as running
// after. iptables-legacy rules are not visible here, nor IPv6 and bridge
// tables, which never see the packets the agent steers.
func markConflicts(c *nftables.Conn, mask uint32, ownsTable func(int) bool) ([]markConflict, error) {
	chains, err := c.ListChains()
	if err != nil {
		return nil, fmt.Errorf("list nftables chains: %w", err)
	}
	type key struct {
		family nftables.TableFamily
		table  string
		chain  string
	}
	type chainUse struct {
		chain *nftables.Chain
		used  markUsage
		jumps []string
		runs  int
	}
	byKey := map[key]*chainUse{}
	var order []key
	for _, ch := range chains {
		switch ch.Table.Family {
		case nftables.TableFamilyIPv4, nftables.TableFamilyINet, nftables.TableFamilyNetdev:
		default:
			continue
		}
		if ch.Table.Name == TableName && ch.Table.Family == nftables.TableFamilyIPv4 {
			continue
		}
		rules, err := c.GetRules(ch.Table, ch)
		if errors.Is(err, unix.ENOENT) {
			continue // removed since it was listed
		}
		if err != nil {
			return nil, fmt.Errorf("list rules of chain %s in table %s: %w", ch.Name, ch.Table.Name, err)
		}
		cu := &chainUse{chain: ch}
		for _, r := range rules {
			u, jumps := markUse(r.Exprs)
			cu.used.add(u)
			cu.jumps = append(cu.jumps, jumps...)
		}
		if ch.Hooknum != nil {
			cu.runs = whenRuns(ch)
		}
		k := key{ch.Table.Family, ch.Table.Name, ch.Name}
		byKey[k] = cu
		order = append(order, k)
	}
	// Carry each base chain's place down the chains it jumps to.
	for changed := true; changed; {
		changed = false
		for _, k := range order {
			cu := byKey[k]
			for _, j := range cu.jumps {
				if to, ok := byKey[key{k.family, k.table, j}]; ok && to.runs|cu.runs != to.runs {
					to.runs |= cu.runs
					changed = true
				}
			}
		}
	}
	var found []markConflict
	for _, k := range order {
		cu := byKey[k]
		runs := cu.runs
		if runs == 0 {
			runs = runsAfter
		}
		var bad markUsage
		if runs&runsBefore != 0 {
			bad.Meta |= cu.used.MetaSet & mask
		}
		if runs&runsAfter != 0 {
			bad.Meta |= cu.used.Meta & mask
		}
		bad.Ct = cu.used.Ct & mask
		if bad.Meta|bad.Ct != 0 {
			found = append(found, markConflict{Where: fmt.Sprintf("chain %s of table %s %s", k.chain, family(k.family), k.table), Bits: bad})
		}
	}
	rules, err := netlink.RuleList(unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("list policy routing rules: %w", err)
	}
	for _, r := range rules {
		if ownsTable(r.Table) || r.Mark == 0 && r.Mask == nil {
			continue
		}
		bits := ^uint32(0)
		if r.Mask != nil {
			bits = *r.Mask
		}
		if bits&mask != 0 {
			found = append(found, markConflict{Where: fmt.Sprintf("policy routing rule %d (fwmark %#x, table %d)", r.Priority, r.Mark, r.Table), Bits: markUsage{Meta: bits & mask}})
		}
	}
	return found, nil
}

// whenRuns places a base chain before or after the agent's marking: ingress
// hooks run before it, prerouting and output chains of a lower priority
// run before it, and the rest run after.
func whenRuns(ch *nftables.Chain) int {
	if ch.Table.Family == nftables.TableFamilyNetdev {
		return runsBefore
	}
	prio := 0
	if ch.Priority != nil {
		prio = int(*ch.Priority)
	}
	switch *ch.Hooknum {
	case *nftables.ChainHookIngress:
		return runsBefore
	case *nftables.ChainHookPrerouting, *nftables.ChainHookOutput:
		if prio < ownMarkPriority {
			return runsBefore
		}
	}
	return runsAfter
}

func family(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return fmt.Sprintf("family-%d", f)
}
