package dataplane

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// markUsage are the bits of the packet mark (Meta) and the connection mark
// (Ct) that rules read or change, and the bits of the packet mark a write
// may turn on (MetaSet).
type markUsage struct {
	Meta, Ct, MetaSet uint32
}

func (u *markUsage) add(o markUsage) {
	u.Meta |= o.Meta
	u.Ct |= o.Ct
	u.MetaSet |= o.MetaSet
}

// regMark is what a register holds when it holds a mark: which mark, the
// bits of it kept, and the bits flipped in after. A constant is a register
// that keeps nothing.
type regMark struct {
	ct, constant bool
	keep, xor    uint32
}

// markUse is the mark bits the rule made of exprs reads or changes, and the
// chains it jumps or goes to. A rule that reads every bit, such as
// "meta mark 0x4000", uses them all; one that reads "meta mark & 0x4000"
// uses only 0x4000. Writes are counted the same way: "meta mark set meta
// mark | 0x10" changes only 0x10, while "meta mark set ct mark" changes
// every bit of the packet mark. iptables rules made by iptables-nft carry
// their marks in xtables matches and targets, which are read too.
func markUse(exprs []expr.Any) (markUsage, []string) {
	var used markUsage
	var jumps []string
	use := func(ct bool, bits uint32) {
		if ct {
			used.Ct |= bits
		} else {
			used.Meta |= bits
		}
	}
	regs := map[uint32]regMark{}
	for _, e := range exprs {
		switch e := e.(type) {
		case *expr.Meta:
			if e.Key != expr.MetaKeyMARK {
				if !e.SourceRegister {
					delete(regs, e.Register)
				}
				continue
			}
			if !e.SourceRegister {
				regs[e.Register] = regMark{keep: ^uint32(0)}
				continue
			}
			changed, set := written(regs, e.Register, false, use)
			use(false, changed)
			used.MetaSet |= set
		case *expr.Ct:
			if e.Key != expr.CtKeyMARK {
				if !e.SourceRegister {
					delete(regs, e.Register)
				}
				continue
			}
			if !e.SourceRegister {
				regs[e.Register] = regMark{ct: true, keep: ^uint32(0)}
				continue
			}
			changed, _ := written(regs, e.Register, true, use)
			use(true, changed)
		case *expr.Bitwise:
			src, ok := regs[e.SourceRegister]
			if !ok || len(e.Mask) != 4 || len(e.Xor) != 4 {
				delete(regs, e.DestRegister)
				continue
			}
			mask, xor := binary.NativeEndian.Uint32(e.Mask), binary.NativeEndian.Uint32(e.Xor)
			regs[e.DestRegister] = regMark{ct: src.ct, constant: src.constant, keep: src.keep & mask, xor: src.xor&mask ^ xor}
		case *expr.Cmp:
			if r, ok := regs[e.Register]; ok && !r.constant {
				use(r.ct, r.keep)
			}
		case *expr.Range:
			if r, ok := regs[e.Register]; ok && !r.constant {
				use(r.ct, r.keep)
			}
		case *expr.Lookup:
			if r, ok := regs[e.SourceRegister]; ok && !r.constant {
				use(r.ct, r.keep)
			}
		case *expr.Payload:
			delete(regs, e.DestRegister)
		case *expr.Immediate:
			if len(e.Data) == 4 {
				regs[e.Register] = regMark{constant: true, xor: binary.NativeEndian.Uint32(e.Data)}
			} else {
				delete(regs, e.Register)
			}
		case *expr.Verdict:
			if e.Kind == expr.VerdictJump || e.Kind == expr.VerdictGoto {
				jumps = append(jumps, e.Chain)
			}
		case *expr.Match:
			xtMatch(e.Name, info(e.Info), use)
		case *expr.Target:
			xtTarget(e.Name, info(e.Info), use, &used.MetaSet)
		}
	}
	return used, jumps
}

// written is the bits a store from register r into a mark changes, and the
// bits it may turn on. A value made from the same mark changes the bits it
// dropped or flipped, and turns on the flipped ones. A constant replaces
// the whole mark and turns on its own bits. A value made from the other
// mark, as in "meta mark set ct mark & 0x80", replaces the whole mark, may
// turn on any bit it kept of the other, and reads those.
func written(regs map[uint32]regMark, r uint32, ct bool, use func(bool, uint32)) (changed, set uint32) {
	v, ok := regs[r]
	switch {
	case !ok:
		return ^uint32(0), ^uint32(0)
	case v.constant:
		return ^uint32(0), v.xor
	case v.ct != ct:
		use(v.ct, v.keep)
		return ^uint32(0), v.keep | v.xor
	}
	return ^v.keep | v.xor, v.xor
}

func info(i xt.InfoAny) []byte {
	if u, ok := i.(*xt.Unknown); ok {
		return *u
	}
	return nil
}

// xtMatch reads the mark and connmark matches (struct xt_mark_mtinfo1 and
// xt_connmark_mtinfo1: mark, mask).
func xtMatch(name string, b []byte, use func(bool, uint32)) {
	if len(b) < 8 {
		return
	}
	mask := binary.NativeEndian.Uint32(b[4:])
	switch name {
	case "mark":
		use(false, mask)
	case "connmark":
		use(true, mask)
	}
}

// xtTarget reads the MARK target (struct xt_mark_tginfo2: mark, mask; the
// new mark is (mark & ^mask) ^ value) and the CONNMARK target (struct
// xt_connmark_tginfo1/2: ctmark, ctmask, nfmask, mode).
func xtTarget(name string, b []byte, use func(bool, uint32), metaSet *uint32) {
	switch name {
	case "MARK":
		if len(b) < 8 {
			return
		}
		value, mask := binary.NativeEndian.Uint32(b), binary.NativeEndian.Uint32(b[4:])
		use(false, mask|value)
		*metaSet |= value
	case "CONNMARK":
		if len(b) < 13 {
			return
		}
		ctmark, ctmask, nfmask := binary.NativeEndian.Uint32(b), binary.NativeEndian.Uint32(b[4:]), binary.NativeEndian.Uint32(b[8:])
		switch b[12] {
		case 0: // --set-xmark
			use(true, ctmask|ctmark)
		case 1: // --save-mark
			use(true, ctmask)
			use(false, nfmask)
		case 2: // --restore-mark
			use(false, nfmask)
			use(true, ctmask)
			*metaSet |= nfmask & ctmask
		}
	}
}

// markConflict describes a rule of another component that uses mark bits the
// agent owns.
type markConflict struct {
	Where string
	Bits  markUsage
}

func (c markConflict) String() string {
	var uses []string
	if c.Bits.Meta != 0 {
		uses = append(uses, fmt.Sprintf("packet mark bits 0x%08x", c.Bits.Meta))
	}
	if c.Bits.Ct != 0 {
		uses = append(uses, fmt.Sprintf("connection mark bits 0x%08x", c.Bits.Ct))
	}
	return c.Where + " uses " + strings.Join(uses, " and ")
}
