package voleith

import (
	"crypto/sha256"
	"encoding/binary"
)

// Constraint layer and circuits (SPEC §7).

const (
	kindConst uint8 = 0
	kindPub   uint8 = 1
	kindSec   uint8 = 2
)

const (
	opXOR    uint8 = 0x01
	opAND    uint8 = 0x02
	opNOT    uint8 = 0x03
	opASSERT uint8 = 0x04
)

type instr struct {
	op      uint8
	a, b, c uint32 // b unused by NOT; c used by ASSERT only
}

type circuit struct {
	P, S    int
	kind    []uint8 // kind of every wire id
	ins     []instr
	outputs []uint32
	nMul    int // AND of two SEC wires
	nAssert int
}

// ell is the number of witness bits, S + #MUL (§7.2).
func (c *circuit) ell() int { return c.S + c.nMul }

// nConstraints is #MUL + #ASSERT (§7.2).
func (c *circuit) nConstraints() int { return c.nMul + c.nAssert }

type builder struct{ c *circuit }

func newBuilder(P, S int) *builder {
	c := &circuit{P: P, S: S}
	c.kind = make([]uint8, 2+P+S, 2+P+S+300000)
	for i := 0; i < P; i++ {
		c.kind[2+i] = kindPub
	}
	for i := 0; i < S; i++ {
		c.kind[2+P+i] = kindSec
	}
	return &builder{c}
}

func isConst(w int) bool { return w < 2 }

func (b *builder) pubWire(i int) int { return 2 + i }
func (b *builder) secWire(i int) int { return 2 + b.c.P + i }
func (b *builder) isSec(w int) bool  { return b.c.kind[w] == kindSec }

func (b *builder) emit(op uint8, x, y int) int {
	k := kindPub
	if b.c.kind[x] == kindSec || (op != opNOT && b.c.kind[y] == kindSec) {
		k = kindSec
	}
	if op == opAND && b.c.kind[x] == kindSec && b.c.kind[y] == kindSec {
		b.c.nMul++
	}
	b.c.ins = append(b.c.ins, instr{op: op, a: uint32(x), b: uint32(y)})
	b.c.kind = append(b.c.kind, k)
	return len(b.c.kind) - 1
}

func (b *builder) XOR(x, y int) int {
	switch {
	case isConst(x) && isConst(y):
		return x ^ y
	case isConst(x):
		if x == 0 {
			return y
		}
		return b.NOT(y)
	case isConst(y):
		if y == 0 {
			return x
		}
		return b.NOT(x)
	}
	return b.emit(opXOR, x, y)
}

func (b *builder) AND(x, y int) int {
	switch {
	case isConst(x) && isConst(y):
		return x & y
	case isConst(x):
		if x == 1 {
			return y
		}
		return 0
	case isConst(y):
		if y == 1 {
			return x
		}
		return 0
	}
	return b.emit(opAND, x, y)
}

func (b *builder) NOT(x int) int {
	if isConst(x) {
		return 1 - x
	}
	return b.emit(opNOT, x, 0)
}

func (b *builder) ASSERT(x, y, z int) {
	b.c.ins = append(b.c.ins, instr{op: opASSERT, a: uint32(x), b: uint32(y), c: uint32(z)})
	b.c.nAssert++
}

// SHA-256 gadgets (§7.4). A word is 32 wire ids, least significant bit first.

type word [32]int

func constWord(v uint32) word {
	var w word
	for i := 0; i < 32; i++ {
		w[i] = int(v>>uint(i)) & 1
	}
	return w
}

func rotrW(w word, n int) word {
	var r word
	for i := 0; i < 32; i++ {
		r[i] = w[(i+n)%32]
	}
	return r
}

func shrW(w word, n int) word {
	var r word
	for i := 0; i < 32; i++ {
		if i+n < 32 {
			r[i] = w[i+n]
		} else {
			r[i] = 0
		}
	}
	return r
}

func (b *builder) xorW(x, y word) word {
	var r word
	for i := 0; i < 32; i++ {
		r[i] = b.XOR(x[i], y[i])
	}
	return r
}

func (b *builder) bigSigma0(a word) word {
	return b.xorW(b.xorW(rotrW(a, 2), rotrW(a, 13)), rotrW(a, 22))
}
func (b *builder) bigSigma1(e word) word {
	return b.xorW(b.xorW(rotrW(e, 6), rotrW(e, 11)), rotrW(e, 25))
}
func (b *builder) smallSigma0(x word) word {
	return b.xorW(b.xorW(rotrW(x, 7), rotrW(x, 18)), shrW(x, 3))
}
func (b *builder) smallSigma1(x word) word {
	return b.xorW(b.xorW(rotrW(x, 17), rotrW(x, 19)), shrW(x, 10))
}

func (b *builder) ch(e, f, g word) word {
	var r word
	for i := 0; i < 32; i++ {
		t := b.XOR(f[i], g[i])
		t = b.AND(e[i], t)
		r[i] = b.XOR(g[i], t)
	}
	return r
}

func (b *builder) maj(x, y, z word) word {
	var r word
	for i := 0; i < 32; i++ {
		if b.isSec(x[i]) && !b.isSec(y[i]) && !b.isSec(z[i]) {
			t1 := b.AND(y[i], z[i])
			t2 := b.XOR(y[i], z[i])
			t2 = b.AND(x[i], t2)
			r[i] = b.XOR(t1, t2)
		} else {
			t1 := b.XOR(x[i], y[i])
			t2 := b.XOR(x[i], z[i])
			t := b.AND(t1, t2)
			r[i] = b.XOR(t, x[i])
		}
	}
	return r
}

func (b *builder) add(x, y word) word {
	var s word
	c := 0
	for i := 0; i < 32; i++ {
		s[i] = b.XOR(b.XOR(x[i], y[i]), c)
		if i < 31 {
			t1 := b.XOR(x[i], c)
			t2 := b.XOR(y[i], c)
			c = b.XOR(b.AND(t1, t2), c)
		}
	}
	return s
}

func (b *builder) wordHasSec(w word) bool {
	for _, x := range w {
		if b.isSec(x) {
			return true
		}
	}
	return false
}

func wordIsZero(w word) bool {
	for _, x := range w {
		if x != 0 {
			return false
		}
	}
	return true
}

func (b *builder) addMulti(words ...word) word {
	var ordered []word
	for pass := 0; pass < 2; pass++ {
		for _, w := range words {
			if b.wordHasSec(w) != (pass == 1) || wordIsZero(w) {
				continue
			}
			ordered = append(ordered, w)
		}
	}
	if len(ordered) == 0 {
		return constWord(0)
	}
	acc := ordered[0]
	for _, w := range ordered[1:] {
		acc = b.add(acc, w)
	}
	return acc
}

func (b *builder) assertAdd(x, y, z word) {
	var c [32]int
	for i := 0; i < 32; i++ {
		c[i] = b.XOR(b.XOR(x[i], y[i]), z[i])
	}
	b.ASSERT(c[0], 1, 0)
	for i := 0; i < 31; i++ {
		p := b.XOR(x[i], c[i])
		q := b.XOR(y[i], c[i])
		r := b.XOR(c[i+1], c[i])
		b.ASSERT(p, q, r)
	}
}

// compress is §7.4's compress(H, W, S). With S != nil it asserts the final
// state and returns nil.
func (b *builder) compress(H [8]word, block [16]word, S *[8]word) []word {
	var W [64]word
	copy(W[:16], block[:])
	for t := 16; t < 64; t++ {
		s1 := b.smallSigma1(W[t-2])
		s0 := b.smallSigma0(W[t-15])
		W[t] = b.addMulti(s1, W[t-7], s0, W[t-16])
	}
	a, bb, c, d, e, f, g, h := H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]
	for t := 0; t < 64; t++ {
		s1 := b.bigSigma1(e)
		chw := b.ch(e, f, g)
		T1 := b.addMulti(h, s1, chw, constWord(sha256K[t]), W[t])
		s0 := b.bigSigma0(a)
		mj := b.maj(a, bb, c)
		T2 := b.addMulti(s0, mj)
		var e2, a2 word
		if S != nil && t >= 60 {
			e2 = S[4+63-t]
			a2 = S[63-t]
			b.assertAdd(d, T1, e2)
			b.assertAdd(T1, T2, a2)
		} else {
			e2 = b.addMulti(d, T1)
			a2 = b.addMulti(T1, T2)
		}
		h, g, f, e, d, c, bb, a = g, f, e, e2, c, bb, a, a2
	}
	if S != nil {
		return nil
	}
	state := [8]word{a, bb, c, d, e, f, g, h}
	out := make([]word, 8)
	for w := 0; w < 8; w++ {
		out[w] = b.addMulti(H[w], state[w])
	}
	return out
}

// Statement 0x01 (§7.5).
const (
	st1P = 776
	st1S = 256
)

func buildStatement1() *circuit {
	b := newBuilder(st1P, st1S)
	var X [8]word
	for j := 0; j < 8; j++ {
		for i := 0; i < 32; i++ {
			X[j][i] = b.secWire(8*(4*j+3-i/8) + i%8)
		}
	}
	var W8 word
	for i := 0; i < 32; i++ {
		switch {
		case i < 23:
			W8[i] = 0
		case i == 23:
			W8[i] = 1
		default:
			W8[i] = b.pubWire(768 + i - 24)
		}
	}
	var ivIn, ivOut, T [8]word
	for w := 0; w < 8; w++ {
		for i := 0; i < 32; i++ {
			ivIn[w][i] = b.pubWire(32*w + i)
			ivOut[w][i] = b.pubWire(256 + 32*w + i)
			T[w][i] = b.pubWire(512 + 32*w + i)
		}
	}
	var inner [16]word
	copy(inner[:8], X[:])
	inner[8] = W8
	for k := 9; k < 15; k++ {
		inner[k] = constWord(0)
	}
	inner[15] = constWord(776)
	D := b.compress(ivIn, inner, nil)
	var outer [16]word
	copy(outer[:8], D)
	outer[8] = constWord(0x80000000)
	for k := 9; k < 15; k++ {
		outer[k] = constWord(0)
	}
	outer[15] = constWord(768)
	b.compress(ivOut, outer, &T)
	return b.c
}

// buildCompression is the standalone compression circuit of §7.4: 768 secret
// inputs (P = 0 assumed), 256 outputs.
func buildCompression() *circuit {
	b := newBuilder(0, 768)
	var H [8]word
	var W [16]word
	for j := 0; j < 24; j++ {
		for i := 0; i < 32; i++ {
			if j < 8 {
				H[j][i] = b.secWire(32*j + i)
			} else {
				W[j-8][i] = b.secWire(32*j + i)
			}
		}
	}
	out := b.compress(H, W, nil)
	for w := 0; w < 8; w++ {
		for i := 0; i < 32; i++ {
			b.c.outputs = append(b.c.outputs, uint32(out[w][i]))
		}
	}
	return b.c
}

// serialize is the canonical serialization of §7.6 (opcode as one byte).
func (c *circuit) serialize() []byte {
	out := []byte("VOLEitH-rescue circuit v0.1")
	out = append(out, 0x00)
	out = binary.LittleEndian.AppendUint32(out, uint32(c.P))
	out = binary.LittleEndian.AppendUint32(out, uint32(c.S))
	out = binary.LittleEndian.AppendUint32(out, uint32(len(c.ins)))
	for _, in := range c.ins {
		out = append(out, in.op)
		out = binary.LittleEndian.AppendUint32(out, in.a)
		if in.op != opNOT {
			out = binary.LittleEndian.AppendUint32(out, in.b)
		}
		if in.op == opASSERT {
			out = binary.LittleEndian.AppendUint32(out, in.c)
		}
	}
	out = binary.LittleEndian.AppendUint32(out, uint32(len(c.outputs)))
	for _, o := range c.outputs {
		out = binary.LittleEndian.AppendUint32(out, o)
	}
	return out
}

func (c *circuit) digest() [32]byte { return sha256.Sum256(c.serialize()) }

// evalClear evaluates the circuit on bits (§7.3, "Clear"). It returns the
// witness w (secret inputs then MUL outputs) and whether every ASSERT held.
func (c *circuit) evalClear(pub, sec []uint8) (w []uint8, ok bool) {
	v := make([]uint8, len(c.kind))
	v[1] = 1
	copy(v[2:], pub)
	copy(v[2+c.P:], sec)
	w = append(w, sec...)
	ok = true
	n := 2 + c.P + c.S
	for _, in := range c.ins {
		switch in.op {
		case opXOR:
			v[n] = v[in.a] ^ v[in.b]
			n++
		case opAND:
			v[n] = v[in.a] & v[in.b]
			if c.kind[in.a] == kindSec && c.kind[in.b] == kindSec {
				w = append(w, v[n])
			}
			n++
		case opNOT:
			v[n] = v[in.a] ^ 1
			n++
		case opASSERT:
			if v[in.a]&v[in.b] != v[in.c] {
				ok = false
			}
		}
	}
	return w, ok
}
