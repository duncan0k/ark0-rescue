// Package voleith is an independent verifier for the VOLEitH rescue proofs of
// SPEC.md v0.2, revision 1. It implements §11 only; there is no prover.
package voleith

import (
	"bytes"
	"encoding/binary"
	"sync"
)

// Parameters (SPEC §2).
const (
	Version    = 0x02
	lambda     = 128
	tau        = 24
	tau0       = 8
	k0         = 6
	k1         = 5
	MaxMessage = 65535

	// StatementHMAC is statement id 0x01 (§7.5).
	StatementHMAC = 0x01
)

// Statement is a statement id and its canonical public-input encoding
// (for 0x01: u8(|K|) ‖ K ‖ u8(suffix) ‖ y, §7.5).
type Statement struct {
	ID     byte
	Public []byte
}

// layout holds the fixed sizes of one statement id (§10). Steps 1–6 of §11
// need only this, not the circuit.
type layout struct {
	ell, ellHat         int // witness bits ℓ, VOLE rows ℓ̂ = ℓ + 3λ
	colBytes, dBytes    int // ⌈ℓ̂/8⌉, ⌈ℓ/8⌉
	offC, offU, offD    int
	offA, offOpen, offH int
	proofLen            int
}

func newLayout(ell int) layout {
	var l layout
	l.ell = ell
	l.ellHat = ell + 3*lambda
	l.colBytes = (l.ellHat + 7) / 8
	l.dBytes = (ell + 7) / 8
	l.offC = 2 + 16
	l.offU = l.offC + (tau-1)*l.colBytes
	l.offD = l.offU + 32
	l.offA = l.offD + l.dBytes
	l.offOpen = l.offA + 16
	open := 0
	for i := 0; i < tau; i++ {
		open += 16*depth(i) + 32
	}
	l.offH = l.offOpen + open
	l.proofLen = l.offH + 16
	return l
}

// statement1Ell is ℓ for statement 0x01 (§7.5); a test checks it against the
// circuit.
const statement1Ell = 42071

var statement1Layout = newLayout(statement1Ell)

// ProofLen returns the proof length for a registered statement id, or 0.
func ProofLen(id byte) int {
	if id == StatementHMAC {
		return statement1Layout.proofLen
	}
	return 0
}

// depth is k_i (§2).
func depth(i int) int {
	if i < tau0 {
		return k0
	}
	return k1
}

// offset is o_i (§5.3).
func offset(i int) int {
	if i < tau0 {
		return k0 * i
	}
	return k0*tau0 + k1*(i-tau0)
}

var (
	st1Once    sync.Once
	st1Circuit *circuit
)

func statement1Circuit() *circuit {
	st1Once.Do(func() { st1Circuit = buildStatement1() })
	return st1Circuit
}

// trace records intermediate values for tests.
type trace struct {
	mu, iv       []byte
	treeHashes   [tau][]byte
	hcom, chall1 []byte
	hV, chall2   []byte
	bTilde       []byte
	chall3Prime  []byte
	rejectStep   int  // §11 step at which verification failed (11: final comparison)
	hashed       bool // whether any hashing happened (step 7 reached)
}

// Verify implements verify(statement, m, π) of SPEC §11. Any internal error
// is a rejection.
func Verify(st Statement, m, proof []byte) bool {
	return verify(st, m, proof, nil)
}

// checkPublic is §11 step 2 for statement 0x01.
func checkPublic(pub []byte) bool {
	if len(pub) < 1 {
		return false
	}
	L := int(pub[0])
	if L < 1 || L > 64 || len(pub) != L+34 {
		return false
	}
	for _, c := range pub[1 : 1+L] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// padOK reports whether the padding bits of enc_n(b) are zero (§1.2).
func padOK(b []byte, n int) bool {
	if n%8 == 0 {
		return true
	}
	return b[len(b)-1]&(0xff<<uint(n%8)) == 0
}

func verify(st Statement, m, proof []byte, tr *trace) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
			if tr != nil {
				tr.rejectStep = -1
			}
		}
	}()
	fail := func(step int) bool {
		if tr != nil {
			tr.rejectStep = step
		}
		return false
	}

	// Steps 1–5: no hashing, no parsing of proof contents.
	if st.ID != StatementHMAC { // 1
		return fail(1)
	}
	if !checkPublic(st.Public) { // 2
		return fail(2)
	}
	if len(m) > MaxMessage { // 3
		return fail(3)
	}
	lay := &statement1Layout
	if len(proof) != lay.proofLen { // 4
		return fail(4)
	}
	if proof[0] != Version || proof[1] != st.ID { // 5
		return fail(5)
	}

	// Step 6: split at the fixed offsets and check the padding bits.
	ivPre := proof[2:18]
	var c [tau][]byte // c[0] unused
	for i := 1; i < tau; i++ {
		c[i] = proof[lay.offC+(i-1)*lay.colBytes : lay.offC+i*lay.colBytes]
		if !padOK(c[i], lay.ellHat) {
			return fail(6)
		}
	}
	uTilde := proof[lay.offU:lay.offD]
	dEnc := proof[lay.offD:lay.offA]
	if !padOK(dEnc, lay.ell) {
		return fail(6)
	}
	aTildeB := proof[lay.offA:lay.offOpen]
	var open [tau][]byte
	p := lay.offOpen
	for i := 0; i < tau; i++ {
		n := 16*depth(i) + 32
		open[i] = proof[p : p+n]
		p += n
	}
	chall3 := proof[lay.offH:lay.proofLen]

	// The circuit is built lazily, after step 6 (§11, properties).
	circ := statement1Circuit()
	if circ.ell() != lay.ell {
		return fail(-1)
	}

	// Step 7: μ, iv, Δ.
	if tr != nil {
		tr.hashed = true
	}
	mu := shakeTagged("mu", 32,
		[]byte{Version, st.ID}, u16le(len(st.Public)), st.Public, u64le(uint64(len(m))), m)
	iv := shakeTagged("iv", 16, ivPre, mu)
	delta := gfFromBytes(chall3)
	deltaBit := func(j int) bool { return chall3[j/8]>>(uint(j)%8)&1 == 1 }
	if tr != nil {
		tr.mu, tr.iv = mu, iv
	}

	// Step 8: reconstruct each tree, expand leaves, form Q.
	nWords := (lay.ellHat + 63) / 64
	Q := make([][]uint64, lambda)
	qBuf := make([]uint64, lambda*nWords)
	for j := range Q {
		Q[j] = qBuf[j*nWords : (j+1)*nWords]
	}
	rWords := make([]uint64, nWords)
	expBuf := make([]byte, nWords*8)
	cWords := make([]uint64, nWords)
	lastMask := ^uint64(0)
	if lay.ellHat%64 != 0 {
		lastMask = (uint64(1) << uint(lay.ellHat%64)) - 1
	}

	hGGM, hLeaf, hExp, hTree := newTagged("ggm"), newTagged("leaf"), newTagged("exp"), newTagged("tree")
	treeHashes := make([]byte, 0, 32*tau)
	var seeds [128][16]byte
	var known [128]bool
	var nodeBuf [2]byte
	var leafOut [48]byte
	var ggmOut [32]byte
	coms := make([]byte, 0, 32*64)
	for i := 0; i < tau; i++ {
		k := depth(i)
		N := 1 << uint(k)
		o := offset(i)
		jStar := 0
		for b := 0; b < k; b++ {
			if deltaBit(o + b) {
				jStar |= 1 << uint(b)
			}
		}
		for n := range known[:2*N] {
			known[n] = false
		}
		for d := 1; d <= k; d++ {
			s := ((N + jStar) >> uint(k-d)) ^ 1
			copy(seeds[s][:], open[i][16*(d-1):16*d])
			known[s] = true
		}
		ti := []byte{byte(i)}
		for n := 2; n < N; n++ {
			if !known[n] {
				continue
			}
			binary.LittleEndian.PutUint16(nodeBuf[:], uint16(n))
			hGGM.sum(ggmOut[:], iv, ti, nodeBuf[:], seeds[n][:])
			copy(seeds[2*n][:], ggmOut[:16])
			copy(seeds[2*n+1][:], ggmOut[16:])
			known[2*n], known[2*n+1] = true, true
		}
		coms = coms[:0]
		for j := 0; j < N; j++ {
			if j == jStar {
				coms = append(coms, open[i][16*k:16*k+32]...)
				continue
			}
			binary.LittleEndian.PutUint16(nodeBuf[:], uint16(N+j))
			hLeaf.sum(leafOut[:], iv, ti, nodeBuf[:], seeds[N+j][:])
			coms = append(coms, leafOut[16:48]...)
			// Leaf expansion r_{i,j} (§5.1): the first ℓ̂ bits.
			hExp.sum(expBuf[:lay.colBytes], iv, ti, nodeBuf[:], leafOut[:16])
			for w := 0; w < nWords; w++ {
				rWords[w] = binary.LittleEndian.Uint64(expBuf[8*w:])
			}
			rWords[nWords-1] &= lastMask
			// q_{i,b} = ⊕_{j≠j*, bit_b(j⊕j*)=1} r_{i,j} (§5.2).
			x := j ^ jStar
			for b := 0; b < k; b++ {
				if x>>uint(b)&1 == 1 {
					xorWords(Q[o+b], rWords)
				}
			}
		}
		var hi [32]byte
		hTree.sum(hi[:], iv, ti, coms)
		treeHashes = append(treeHashes, hi[:]...)
		if tr != nil {
			tr.treeHashes[i] = append([]byte(nil), hi[:]...)
		}
		// Corrections (§5.3): Q_{o_i+b} ⊕= Δ_{o_i+b}·c_i for i ≥ 1.
		if i >= 1 {
			bytesToWords(cWords, c[i], expBuf)
			for b := 0; b < k; b++ {
				if deltaBit(o + b) {
					xorWords(Q[o+b], cWords)
				}
			}
		}
	}
	hcom := shakeTagged("hcom", 32, treeHashes)
	ch1Parts := [][]byte{mu, hcom}
	for i := 1; i < tau; i++ {
		ch1Parts = append(ch1Parts, c[i])
	}
	ch1Parts = append(ch1Parts, ivPre)
	chall1 := shakeTagged("ch1", 32, ch1Parts...)
	if tr != nil {
		tr.hcom, tr.chall1 = hcom, chall1
	}

	// Step 9: h_V from VH(Q_j) ⊕ Δ_j·ũ (§5.4); chall2.
	s1 := newMulTable(gfFromBytes(chall1[0:16]))
	t1 := newMulTable(gfFromBytes(chall1[16:32]))
	vt := make([]byte, 32*lambda)
	for j := 0; j < lambda; j++ {
		out := vt[32*j : 32*j+32]
		volehash(out, Q[j], lay.ell, s1, t1)
		if deltaBit(j) {
			for x := 0; x < 32; x++ {
				out[x] ^= uTilde[x]
			}
		}
	}
	hV := shakeTagged("hv", 32, vt)
	chall2 := shakeTagged("ch2", 64, chall1, uTilde, hV, dEnc)
	if tr != nil {
		tr.hV, tr.chall2 = hV, chall2
	}

	// Step 10: witness correction (§6.1), rows, circuit keys, ZKHash.
	dWords := make([]uint64, nWords)
	bytesToWords(dWords, dEnc, expBuf)
	for j := 0; j < lambda; j++ {
		if deltaBit(j) {
			xorWords(Q[j], dWords) // d is zero on rows ≥ ℓ (padding checked)
		}
	}
	nRows := lay.ell + lambda
	rows := transposeRows(Q, nRows)

	r0 := gfFromBytes(chall2[0:16])
	r1 := gfFromBytes(chall2[16:32])
	s2 := newMulTable(gfFromBytes(chall2[32:48]))
	t2 := newMulTable(gfFromBytes(chall2[48:64]))
	dt := newMulTable(delta)

	pubBits := statement1PublicBits(st.Public)
	hs, ht, ok2 := evalKeys(circ, pubBits, rows, delta, dt, s2, t2)
	if !ok2 {
		return fail(-1)
	}
	// q* = Σ_{i<128} X^i·q[ℓ+i], by Horner in X.
	var qStar gf
	for i := lambda - 1; i >= 0; i-- {
		qStar = qStar.mulX().add(rows[lay.ell+i])
	}
	qTilde := r0.mul(hs).add(r1.mul(ht)).add(qStar)
	aTilde := gfFromBytes(aTildeB)
	bTilde := qTilde.add(dt.mul(aTilde))
	bEnc := bTilde.bytes()

	// Step 11.
	chall3p := shakeTagged("ch3", 16, chall2, aTildeB, bEnc[:])
	if tr != nil {
		tr.bTilde = append([]byte(nil), bEnc[:]...)
		tr.chall3Prime = chall3p
	}
	if !bytes.Equal(chall3p, chall3) {
		return fail(11)
	}
	return true
}

func xorWords(dst, src []uint64) {
	_ = dst[len(src)-1]
	for i, v := range src {
		dst[i] ^= v
	}
}

// bytesToWords decodes b (little-endian bit order, §1.2) into dst, zero-filling.
func bytesToWords(dst []uint64, b []byte, scratch []byte) {
	n := copy(scratch, b)
	clear(scratch[n:])
	for w := range dst {
		dst[w] = binary.LittleEndian.Uint64(scratch[8*w:])
	}
}

// getBits128 returns bits [off, off+128) of a word-packed bit string.
func getBits128(w []uint64, off int) gf {
	idx, sh := off/64, uint(off%64)
	if sh == 0 {
		return gf{w[idx], w[idx+1]}
	}
	lo := w[idx]>>sh | w[idx+1]<<(64-sh)
	var nx uint64
	if idx+2 < len(w) {
		nx = w[idx+2]
	}
	hi := w[idx+1]>>sh | nx<<(64-sh)
	return gf{lo, hi}
}

// volehash writes VH(x) (§5.4) for a column x of ℓ̂ = ℓ + 384 bits.
func volehash(out []byte, x []uint64, ell int, s, t *mulTable) {
	n0 := ell + lambda // |x0|
	nv := (n0 + 127) / 128
	var hs, ht gf
	for j := 0; j < nv; j++ {
		y := gf{x[2*j], x[2*j+1]}
		if j == nv-1 {
			rem := n0 - 128*(nv-1) // bits of x0 in the last block
			switch {
			case rem <= 64:
				y.hi = 0
				if rem < 64 {
					y.lo &= (uint64(1) << uint(rem)) - 1
				}
			case rem < 128:
				y.hi &= (uint64(1) << uint(rem-64)) - 1
			}
		}
		hs = s.mul(hs.add(y))
		ht = t.mul(ht.add(y))
	}
	hs = hs.add(getBits128(x, n0))
	ht = ht.add(getBits128(x, n0+128))
	hs.put(out[0:16])
	ht.put(out[16:32])
}

// transposeRows returns q[r] = Σ_j Q_j[r]·X^j for r < nRows (§5.3, row view).
func transposeRows(Q [][]uint64, nRows int) []gf {
	nBlocks := (nRows + 63) / 64
	rows := make([]gf, nBlocks*64)
	var a, b [64]uint64
	for w := 0; w < nBlocks; w++ {
		for j := 0; j < 64; j++ {
			a[j] = Q[j][w]
			b[j] = Q[64+j][w]
		}
		transpose64(&a)
		transpose64(&b)
		for r := 0; r < 64; r++ {
			rows[64*w+r] = gf{a[r], b[r]}
		}
	}
	return rows[:nRows]
}

// transpose64 transposes a 64×64 bit matrix: out[i] bit j = in[j] bit i.
func transpose64(a *[64]uint64) {
	m := uint64(0x00000000FFFFFFFF)
	for j := 32; j != 0; j >>= 1 {
		for k := 0; k < 64; k = (k + j + 1) &^ j {
			t := (a[k]>>uint(j) ^ a[k+j]) & m
			a[k] ^= t << uint(j)
			a[k+j] ^= t
		}
		m ^= m << uint(j>>1)
	}
}

// statement1PublicBits computes the P = 776 public bits of §7.5.
func statement1PublicBits(pub []byte) []uint8 {
	L := int(pub[0])
	K := pub[1 : 1+L]
	suffix := pub[1+L]
	y := pub[2+L : 34+L]
	var ipad, opad [64]byte
	for i := range ipad {
		var k byte
		if i < L {
			k = K[i]
		}
		ipad[i] = k ^ 0x36
		opad[i] = k ^ 0x5c
	}
	ivIn := sha256Compress(sha256IV, ipad[:])
	ivOut := sha256Compress(sha256IV, opad[:])
	out := make([]uint8, st1P)
	for w := 0; w < 8; w++ {
		T := binary.BigEndian.Uint32(y[4*w:]) - ivOut[w]
		for i := 0; i < 32; i++ {
			out[32*w+i] = uint8(ivIn[w] >> uint(i) & 1)
			out[256+32*w+i] = uint8(ivOut[w] >> uint(i) & 1)
			out[512+32*w+i] = uint8(T >> uint(i) & 1)
		}
	}
	for i := 0; i < 8; i++ {
		out[768+i] = suffix >> uint(i) & 1
	}
	return out
}

// evalKeys evaluates the verifier's keys over the circuit (§7.3) and returns
// the two ZKHash accumulators Σ s^(C−1−t)·B_t and Σ t^(C−1−t)·B_t (§6.3).
func evalKeys(c *circuit, pubBits []uint8, rows []gf, delta gf, dt, s, t *mulTable) (hs, ht gf, ok bool) {
	nw := len(c.kind)
	keys := make([]gf, nw)
	bitv := make([]uint8, nw)
	bitv[1] = 1
	copy(bitv[2:], pubBits)
	for i := 0; i < c.S; i++ {
		keys[2+c.P+i] = rows[i]
	}
	kind := c.kind
	mulIdx := c.S
	nConstr := 0
	n := 2 + c.P + c.S
	// q_w for any wire: the key of a SEC wire, β_w·Δ otherwise.
	qOf := func(w uint32) gf {
		if kind[w] == kindSec {
			return keys[w]
		}
		if bitv[w] == 1 {
			return delta
		}
		return gf{}
	}
	absorb := func(B gf) {
		hs = s.mul(hs).add(B)
		ht = t.mul(ht).add(B)
		nConstr++
	}
	for _, in := range c.ins {
		switch in.op {
		case opXOR:
			ka, kb := kind[in.a], kind[in.b]
			switch {
			case ka == kindSec && kb == kindSec:
				keys[n] = keys[in.a].add(keys[in.b])
			case ka == kindSec:
				keys[n] = keys[in.a]
				if bitv[in.b] == 1 {
					keys[n] = keys[n].add(delta)
				}
			case kb == kindSec:
				keys[n] = keys[in.b]
				if bitv[in.a] == 1 {
					keys[n] = keys[n].add(delta)
				}
			default:
				bitv[n] = bitv[in.a] ^ bitv[in.b]
			}
			n++
		case opNOT:
			if kind[in.a] == kindSec {
				keys[n] = keys[in.a].add(delta)
			} else {
				bitv[n] = bitv[in.a] ^ 1
			}
			n++
		case opAND:
			ka, kb := kind[in.a], kind[in.b]
			switch {
			case ka == kindSec && kb == kindSec:
				qc := rows[mulIdx]
				mulIdx++
				keys[n] = qc
				absorb(keys[in.a].mul(keys[in.b]).add(dt.mul(qc)))
			case ka == kindSec:
				if bitv[in.b] == 1 {
					keys[n] = keys[in.a]
				}
			case kb == kindSec:
				if bitv[in.a] == 1 {
					keys[n] = keys[in.b]
				}
			default:
				bitv[n] = bitv[in.a] & bitv[in.b]
			}
			n++
		case opASSERT:
			absorb(qOf(in.a).mul(qOf(in.b)).add(dt.mul(qOf(in.c))))
		default:
			return gf{}, gf{}, false
		}
	}
	if mulIdx != c.ell() || nConstr != c.nConstraints() {
		return gf{}, gf{}, false
	}
	return hs, ht, true
}
