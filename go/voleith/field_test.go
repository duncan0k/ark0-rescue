package voleith

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func randGF(r *rand.Rand) gf { return gf{r.Uint64(), r.Uint64()} }

// mulNaive is shift-and-add multiplication, as a reference for mul.
func mulNaive(a, b gf) gf {
	var r gf
	for i := 0; i < 128; i++ {
		var bit uint64
		if i < 64 {
			bit = b.lo >> uint(i) & 1
		} else {
			bit = b.hi >> uint(i-64) & 1
		}
		if bit == 1 {
			r = r.add(a)
		}
		a = a.mulX()
	}
	return r
}

func TestFieldReduction(t *testing.T) {
	// X^127 · X = X^128 = X^7 + X^2 + X + 1 (§1.3).
	x127 := gf{0, 1 << 63}
	if got := x127.mulX(); got != (gf{0x87, 0}) {
		t.Errorf("X^128 = %x", got)
	}
	if got := x127.mul(gf{2, 0}); got != (gf{0x87, 0}) {
		t.Errorf("mul X^127·X = %x", got)
	}
	// Byte order: byte 0 holds X^0..X^7.
	b := make([]byte, 16)
	b[0] = 0x02
	if gfFromBytes(b) != (gf{2, 0}) {
		t.Errorf("encoding")
	}
}

func TestFieldMul(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 2000; i++ {
		a, b := randGF(r), randGF(r)
		want := mulNaive(a, b)
		if got := a.mul(b); got != want {
			t.Fatalf("mul(%x,%x) = %x want %x", a, b, got, want)
		}
		if got := newMulTable(a).mul(b); got != want {
			t.Fatalf("table mul(%x,%x) = %x want %x", a, b, got, want)
		}
	}
}

func TestTranspose(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	nRows := 200
	nWords := (nRows + 63) / 64
	Q := make([][]uint64, 128)
	for j := range Q {
		Q[j] = make([]uint64, nWords)
		for w := range Q[j] {
			Q[j][w] = r.Uint64()
		}
	}
	rows := transposeRows(Q, nRows)
	for row := 0; row < nRows; row++ {
		var want gf
		for j := 0; j < 128; j++ {
			bit := Q[j][row/64] >> uint(row%64) & 1
			if j < 64 {
				want.lo |= bit << uint(j)
			} else {
				want.hi |= bit << uint(j-64)
			}
		}
		if rows[row] != want {
			t.Fatalf("row %d", row)
		}
	}
}

func TestGetBits128(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	w := make([]uint64, 8)
	for i := range w {
		w[i] = r.Uint64()
	}
	bit := func(i int) uint64 {
		if i >= 64*len(w) {
			return 0
		}
		return w[i/64] >> uint(i%64) & 1
	}
	for off := 0; off+128 <= 64*len(w); off++ {
		g := getBits128(w, off)
		for i := 0; i < 128; i++ {
			var got uint64
			if i < 64 {
				got = g.lo >> uint(i) & 1
			} else {
				got = g.hi >> uint(i-64) & 1
			}
			if got != bit(off+i) {
				t.Fatalf("off %d bit %d", off, i)
			}
		}
	}
}

func TestPadOK(t *testing.T) {
	b := []byte{0xff, 0x7f}
	if !padOK(b, 15) || padOK([]byte{0xff, 0x80}, 15) || !padOK([]byte{0xff, 0xff}, 16) {
		t.Errorf("padOK")
	}
}

func TestTaggedHashLayout(t *testing.T) {
	// u8(|T|) ‖ T with T = "VOLEitH-rescue/v0.2/" ‖ name (§3.1).
	tg := newTagged("mu")
	want := append([]byte{22}, "VOLEitH-rescue/v0.2/mu"...)
	if !bytes.Equal(tg.head, want) {
		t.Errorf("tag head %q", tg.head)
	}
}

func TestDepthsAndOffsets(t *testing.T) {
	sum := 0
	leaves := 0
	for i := 0; i < tau; i++ {
		if offset(i) != sum {
			t.Errorf("o_%d = %d want %d", i, offset(i), sum)
		}
		sum += depth(i)
		leaves += 1<<uint(depth(i)) - 1
	}
	if sum != lambda || leaves != 1000 {
		t.Errorf("Σk = %d, Σ(N−1) = %d", sum, leaves)
	}
	if offset(8) != 48 || offset(23) != 48+5*15 {
		t.Errorf("offsets")
	}
}

func TestStatement1ClearEvaluation(t *testing.T) {
	// The circuit, evaluated in the clear on a KAT witness, satisfies every
	// ASSERT, and fails with a wrong y (§7.3, §7.7).
	f := loadKAT(t)
	v := f.Vectors[0]
	c := statement1Circuit()
	pub := unhex(t, v.PublicInputs)
	x := unhex(t, v.WitnessX)
	sec := make([]uint8, 256)
	for n := 0; n < 32; n++ {
		for b := 0; b < 8; b++ {
			sec[8*n+b] = x[n] >> uint(b) & 1
		}
	}
	w, ok := c.evalClear(statement1PublicBits(pub), sec)
	if !ok || len(w) != c.ell() {
		t.Fatalf("clear evaluation: ok=%v len=%d", ok, len(w))
	}
	bad := append([]byte(nil), pub...)
	bad[len(bad)-1] ^= 1
	if _, ok := c.evalClear(statement1PublicBits(bad), sec); ok {
		t.Errorf("wrong y satisfied the circuit")
	}
}

func TestEdgeInputs(t *testing.T) {
	f := loadKAT(t)
	v := f.Vectors[0]
	pub := unhex(t, v.PublicInputs)
	msg := unhex(t, v.Message)
	proof := unhex(t, v.Proof)
	st := Statement{StatementHMAC, pub}

	if Verify(Statement{StatementHMAC, nil}, msg, proof) || Verify(st, msg, nil) {
		t.Errorf("nil inputs accepted")
	}
	if Verify(st, make([]byte, MaxMessage+1), proof) {
		t.Errorf("oversized message accepted")
	}
	// K of 64 printable bytes is well-formed; 65 is not (§11 step 2).
	k64 := append([]byte{64}, bytes.Repeat([]byte{'a'}, 64)...)
	k64 = append(k64, make([]byte, 33)...)
	if !checkPublic(k64) {
		t.Errorf("64-byte K rejected by step 2")
	}
	k65 := append([]byte{65}, bytes.Repeat([]byte{'a'}, 65)...)
	k65 = append(k65, make([]byte, 33)...)
	if checkPublic(k65) {
		t.Errorf("65-byte K accepted by step 2")
	}
	for _, c := range []byte{0x20, 0x7e} {
		p := append([]byte(nil), pub...)
		p[1] = c
		if !checkPublic(p) {
			t.Errorf("K byte %#x rejected", c)
		}
	}
	// Δ = 2^128 − 1 and Δ = 0 run the full verification and reject (§11).
	for _, fill := range []byte{0xff, 0x00} {
		p := append([]byte(nil), proof...)
		for i := statement1Layout.offH; i < len(p); i++ {
			p[i] = fill
		}
		var tr trace
		if verify(st, msg, p, &tr) || tr.rejectStep != 11 {
			t.Errorf("chall3 filled with %#x: step %d", fill, tr.rejectStep)
		}
	}
}
