package voleith

import "encoding/binary"

// gf is an element of GF(2^128) = GF(2)[X]/(X^128 + X^7 + X^2 + X + 1)
// (SPEC §1.3). lo holds the coefficients of X^0..X^63 (bit i = X^i), hi those
// of X^64..X^127. The 16-byte encoding is little-endian: byte 0 holds X^0..X^7.
type gf struct{ lo, hi uint64 }

func gfFromBytes(b []byte) gf {
	return gf{binary.LittleEndian.Uint64(b[0:8]), binary.LittleEndian.Uint64(b[8:16])}
}

func (a gf) put(b []byte) {
	binary.LittleEndian.PutUint64(b[0:8], a.lo)
	binary.LittleEndian.PutUint64(b[8:16], a.hi)
}

func (a gf) bytes() [16]byte {
	var b [16]byte
	a.put(b[:])
	return b
}

func (a gf) add(b gf) gf { return gf{a.lo ^ b.lo, a.hi ^ b.hi} }

func (a gf) isZero() bool { return a.lo|a.hi == 0 }

// mulX returns a·X.
func (a gf) mulX() gf {
	carry := a.hi >> 63
	return gf{(a.lo << 1) ^ (carry * 0x87), (a.hi << 1) | (a.lo >> 63)}
}

// clmul64 returns the 128-bit carry-less product of x and y as (lo, hi).
// The verifier handles public data only, so table lookups are acceptable.
func clmul64(x, y uint64) (lo, hi uint64) {
	// tab[n] = x·n for n < 16, as a 67-bit value (tl, th).
	var tl, th [16]uint64
	tl[1] = x
	for n := 2; n < 16; n += 2 {
		tl[n] = tl[n/2] << 1
		th[n] = th[n/2]<<1 | tl[n/2]>>63
		tl[n+1] = tl[n] ^ x
		th[n+1] = th[n]
	}
	for i := 60; i >= 0; i -= 4 {
		hi = hi<<4 | lo>>60
		lo <<= 4
		n := (y >> uint(i)) & 15
		lo ^= tl[n]
		hi ^= th[n]
	}
	return lo, hi
}

// reduce256 reduces z3:z2:z1:z0 modulo X^128 + X^7 + X^2 + X + 1.
func reduce256(z0, z1, z2, z3 uint64) gf {
	t := z3
	z1 ^= t ^ t<<1 ^ t<<2 ^ t<<7
	z2 ^= t>>63 ^ t>>62 ^ t>>57
	t = z2
	z0 ^= t ^ t<<1 ^ t<<2 ^ t<<7
	z1 ^= t>>63 ^ t>>62 ^ t>>57
	return gf{z0, z1}
}

// mul returns a·b (generic, Karatsuba over clmul64).
func (a gf) mul(b gf) gf {
	l0, l1 := clmul64(a.lo, b.lo)
	h0, h1 := clmul64(a.hi, b.hi)
	m0, m1 := clmul64(a.lo^a.hi, b.lo^b.hi)
	m0 ^= l0 ^ h0
	m1 ^= l1 ^ h1
	return reduce256(l0, l1^m0, h0^m1, h1)
}

// mulTable multiplies by a fixed element: t[k][n] = e·(n·X^{4k}).
type mulTable [32][16]gf

func newMulTable(e gf) *mulTable {
	t := new(mulTable)
	p := e
	for k := 0; k < 32; k++ {
		// p = e·X^{4k}
		b0 := p
		b1 := b0.mulX()
		b2 := b1.mulX()
		b3 := b2.mulX()
		for n := 1; n < 16; n++ {
			var v gf
			if n&1 != 0 {
				v = v.add(b0)
			}
			if n&2 != 0 {
				v = v.add(b1)
			}
			if n&4 != 0 {
				v = v.add(b2)
			}
			if n&8 != 0 {
				v = v.add(b3)
			}
			t[k][n] = v
		}
		p = b3.mulX()
	}
	return t
}

// mul returns e·b for the table's element e.
func (t *mulTable) mul(b gf) gf {
	var r gf
	x := b.lo
	for k := 0; k < 16; k++ {
		r = r.add(t[k][x&15])
		x >>= 4
	}
	x = b.hi
	for k := 16; k < 32; k++ {
		r = r.add(t[k][x&15])
		x >>= 4
	}
	return r
}
