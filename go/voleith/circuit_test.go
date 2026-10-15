package voleith

import (
	"encoding/hex"
	"testing"
)

func countOps(c *circuit) map[string]int {
	m := map[string]int{}
	for _, in := range c.ins {
		switch in.op {
		case opXOR:
			m["XOR"]++
		case opAND:
			m["AND"]++
			ka, kb := c.kind[in.a], c.kind[in.b]
			switch {
			case ka == kindSec && kb == kindSec:
				m["AND_ss"]++
			case ka == kindSec || kb == kindSec:
				m["AND_sp"]++
			default:
				m["AND_pp"]++
			}
		case opNOT:
			m["NOT"]++
		case opASSERT:
			m["ASSERT"]++
		}
	}
	return m
}

func TestStatement1CircuitDigest(t *testing.T) {
	c := buildStatement1()
	d := c.digest()
	m := countOps(c)
	t.Logf("counts %v ell=%d C=%d", m, c.ell(), c.nConstraints())
	if got := hex.EncodeToString(d[:]); got != "5aadd73b39947a32f0eb217cf750ee280c3dadcd60b9ccccb09509892cf1435d" {
		t.Errorf("digest %s", got)
	}
	want := map[string]int{"XOR": 211450, "AND": 42900, "AND_ss": 41815, "AND_sp": 255, "AND_pp": 830, "NOT": 3857, "ASSERT": 256}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %d, want %d", k, m[k], v)
		}
	}
	if c.ell() != 42071 || c.nConstraints() != 42071 {
		t.Errorf("ell %d C %d", c.ell(), c.nConstraints())
	}
}

func TestCompressionCircuitDigest(t *testing.T) {
	c := buildCompression()
	d := c.digest()
	m := countOps(c)
	t.Logf("counts %v", m)
	if got := hex.EncodeToString(d[:]); got != "c0a978cb3bf40e83098fbf7b74226c557842bc09892598b66bdf3c7225c29114" {
		t.Errorf("digest %s", got)
	}
	if m["AND"] != 22573 || m["XOR"] != 111607 || m["NOT"] != 1891 {
		t.Errorf("counts %v", m)
	}
}

// TestAddCosts checks the MUL counts claimed in §7.4: two SEC words cost 31
// MULs, a public addend 30, a constant addend κ saves 1 + tz(κ) carries.
func TestAddCosts(t *testing.T) {
	mk := func(P int) (*builder, word, word) {
		b := newBuilder(P, 32)
		var x, p word
		for i := 0; i < 32; i++ {
			x[i] = b.secWire(i)
			if P > 0 {
				p[i] = b.pubWire(i)
			}
		}
		return b, x, p
	}
	var x, y word
	b2 := newBuilder(0, 64)
	for i := 0; i < 32; i++ {
		x[i], y[i] = b2.secWire(i), b2.secWire(32+i)
	}
	b2.addMulti(x, y)
	if b2.c.nMul != 31 {
		t.Errorf("SEC+SEC: %d MULs", b2.c.nMul)
	}
	b, x, p := mk(32)
	b.addMulti(x, p)
	if b.c.nMul != 30 {
		t.Errorf("SEC+PUB: %d MULs", b.c.nMul)
	}
	for _, k := range []uint32{1, 2, 0x80, 0x428a2f98, 0x80000000, 0xffffffff} {
		b, x, _ := mk(0)
		b.addMulti(x, constWord(k))
		tz := 0
		for k>>uint(tz)&1 == 0 {
			tz++
		}
		want := 31 - (1 + tz)
		if want < 0 {
			want = 0
		}
		if b.c.nMul != want {
			t.Errorf("SEC+const %#x: %d MULs, want %d", k, b.c.nMul, want)
		}
	}
}
