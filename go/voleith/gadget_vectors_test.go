package voleith

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The per-gadget circuits of vectors/gadgets-v0.2.json (SPEC §7.6, revision
// 2), rebuilt with this package's builder, which was written from revision
// 1. Each entry's construction is transcribed from the file's
// "construction" text.

type gadgetVector struct {
	Name         string         `json:"name"`
	Construction string         `json:"construction"`
	NPublic      int            `json:"n_public"`
	NSecret      int            `json:"n_secret"`
	NInstr       int            `json:"n_instructions"`
	NOutputs     int            `json:"n_outputs"`
	GateCounts   map[string]int `json:"gate_counts"`
	SerLen       int            `json:"serialization_len"`
	SHA256       string         `json:"sha256_of_serialization"`
	SerHex       string         `json:"serialization_hex"`
}

// pw and sw are public word Pj and secret word Sj: input bits
// [32j, 32j+32), bit 0 first.
func (b *builder) pw(j int) word {
	var w word
	for i := 0; i < 32; i++ {
		w[i] = b.pubWire(32*j + i)
	}
	return w
}

func (b *builder) sw(j int) word {
	var w word
	for i := 0; i < 32; i++ {
		w[i] = b.secWire(32*j + i)
	}
	return w
}

func (b *builder) outputWords(ws ...word) {
	for _, w := range ws {
		for i := 0; i < 32; i++ {
			b.c.outputs = append(b.c.outputs, uint32(w[i]))
		}
	}
}

var gadgetBuilders = map[string]func(b *builder){
	"add_sec_sec":   func(b *builder) { b.outputWords(b.add(b.sw(0), b.sw(1))) },
	"add_sec_pub":   func(b *builder) { b.outputWords(b.add(b.sw(0), b.pw(0))) },
	"add_pub_sec":   func(b *builder) { b.outputWords(b.add(b.pw(0), b.sw(0))) },
	"add_sec_const": func(b *builder) { b.outputWords(b.add(b.sw(0), constWord(0x428a2f98))) },
	"add_multi_mixed": func(b *builder) {
		b.outputWords(b.addMulti(b.sw(0), b.pw(0), constWord(0), constWord(0x428a2f98), b.sw(1), b.pw(1)))
	},
	"xor_w_sec_const": func(b *builder) { b.outputWords(b.xorW(b.sw(0), constWord(0x0000ffff))) },
	"ch_sec":          func(b *builder) { b.outputWords(b.ch(b.sw(0), b.sw(1), b.sw(2))) },
	"ch_sec_pub_pub":  func(b *builder) { b.outputWords(b.ch(b.sw(0), b.pw(0), b.pw(1))) },
	"ch_pub_sec_sec":  func(b *builder) { b.outputWords(b.ch(b.pw(0), b.sw(0), b.sw(1))) },
	"maj_sec":         func(b *builder) { b.outputWords(b.maj(b.sw(0), b.sw(1), b.sw(2))) },
	"maj_sec_pub_pub": func(b *builder) { b.outputWords(b.maj(b.sw(0), b.pw(0), b.pw(1))) },
	"maj_mixed_bits": func(b *builder) {
		// x[i] = S0[i] for even i, P0[i] for odd i; z[i] = S1[i] for odd i,
		// P2[i] for even i.
		s0, s1, p0, p2 := b.sw(0), b.sw(1), b.pw(0), b.pw(2)
		var x, z word
		for i := 0; i < 32; i++ {
			if i%2 == 0 {
				x[i], z[i] = s0[i], p2[i]
			} else {
				x[i], z[i] = p0[i], s1[i]
			}
		}
		b.outputWords(b.maj(x, b.pw(1), z))
	},
	"big_sigma0_sec":   func(b *builder) { b.outputWords(b.bigSigma0(b.sw(0))) },
	"big_sigma1_sec":   func(b *builder) { b.outputWords(b.bigSigma1(b.sw(0))) },
	"small_sigma0_sec": func(b *builder) { b.outputWords(b.smallSigma0(b.sw(0))) },
	"small_sigma1_sec": func(b *builder) { b.outputWords(b.smallSigma1(b.sw(0))) },
	"big_sigma0_pub":   func(b *builder) { b.outputWords(b.bigSigma0(b.pw(0))) },
	"assert_add_sec_sec_pub": func(b *builder) {
		b.assertAdd(b.sw(0), b.sw(1), b.pw(0))
	},
	"assert_add_sec_pub_pub": func(b *builder) {
		b.assertAdd(b.sw(0), b.pw(0), b.pw(1))
	},
	"compress_pub_block": func(b *builder) {
		// H = [S0..S7], W = [P0..P15], no S; output 32w + i is bit i of
		// output word w.
		var H [8]word
		var W [16]word
		for j := 0; j < 8; j++ {
			H[j] = b.sw(j)
		}
		for j := 0; j < 16; j++ {
			W[j] = b.pw(j)
		}
		b.outputWords(b.compress(H, W, nil)...)
	},
}

func TestGadgetVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir, "gadgets-v0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Circuits []gadgetVector `json:"circuits"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Circuits) != len(gadgetBuilders) {
		t.Errorf("%d circuits in the file, %d builders", len(file.Circuits), len(gadgetBuilders))
	}
	for _, v := range file.Circuits {
		t.Run(v.Name, func(t *testing.T) {
			build, ok := gadgetBuilders[v.Name]
			if !ok {
				t.Fatalf("no builder for %q (%s)", v.Name, v.Construction)
			}
			b := newBuilder(v.NPublic, v.NSecret)
			build(b)
			c := b.c
			ser := c.serialize()
			d := sha256.Sum256(ser)
			if got := hex.EncodeToString(d[:]); got != v.SHA256 {
				t.Errorf("digest %s, want %s", got, v.SHA256)
			}
			if len(ser) != v.SerLen {
				t.Errorf("serialization length %d, want %d", len(ser), v.SerLen)
			}
			if v.SerHex != "" && hex.EncodeToString(ser) != v.SerHex {
				t.Errorf("serialization hex differs")
			}
			if len(c.ins) != v.NInstr {
				t.Errorf("instructions %d, want %d", len(c.ins), v.NInstr)
			}
			if len(c.outputs) != v.NOutputs {
				t.Errorf("outputs %d, want %d", len(c.outputs), v.NOutputs)
			}
			m := countOps(c)
			got := map[string]int{
				"XOR": m["XOR"], "AND": m["AND"], "NOT": m["NOT"], "ASSERT": m["ASSERT"],
				"AND_secret_secret": m["AND_ss"],
			}
			if len(v.GateCounts) != len(got) {
				t.Errorf("gate count keys %v, want %v", v.GateCounts, got)
			}
			for k, want := range v.GateCounts {
				if got[k] != want {
					t.Errorf("%s = %d, want %d", k, got[k], want)
				}
			}
			if c.nMul != m["AND_ss"] {
				t.Errorf("nMul %d, AND_ss %d", c.nMul, m["AND_ss"])
			}
		})
	}
}
