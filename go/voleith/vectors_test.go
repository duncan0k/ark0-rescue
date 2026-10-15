package voleith

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const vectorDir = "../../vectors"

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

type katVector struct {
	Description   string            `json:"description"`
	StatementID   int               `json:"statement_id"`
	KASCII        string            `json:"K_ascii"`
	Suffix        int               `json:"suffix"`
	Y             string            `json:"y"`
	PublicInputs  string            `json:"public_inputs"`
	WitnessX      string            `json:"witness_x"`
	Message       string            `json:"message"`
	Rho           string            `json:"rho"`
	ProofLen      int               `json:"proof_len"`
	ProofSHA256   string            `json:"proof_sha256"`
	Intermediates map[string]string `json:"intermediates"`
	Proof         string            `json:"proof"`
}

type proofEdit struct {
	Op     string `json:"op"`
	Offset int    `json:"offset"`
	Mask   string `json:"mask"`
	Data   string `json:"data"`
	Length int    `json:"length"`
}

type negVector struct {
	Description  string    `json:"description"`
	BaseVector   int       `json:"base_vector"`
	StatementID  int       `json:"statement_id"`
	PublicInputs string    `json:"public_inputs"`
	Message      string    `json:"message"`
	ProofEdit    proofEdit `json:"proof_edit"`
	Expected     bool      `json:"expected"`
}

type katFile struct {
	ProtocolVersionByte int `json:"protocol_version_byte"`
	Params              struct {
		Lambda, Tau, Tau0, K0, Tau1, K1 int
	} `json:"params"`
	StatementID int `json:"statement_id"`
	Circuit     struct {
		SHA256     string         `json:"sha256_of_serialization"`
		NPublic    int            `json:"n_public"`
		NSecret    int            `json:"n_secret_inputs"`
		NWitness   int            `json:"n_witness"`
		NConstr    int            `json:"n_constraints"`
		NMul       int            `json:"n_and_secret_secret"`
		NAssert    int            `json:"n_assert"`
		GateCounts map[string]int `json:"gate_counts"`
	} `json:"circuit"`
	ProofLen  int         `json:"proof_len"`
	Vectors   []katVector `json:"vectors"`
	Negatives []negVector `json:"negative_vectors"`
}

var (
	katOnce sync.Once
	katData katFile
	katErr  error
)

func loadKAT(t testing.TB) *katFile {
	katOnce.Do(func() {
		b, err := os.ReadFile(filepath.Join(vectorDir, "statement1-v0.2.json"))
		if err != nil {
			katErr = err
			return
		}
		katErr = json.Unmarshal(b, &katData)
	})
	if katErr != nil {
		t.Fatalf("load: %v", katErr)
	}
	return &katData
}

func applyEdit(t testing.TB, p []byte, e proofEdit) []byte {
	t.Helper()
	p = append([]byte(nil), p...)
	switch e.Op {
	case "none":
	case "xor":
		m := unhex(t, e.Mask)
		for i, b := range m {
			p[e.Offset+i] ^= b
		}
	case "set":
		copy(p[e.Offset:], unhex(t, e.Data))
	case "truncate":
		p = p[:e.Length]
	case "append":
		p = append(p, unhex(t, e.Data)...)
	case "prepend":
		p = append(unhex(t, e.Data), p...)
	default:
		t.Fatalf("unknown edit op %q", e.Op)
	}
	return p
}

func TestKATHeader(t *testing.T) {
	f := loadKAT(t)
	if f.ProtocolVersionByte != Version || f.StatementID != StatementHMAC {
		t.Errorf("header %d %d", f.ProtocolVersionByte, f.StatementID)
	}
	if f.Params.Lambda != lambda || f.Params.Tau != tau || f.Params.Tau0 != tau0 || f.Params.K0 != k0 || f.Params.K1 != k1 || f.Params.Tau1 != tau-tau0 {
		t.Errorf("params %+v", f.Params)
	}
	if f.ProofLen != ProofLen(StatementHMAC) || ProofLen(StatementHMAC) != 130218 {
		t.Errorf("proof_len %d vs %d", f.ProofLen, ProofLen(StatementHMAC))
	}
	c := statement1Circuit()
	d := c.digest()
	if hex.EncodeToString(d[:]) != f.Circuit.SHA256 {
		t.Errorf("circuit digest mismatch")
	}
	if c.P != f.Circuit.NPublic || c.S != f.Circuit.NSecret || c.ell() != f.Circuit.NWitness ||
		c.nConstraints() != f.Circuit.NConstr || c.nMul != f.Circuit.NMul || c.nAssert != f.Circuit.NAssert {
		t.Errorf("circuit sizes differ from JSON: %+v", f.Circuit)
	}
	m := countOps(c)
	for k, v := range f.Circuit.GateCounts {
		key := k
		if k == "AND_secret_secret" {
			key = "AND_ss"
		}
		if m[key] != v {
			t.Errorf("gate count %s = %d, JSON %d", k, m[key], v)
		}
	}
	if c.ell() != statement1Ell {
		t.Errorf("layout ell %d vs circuit %d", statement1Ell, c.ell())
	}
	// Offsets of §10.
	l := statement1Layout
	got := []int{l.offC, l.offU, l.offD, l.offA, l.offOpen, l.offH, l.proofLen}
	want := []int{18, 122079, 122111, 127370, 127386, 130202, 130218}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("offset %d: %d want %d", i, got[i], want[i])
		}
	}
}

func TestKATVectors(t *testing.T) {
	f := loadKAT(t)
	if len(f.Vectors) != 4 {
		t.Errorf("expected 4 KAT vectors, got %d", len(f.Vectors))
	}
	for vi, v := range f.Vectors {
		t.Run(fmt.Sprintf("kat%d", vi), func(t *testing.T) {
			proof := unhex(t, v.Proof)
			sum := sha256.Sum256(proof)
			if hex.EncodeToString(sum[:]) != v.ProofSHA256 || len(proof) != v.ProofLen {
				t.Fatalf("proof bytes do not match proof_sha256/proof_len")
			}
			pub := unhex(t, v.PublicInputs)
			msg := unhex(t, v.Message)
			y := unhex(t, v.Y)
			x := unhex(t, v.WitnessX)
			im := v.Intermediates

			// The public-input encoding of §7.5 from its parts.
			enc := append([]byte{byte(len(v.KASCII))}, v.KASCII...)
			enc = append(enc, byte(v.Suffix))
			enc = append(enc, y...)
			if !bytes.Equal(enc, pub) {
				t.Errorf("public_inputs is not u8(|K|) ‖ K ‖ u8(suffix) ‖ y")
			}
			// The relation itself, natively (RFC 2104).
			mac := hmac.New(sha256.New, []byte(v.KASCII))
			mac.Write(x)
			mac.Write([]byte{byte(v.Suffix)})
			if !bytes.Equal(mac.Sum(nil), y) {
				t.Errorf("HMAC(K, x ‖ suffix) != y")
			}

			var tr trace
			ok := verify(Statement{byte(v.StatementID), pub}, msg, proof, &tr)
			if !ok {
				t.Errorf("valid KAT rejected")
			}
			check := func(name string, got []byte) {
				t.Helper()
				if hex.EncodeToString(got) != im[name] {
					t.Errorf("%s = %x, want %s", name, got, im[name])
				}
			}
			check("mu", tr.mu)
			check("iv", tr.iv)
			var th []byte
			for _, h := range tr.treeHashes {
				th = append(th, h...)
			}
			check("tree_hashes", th)
			check("hcom", tr.hcom)
			check("chall1", tr.chall1)
			check("h_v", tr.hV)
			check("chall2", tr.chall2)
			check("b_tilde", tr.bTilde)
			check("chall3", tr.chall3Prime)

			// Values carried in the proof.
			l := statement1Layout
			check("iv_pre", proof[2:18])
			check("u_tilde", proof[l.offU:l.offD])
			check("a_tilde", proof[l.offA:l.offOpen])
			check("chall3", proof[l.offH:])

			// Prover-side values: recompute them from the JSON's secrets with
			// the tagged hash only (no prover is implemented), to pin rnd, root
			// and ggm, and to check the openings against the full trees.
			rho := unhex(t, v.Rho)
			rIv := shakeTagged("rnd", 32, u16le(len(x)), x, tr.mu, rho)
			check("r", rIv[:16])
			check("iv_pre", rIv[16:])
			roots := shakeTagged("root", 16*tau, tr.iv, unhex(t, im["r"]))
			check("roots", roots)
			checkOpenings(t, proof, tr.iv, roots)
		})
	}
}

// checkOpenings expands every tree from its root and checks that open_i holds
// the co-path seeds of j* = δ_i and com_{i,j*}, and that h_i matches.
func checkOpenings(t *testing.T, proof, iv, roots []byte) {
	l := statement1Layout
	chall3 := proof[l.offH:]
	p := l.offOpen
	for i := 0; i < tau; i++ {
		k := depth(i)
		N := 1 << uint(k)
		seeds := make([][]byte, 2*N)
		seeds[1] = roots[16*i : 16*i+16]
		for n := 1; n < N; n++ {
			out := shakeTagged("ggm", 32, iv, []byte{byte(i)}, u16le(n), seeds[n])
			seeds[2*n], seeds[2*n+1] = out[:16], out[16:]
		}
		var coms []byte
		for j := 0; j < N; j++ {
			out := shakeTagged("leaf", 48, iv, []byte{byte(i)}, u16le(N+j), seeds[N+j])
			coms = append(coms, out[16:]...)
		}
		jStar := 0
		for b := 0; b < k; b++ {
			o := offset(i) + b
			jStar |= int(chall3[o/8]>>uint(o%8)&1) << uint(b)
		}
		open := proof[p : p+16*k+32]
		p += 16*k + 32
		for d := 1; d <= k; d++ {
			s := ((N + jStar) >> uint(k-d)) ^ 1
			if !bytes.Equal(open[16*(d-1):16*d], seeds[s]) {
				t.Errorf("tree %d: co-path seed at depth %d differs", i, d)
			}
		}
		if !bytes.Equal(open[16*k:], coms[32*jStar:32*jStar+32]) {
			t.Errorf("tree %d: hidden commitment differs", i)
		}
	}
}

func TestKATNegatives(t *testing.T) {
	f := loadKAT(t)
	if len(f.Negatives) != 52 {
		t.Errorf("expected 52 negative vectors, got %d", len(f.Negatives))
	}
	base := make([][]byte, len(f.Vectors))
	for i, v := range f.Vectors {
		base[i] = unhex(t, v.Proof)
	}
	fails := 0
	steps := map[int]int{}
	for _, nv := range f.Negatives {
		proof := applyEdit(t, base[nv.BaseVector], nv.ProofEdit)
		st := Statement{byte(nv.StatementID), unhex(t, nv.PublicInputs)}
		got := Verify(st, unhex(t, nv.Message), proof)
		var tr trace
		if verify(st, unhex(t, nv.Message), proof, &tr) != got {
			t.Errorf("%q: Verify and verify disagree", nv.Description)
		}
		checkRejectStep(t, nv.Description, &tr, katExpectedSteps(nv))
		steps[tr.rejectStep]++
		if got != nv.Expected {
			t.Errorf("%q: got %v want %v", nv.Description, got, nv.Expected)
		} else {
			fails++
		}
	}
	t.Logf("%d/%d negative vectors rejected as expected; rejecting step histogram %v", fails, len(f.Negatives), steps)
}

// checkRejectStep checks that a rejection happened at one of the allowed
// steps of §11, and that steps 1–6 rejected before any hashing.
func checkRejectStep(t *testing.T, name string, tr *trace, allowed []int) {
	t.Helper()
	if tr.rejectStep >= 1 && tr.rejectStep <= 6 && tr.hashed {
		t.Errorf("%s: rejected at step %d after hashing", name, tr.rejectStep)
	}
	for _, a := range allowed {
		if tr.rejectStep == a {
			return
		}
	}
	t.Errorf("%s: rejected at step %d, expected one of %v", name, tr.rejectStep, allowed)
}

func katExpectedSteps(nv negVector) []int {
	d := nv.Description
	switch {
	case strings.HasPrefix(d, "version byte"), strings.HasPrefix(d, "statement id byte"):
		return []int{5}
	case strings.HasPrefix(d, "padding bit"):
		return []int{6}
	case strings.Contains(d, "truncated"), strings.Contains(d, "empty proof"), strings.Contains(d, "extra byte") && strings.HasPrefix(d, "proof"):
		return []int{4}
	case strings.Contains(d, "unregistered"):
		return []int{1}
	case strings.HasPrefix(d, "public inputs"), strings.HasPrefix(d, "K length"):
		return []int{2}
	}
	return []int{11}
}

func diffExpectedSteps(m diffMutated, msgLen int) []int {
	switch m.Kind {
	case "header":
		return []int{5}
	case "padding":
		return []int{6}
	case "truncate", "extend":
		return []int{4, 5}
	case "malformed":
		return []int{2}
	case "statement":
		if m.StatementID != 1 {
			return []int{1}
		}
	case "message":
		if msgLen > MaxMessage {
			return []int{3}
		}
	}
	// Bit and byte edits: header bytes fail step 5, padding bytes step 6.
	allowed := []int{11}
	l := statement1Layout
	pad := map[int]bool{l.offA - 1: true}
	for i := 1; i < tau; i++ {
		pad[l.offC+i*l.colBytes-1] = true
	}
	for _, e := range m.ProofEdits {
		n := len(e.Mask)/2 + len(e.Data)/2
		for o := e.Offset; o < e.Offset+n; o++ {
			if o <= 1 {
				allowed = append(allowed, 5)
			}
			if pad[o] {
				allowed = append(allowed, 6)
			}
		}
	}
	return allowed
}

// Differential set.

type diffValid struct {
	ID           string `json:"id"`
	StatementID  int    `json:"statement_id"`
	KASCII       string `json:"K_ascii"`
	Suffix       int    `json:"suffix"`
	Y            string `json:"y"`
	PublicInputs string `json:"public_inputs"`
	WitnessX     string `json:"witness_x"`
	Message      string `json:"message"`
	ProofSHA256  string `json:"proof_sha256"`
	ProofB64     string `json:"proof_b64"`
	Expected     bool   `json:"expected"`
}

type diffMutated struct {
	ID           string      `json:"id"`
	Kind         string      `json:"kind"`
	Description  string      `json:"description"`
	Base         int         `json:"base"`
	StatementID  int         `json:"statement_id"`
	PublicInputs string      `json:"public_inputs"`
	Message      *string     `json:"message"`
	MessageZeros int         `json:"message_zeros"`
	ProofEdits   []proofEdit `json:"proof_edits"`
	Expected     bool        `json:"expected"`
}

type diffFile struct {
	Format   string        `json:"format"`
	ProofLen int           `json:"proof_len"`
	Valid    []diffValid   `json:"valid"`
	Mutated  []diffMutated `json:"mutated"`
	Counts   struct {
		Valid   int `json:"valid"`
		Mutated int `json:"mutated"`
	} `json:"counts"`
}

var (
	diffOnce sync.Once
	diffData diffFile
	diffErr  error
)

func loadDiff(t testing.TB) *diffFile {
	diffOnce.Do(func() {
		b, err := os.ReadFile(filepath.Join(vectorDir, "statement1-v0.2-differential.json"))
		if err != nil {
			diffErr = err
			return
		}
		diffErr = json.Unmarshal(b, &diffData)
	})
	if diffErr != nil {
		t.Fatalf("load: %v", diffErr)
	}
	return &diffData
}

// longMessageCase returns the differential set's valid case with a
// 65,535-byte message.
func longMessageCase(t testing.TB) (Statement, []byte, []byte, bool) {
	for _, v := range loadDiff(t).Valid {
		m := unhex(t, v.Message)
		if len(m) == MaxMessage {
			p, err := base64.StdEncoding.DecodeString(v.ProofB64)
			if err != nil {
				t.Fatal(err)
			}
			return Statement{byte(v.StatementID), unhex(t, v.PublicInputs)}, m, p, true
		}
	}
	return Statement{}, nil, nil, false
}

func TestDifferential(t *testing.T) {
	if testing.Short() {
		t.Skip("differential set skipped in -short mode")
	}
	f := loadDiff(t)
	if f.Format != "voleith-differential-1" || len(f.Valid) != f.Counts.Valid || len(f.Mutated) != f.Counts.Mutated {
		t.Fatalf("unexpected file header: %s %d/%d %d/%d", f.Format, len(f.Valid), f.Counts.Valid, len(f.Mutated), f.Counts.Mutated)
	}
	proofs := make([][]byte, len(f.Valid))
	var nPass, nFail, nWrong int
	for i, v := range f.Valid {
		p, err := base64.StdEncoding.DecodeString(v.ProofB64)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(p)
		if hex.EncodeToString(sum[:]) != v.ProofSHA256 {
			t.Errorf("%s: proof_sha256 mismatch", v.ID)
		}
		proofs[i] = p
		got := Verify(Statement{byte(v.StatementID), unhex(t, v.PublicInputs)}, unhex(t, v.Message), p)
		if got != v.Expected {
			nWrong++
			t.Errorf("%s: got %v want %v", v.ID, got, v.Expected)
		} else if got {
			nPass++
		} else {
			nFail++
		}
	}
	byKind := map[string]int{}
	steps := map[int]int{}
	for _, m := range f.Mutated {
		p := proofs[m.Base]
		for _, e := range m.ProofEdits {
			p = applyEdit(t, p, e)
		}
		var msg []byte
		if m.Message == nil {
			msg = make([]byte, m.MessageZeros)
		} else {
			msg = unhex(t, *m.Message)
		}
		if m.StatementID < 0 || m.StatementID > 255 {
			t.Fatalf("%s: statement id %d out of byte range", m.ID, m.StatementID)
		}
		st := Statement{byte(m.StatementID), unhex(t, m.PublicInputs)}
		got := Verify(st, msg, p)
		if !got {
			var tr trace
			if verify(st, msg, p, &tr) {
				t.Errorf("%s: Verify and verify disagree", m.ID)
			}
			checkRejectStep(t, m.ID+" "+m.Description, &tr, diffExpectedSteps(m, len(msg)))
			steps[tr.rejectStep]++
		}
		if got != m.Expected {
			nWrong++
			t.Errorf("%s (%s, %s): got %v want %v", m.ID, m.Kind, m.Description, got, m.Expected)
		} else if got {
			nPass++
		} else {
			nFail++
			byKind[m.Kind]++
		}
	}
	t.Logf("differential: %d accepted, %d rejected, %d wrong verdicts; rejected by kind %v; rejecting step histogram %v", nPass, nFail, nWrong, byKind, steps)
}
